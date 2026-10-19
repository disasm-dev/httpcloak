// Package altsvc remembers which origins have advertised HTTP/3 through an
// Alt-Svc header (RFC 7838), the part of Chromium's HttpServerProperties that
// decides whether a QUIC job exists at all.
//
// Chrome only ever tries QUIC against a server that has said it speaks HTTP/3:
// HttpStreamFactory::JobController::DoCreateJobs creates a QUIC job for an
// alternative service learned from Alt-Svc, or for a DNS HTTPS record offering
// h3, and in no other case.
package altsvc

import (
	"net"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"
)

// maxEntries bounds the cache, like the DNS caches.
const maxEntries = 4096

// Alternative is one parsed alt-value.
type Alternative struct {
	Protocol string
	Host     string
	Port     int
	MaxAge   time.Duration
}

// Parse parses an Alt-Svc field value. "clear" parses to no alternatives. ok
// is false when the value is malformed anywhere, and then the header is
// ignored as a whole, as quiche's SpdyAltSvcWireFormat does. An alternative
// with an unusable port is dropped on its own, as Chromium's
// ProcessAlternativeServices does. max-age defaults to a day.
func Parse(value string) (alts []Alternative, ok bool) {
	value = strings.TrimSpace(value)
	if value == "clear" {
		return nil, true
	}
	for _, element := range splitUnquoted(value, ',') {
		element = strings.TrimSpace(element)
		if element == "" {
			continue // empty list elements are allowed by the #rule
		}
		fields := splitUnquoted(element, ';')
		protocolID, authority, found := strings.Cut(strings.TrimSpace(fields[0]), "=")
		if !found || protocolID == "" {
			return nil, false
		}
		protocol, err := url.PathUnescape(protocolID)
		if err != nil {
			return nil, false
		}
		authority = strings.TrimSpace(authority)
		if len(authority) < 2 || authority[0] != '"' || authority[len(authority)-1] != '"' {
			return nil, false
		}
		host, portStr, err := net.SplitHostPort(authority[1 : len(authority)-1])
		if err != nil {
			return nil, false
		}
		port, err := strconv.Atoi(portStr)
		if err != nil {
			return nil, false
		}
		alt := Alternative{Protocol: protocol, Host: host, Port: port, MaxAge: 24 * time.Hour}
		for _, param := range fields[1:] {
			name, val, found := strings.Cut(strings.TrimSpace(param), "=")
			if !found {
				return nil, false
			}
			if strings.EqualFold(strings.TrimSpace(name), "ma") {
				n, err := strconv.ParseUint(strings.Trim(strings.TrimSpace(val), `"`), 10, 32)
				if err != nil {
					return nil, false
				}
				alt.MaxAge = time.Duration(n) * time.Second
			}
		}
		if port < 1 || port > 65535 {
			continue
		}
		alts = append(alts, alt)
	}
	return alts, true
}

// splitUnquoted splits s on sep wherever sep is outside a quoted-string.
func splitUnquoted(s string, sep byte) []string {
	var out []string
	inQuotes, escaped, start := false, false, 0
	for i := 0; i < len(s); i++ {
		switch c := s[i]; {
		case escaped:
			escaped = false
		case c == '\\' && inQuotes:
			escaped = true
		case c == '"':
			inQuotes = !inQuotes
		case c == sep && !inQuotes:
			out = append(out, s[start:i])
			start = i + 1
		}
	}
	return append(out, s[start:])
}

// Cache holds, per https origin, when its HTTP/3 alternative expires. The zero
// value is ready to use.
type Cache struct {
	mu      sync.Mutex
	entries map[string]time.Time // "host:port" -> expiry of the h3 alternative
}

// Learn records what the Alt-Svc header values of a response from host:port
// advertised. A parsed header replaces everything known about the origin, as
// SetAlternativeServices does, so "clear", or a header that no longer lists
// h3, withdraws the alternative. No values means no Alt-Svc header, which
// changes nothing.
//
// Only h3 on the origin's own host and port counts: that is where this
// library's QUIC dial goes. Chromium would follow an alternative to another
// port, which leaves such an origin on TCP here, a difference in the direction
// of never opening a connection Chrome would not.
func (c *Cache) Learn(host, port string, values []string, now time.Time) {
	if len(values) == 0 {
		return
	}
	// Several header lines read as one list, as GetNormalizedHeader joins them.
	alts, ok := Parse(strings.Join(values, ", "))
	if !ok {
		return
	}
	var expires time.Time
	for _, alt := range alts {
		if alt.Protocol != "h3" || strconv.Itoa(alt.Port) != port {
			continue
		}
		if alt.Host != "" && !strings.EqualFold(alt.Host, host) {
			continue
		}
		if e := now.Add(alt.MaxAge); e.After(expires) {
			expires = e
		}
	}

	origin := net.JoinHostPort(strings.ToLower(host), port)
	c.mu.Lock()
	defer c.mu.Unlock()
	if !expires.After(now) {
		delete(c.entries, origin)
		return
	}
	if c.entries == nil {
		c.entries = make(map[string]time.Time)
	}
	if len(c.entries) >= maxEntries {
		for o, e := range c.entries {
			if !e.After(now) {
				delete(c.entries, o)
			}
		}
	}
	c.entries[origin] = expires
}

// LearnFromURL is Learn for the response to a request for rawURL. Chromium
// reads Alt-Svc off every response to a secure request, whichever protocol
// carried it; anything but https is ignored.
func (c *Cache) LearnFromURL(rawURL string, values []string, now time.Time) {
	if len(values) == 0 {
		return
	}
	u, err := url.Parse(rawURL)
	if err != nil || u.Scheme != "https" {
		return
	}
	c.Learn(u.Hostname(), PortOrDefault(u.Port()), values, now)
}

// AdvertisesH3 reports whether host:port has an unexpired h3 alternative.
func (c *Cache) AdvertisesH3(host, port string, now time.Time) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	e, ok := c.entries[net.JoinHostPort(strings.ToLower(host), port)]
	return ok && e.After(now)
}

// HeaderValues returns the Alt-Svc values from a header map, whatever the
// case of its keys.
func HeaderValues(headers map[string][]string) []string {
	for name, values := range headers {
		if strings.EqualFold(name, "alt-svc") {
			return values
		}
	}
	return nil
}

// PortOrDefault is port, or 443 when it is empty.
func PortOrDefault(port string) string {
	if port == "" {
		return "443"
	}
	return port
}

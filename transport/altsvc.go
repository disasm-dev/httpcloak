package transport

import (
	"context"
	"errors"
	"net"
	"net/url"
	"sync"
	"time"

	"github.com/sardanioss/httpcloak/dns"
	"github.com/sardanioss/httpcloak/internal/altsvc"
)

// Chrome only ever tries QUIC against a server that has said it speaks HTTP/3.
// The job controller creates a QUIC job in two cases and no others: an
// alternative service learned from an earlier Alt-Svc header, or a DNS HTTPS
// record whose alpn offers h3 (HttpStreamFactory::JobController::DoCreateJobs).
// Auto mode used to race QUIC against TCP on the first request to every host,
// which is a connection Chrome would never open.

// errH3NotAdvertised stops an H3 probe for a host that has not offered HTTP/3.
var errH3NotAdvertised = errors.New("http3: not advertised by Alt-Svc or DNS")

// learnAltSvc feeds a response's Alt-Svc header into the cache.
func (t *Transport) learnAltSvc(rawURL string, headers map[string][]string) {
	t.altSvc.LearnFromURL(rawURL, altsvc.HeaderValues(headers), time.Now())
}

// h3Advertised reports whether host has offered HTTP/3: an unexpired Alt-Svc
// alternative, or, on a direct connection to the default port, an HTTPS record
// with h3 in its alpn. Chromium consults DNS only when it resolves the name
// itself, which a proxied connection does not, and the record covers the
// default port only; any other port has its own _port._https name.
func (t *Transport) h3Advertised(ctx context.Context, snap transportSnapshot, host, port string) bool {
	if t.altSvc.AdvertisesH3(host, port, time.Now()) {
		return true
	}
	if snap.hasProxy() || port != "443" || net.ParseIP(host) != nil {
		return false
	}
	return dns.AdvertisesH3(ctx, host)
}

func (s transportSnapshot) hasProxy() bool {
	return s.proxy != nil && (s.proxy.URL != "" || s.proxy.TCPProxy != "" || s.proxy.UDPProxy != "")
}

// h3Upgrader brings up HTTP/3 in the background for a host already served over
// TCP once that host advertises it. That is what Chrome does with a live
// HTTP/2 session: the job controller does not hold the request for QUIC
// (DelayMainJobWithAvailableSpdySession is off), so the request goes out on
// the existing session while the QUIC job carries on and leaves a session for
// the requests after it.
//
// A failed attempt marks the host broken for 5 minutes, doubling with each
// further failure up to two days, Chromium's schedule for a broken alternative
// service.
type h3Upgrader struct {
	mu       sync.Mutex
	inFlight map[string]bool
	broken   map[string]brokenAlt

	ctxOnce sync.Once
	ctx     context.Context
	cancel  context.CancelFunc
}

type brokenAlt struct {
	until    time.Time
	failures int
}

const (
	brokenAltInitialDelay = 5 * time.Minute
	brokenAltMaxDelay     = 48 * time.Hour
	h3UpgradeTimeout      = 10 * time.Second
)

func (u *h3Upgrader) context() context.Context {
	u.ctxOnce.Do(func() { u.ctx, u.cancel = context.WithCancel(context.Background()) })
	return u.ctx
}

// stop cancels any upgrade still connecting, so none outlives the transport.
func (u *h3Upgrader) stop() {
	u.context()
	u.cancel()
}

// begin claims host for one upgrade attempt.
func (u *h3Upgrader) begin(host string, now time.Time) bool {
	u.mu.Lock()
	defer u.mu.Unlock()
	if u.inFlight[host] || now.Before(u.broken[host].until) {
		return false
	}
	if u.inFlight == nil {
		u.inFlight = make(map[string]bool)
	}
	u.inFlight[host] = true
	return true
}

// release gives host back without recording an outcome.
func (u *h3Upgrader) release(host string) {
	u.mu.Lock()
	delete(u.inFlight, host)
	u.mu.Unlock()
}

// end records how the attempt on host went.
func (u *h3Upgrader) end(host string, ok bool, now time.Time) {
	u.mu.Lock()
	defer u.mu.Unlock()
	delete(u.inFlight, host)
	if ok {
		delete(u.broken, host)
		return
	}
	if u.broken == nil {
		u.broken = make(map[string]brokenAlt)
	}
	b := u.broken[host]
	delay := brokenAltInitialDelay << min(b.failures, 10)
	b.failures++
	b.until = now.Add(min(delay, brokenAltMaxDelay))
	u.broken[host] = b
}

// maybeUpgradeToH3 starts a background HTTP/3 connection to a host that is
// being served over TCP but has since sent an Alt-Svc header offering HTTP/3,
// and moves the host to HTTP/3 once that connection is up. The current request
// is not held for it.
//
// Alt-Svc only: a host whose DNS record offers h3 already had its QUIC attempt
// in the first request's race.
func (t *Transport) maybeUpgradeToH3(snap transportSnapshot, rawURL string) {
	if !snap.preset.SupportHTTP3 || snap.h3 == nil || snap.h3ProxyError != nil {
		return
	}
	u, err := url.Parse(rawURL)
	if err != nil || u.Scheme != "https" {
		return
	}
	host, port := u.Hostname(), altsvc.PortOrDefault(u.Port())
	now := time.Now()
	if !t.altSvc.AdvertisesH3(host, port, now) || !t.h3up.begin(host, now) {
		return
	}
	go func() {
		ctx, cancel := context.WithTimeout(t.h3up.context(), h3UpgradeTimeout)
		defer cancel()
		err := snap.h3.Connect(ctx, host, port)
		if t.h3up.context().Err() != nil {
			// The transport closed underneath the attempt; nothing was learned.
			t.h3up.release(host)
			return
		}
		t.h3up.end(host, err == nil, time.Now())
		if err == nil {
			t.cacheProtocol(host, ProtocolHTTP3)
		}
	}()
}

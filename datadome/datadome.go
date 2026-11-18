// Package datadome clears DataDome blocks through the disasm.dev DataDome
// payload API (https://dd.antibotapi.com, docs.disasm.dev/datadome).
//
// A block is answered the way a Chrome on the page answers it: the device
// check ("Verifying your device", the interstitial) or the slider captcha is
// loaded the way the browser's iframe loads it, the page is handed to the
// payload API, and what the API returns is submitted to DataDome. Every
// request to DataDome goes out on the session itself, so it carries the
// session's TLS fingerprint, connection, proxy and cookie jar, and the
// datadome cookie DataDome answers with lands in that jar. The payload API is
// called direct and never makes a request to the site.
//
// A hard block (t=bv) has nothing to answer: the exit's reputation is spent.
// The burned cookie is dropped so the request goes out again like a fresh
// visitor, and when that does not help the response comes back with
// ErrHardBlocked so the caller can change proxy.
//
// httpcloak.WithDatadome wires a Solver into a session so this happens on its
// own: a response that is a block is solved and the request sent again, inside
// the one Do call.
package datadome

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
)

// ErrStillBlocked means the request was blocked again after every solve it
// was allowed (Config.MaxSolves).
var ErrStillBlocked = errors.New("datadome: still blocked after solving")

// ErrHardBlocked means DataDome hard-blocked the request (t=bv) and dropping
// the burned cookie did not clear it. The exit IP is flagged: change proxy.
var ErrHardBlocked = errors.New("datadome: hard blocked (t=bv), the exit IP is flagged")

// DefaultLanguage is the language a solve claims when the session sends no
// Accept-Language.
const DefaultLanguage = "en-GB"

// DefaultIPLookupURL answers with the caller's address and nothing else.
const DefaultIPLookupURL = "https://checkip.amazonaws.com"

// geoOrigin is where the interstitial is served from. An HTML block carries
// no host for it, so the device-check link is built on this one.
const geoOrigin = "https://geo.captcha-delivery.com"

// Config configures a Solver.
type Config struct {
	// APIKey is the payload API key, sent as x-api-key.
	APIKey string

	// JWTSecret is the key's signing secret, for a key that has signing on:
	// each call to the API is then signed (x-signature). Leave it empty
	// otherwise.
	JWTSecret string

	// ServiceURL is where the payload API is. Empty means DefaultServiceURL.
	ServiceURL string

	// MaxSolves is how many blocks one request may answer before it gives up
	// with ErrStillBlocked (or ErrHardBlocked). 0 means 3.
	MaxSolves int

	// IPLookupURL is fetched through the session to learn its exit IP, which
	// every payload carries. It must answer with the address alone. Empty
	// means DefaultIPLookupURL. The answer is kept for 30 minutes per proxy.
	IPLookupURL string

	// HTTPClient makes the calls to the payload API, which go direct rather
	// than through the session's proxy: the exit IP travels inside the
	// payload, so there is no reason to leave from it. Nil means a client
	// with a 30s timeout.
	HTTPClient *http.Client

	// Logf, when set, is told each solve's start and outcome.
	Logf func(format string, args ...any)
}

// Kind is what a response is to DataDome.
type Kind int

const (
	// NotBlocked is a response DataDome let through.
	NotBlocked Kind = iota
	// Interstitial is the "Verifying your device" device check.
	Interstitial
	// Captcha is the slider captcha.
	Captcha
	// HardBlock is a block with nothing to answer (t=bv).
	HardBlock
)

func (k Kind) String() string {
	switch k {
	case Interstitial:
		return "interstitial"
	case Captcha:
		return "captcha"
	case HardBlock:
		return "hard block"
	}
	return "not blocked"
}

// MayBeBlock reports whether a response is worth reading for a block: an
// error status with a text body (or no Content-Type at all). DataDome never
// blocks with a 2xx, so a page that loaded is never buffered for nothing.
func MayBeBlock(status int, headers map[string][]string) bool {
	if status < 400 {
		return false
	}
	var contentType string
	for name, values := range headers {
		if strings.EqualFold(name, "content-type") && len(values) > 0 {
			contentType = strings.ToLower(values[0])
			break
		}
	}
	if contentType == "" {
		return true
	}
	for _, kind := range []string{"html", "json", "text", "xml", "javascript"} {
		if strings.Contains(contentType, kind) {
			return true
		}
	}
	return false
}

// Classify reads a block from a response body. A page the browser renders
// boots the challenge with DataDome's i.js (interstitial) or c.js (captcha);
// an XHR is answered with JSON naming the challenge URL. Either one carrying
// t=bv is a hard block.
func Classify(body []byte) Kind {
	kind := NotBlocked
	if link, ok := jsonBlockURL(body); ok {
		switch {
		case strings.HasPrefix(link.Path, "/interstitial"):
			kind = Interstitial
		case strings.HasPrefix(link.Path, "/captcha"):
			kind = Captcha
		}
	} else if bytes.Contains(body, []byte(`src="https://ct.captcha-delivery.com/i.js"`)) {
		kind = Interstitial
	} else if bytes.Contains(body, []byte(`src="https://ct.captcha-delivery.com/c.js`)) {
		kind = Captcha
	}
	if kind != NotBlocked && (bytes.Contains(body, []byte("t=bv")) || bytes.Contains(body, []byte("'t':'bv'"))) {
		return HardBlock
	}
	return kind
}

// Identity is the browser a solve presents as: the session's User-Agent,
// its low-entropy client hints and its Accept-Language, exactly as the
// session sends them on its own requests.
type Identity struct {
	UserAgent       string
	SecChUa         string
	SecChUaMobile   string
	SecChUaPlatform string
	AcceptLanguage  string

	// Accept and ImageAccept are the browser's Accept on a navigation and on
	// an image load. Empty means Chrome 155's.
	Accept      string
	ImageAccept string
}

// language is the first tag of the Accept-Language. DataDome bakes it into
// the payload and checks it against the header on every later request.
func (id Identity) language() string {
	first, _, _ := strings.Cut(id.AcceptLanguage, ",")
	first, _, _ = strings.Cut(first, ";")
	if first = strings.TrimSpace(first); first != "" {
		return first
	}
	return DefaultLanguage
}

func (id Identity) acceptLanguage() string {
	if id.AcceptLanguage != "" {
		return id.AcceptLanguage
	}
	return DefaultLanguage
}

// Header is one request header, sent with this name and value in this place.
type Header struct {
	Name, Value string
}

// Request is a request a solve sends exactly as given: headers in this order
// and casing and nothing added. A Cookie header with an empty value is a slot
// the session fills from its jar, or drops when the jar has nothing.
type Request struct {
	Method  string
	URL     string
	Headers []Header
	Body    string
}

// Reply is what came of a Request, its body with any Content-Encoding removed.
type Reply struct {
	Status  int
	Headers map[string][]string
	Body    []byte
}

// Browser is the session a block stands in front of. The datadome cookie a
// solve earns is good for its jar, IP and fingerprint only, so everything
// goes through it.
type Browser interface {
	// Send sends req exactly as given, without following a redirect.
	Send(ctx context.Context, req *Request) (*Reply, error)

	// Proxy names the route the session's requests leave by ("" direct). The
	// exit IP is kept per route.
	Proxy() string

	// Cookie is the value of the datadome cookie the jar would send to rawURL.
	Cookie(rawURL string) string

	// StoreCookie stores a Set-Cookie line DataDome handed back as though
	// rawURL's server had sent it, replacing the datadome cookie the jar
	// would send there.
	StoreCookie(rawURL, setCookie string) error

	// ClearCookie removes the datadome cookie the jar would send to rawURL.
	ClearCookie(rawURL string)

	// AdoptClientHints makes the session send these client hint values
	// (keyed by lowercase header name) from now on wherever a host asks for
	// them. The payload was built with them, and DataDome compares the two on
	// every later request.
	AdoptClientHints(hints map[string]string)
}

// Block is a blocked request, as the session saw it.
type Block struct {
	Kind Kind

	// URL is the URL that was blocked.
	URL string

	// Body is the block's body.
	Body []byte

	// XHR is true when the blocked request was not a top-level navigation.
	XHR bool

	// PageURL is the page a blocked XHR ran on (its Referer). An HTML block
	// on an XHR names that page in the challenge link, so it is needed there.
	PageURL string
}

// Outcome is what came of answering a block.
type Outcome struct {
	// Escalated means the interstitial was answered with a captcha instead of
	// a cookie: nothing was stored. Sending the request again gets a fresh
	// block, which is answered in its turn.
	Escalated bool

	// RedirectURL is the URL DataDome wants navigated to after an
	// interstitial (view=redirect): the page that was blocked.
	RedirectURL string

	// Shared means another request's solve of the same host was waited on
	// instead of running a second one.
	Shared bool
}

// Solver answers the blocks one session runs into. Solves of one host run one
// at a time: a request blocked while a solve of its host is under way waits
// for it instead of paying for a second.
type Solver struct {
	api       *api
	browser   Browser
	maxSolves int
	ipURL     string
	logf      func(format string, args ...any)

	mu       sync.Mutex
	inflight map[string]*solving

	ipMu      sync.Mutex
	ipProxy   string
	ipAddress string
	ipExpires time.Time
}

type solving struct {
	done chan struct{}
	err  error
}

// ipTTL is how long a looked-up exit IP is trusted for one route.
const ipTTL = 30 * time.Minute

// New returns a Solver that answers blocks through browser.
func New(cfg Config, browser Browser) *Solver {
	base := strings.TrimRight(cfg.ServiceURL, "/")
	if base == "" {
		base = DefaultServiceURL
	}
	client := cfg.HTTPClient
	if client == nil {
		client = &http.Client{Timeout: 30 * time.Second}
	}
	maxSolves := cfg.MaxSolves
	if maxSolves <= 0 {
		maxSolves = 3
	}
	ipURL := cfg.IPLookupURL
	if ipURL == "" {
		ipURL = DefaultIPLookupURL
	}
	return &Solver{
		api:       &api{base: base, key: cfg.APIKey, jwtSecret: cfg.JWTSecret, client: client},
		browser:   browser,
		maxSolves: maxSolves,
		ipURL:     ipURL,
		logf:      cfg.Logf,
		inflight:  make(map[string]*solving),
	}
}

// MaxSolves is how many blocks one request may answer.
func (s *Solver) MaxSolves() int {
	return s.maxSolves
}

// Solve answers b, presenting as id. An interstitial or captcha is solved and
// the datadome cookie it earns stored in the jar; a hard block has its burned
// cookie dropped. Either way the caller sends the request again. Its errors
// start "datadome:"; a refusal from the payload API is an *APIError
// underneath.
func (s *Solver) Solve(ctx context.Context, b *Block, id Identity) (*Outcome, error) {
	if b.Kind == HardBlock {
		s.log("datadome: hard block on %s, dropping the datadome cookie", hostOf(b.URL))
		s.browser.ClearCookie(b.URL)
		return &Outcome{}, nil
	}
	if b.Kind != Interstitial && b.Kind != Captcha {
		return nil, fmt.Errorf("datadome: nothing to solve in a %s response", b.Kind)
	}
	host := hostOf(b.URL)
	for {
		s.mu.Lock()
		if c, ok := s.inflight[host]; ok {
			s.mu.Unlock()
			select {
			case <-ctx.Done():
				return nil, ctx.Err()
			case <-c.done:
			}
			// The solve waited on was cut short by its own caller's context,
			// not refused, so this caller solves for itself.
			if isContextError(c.err) && ctx.Err() == nil {
				continue
			}
			if c.err != nil {
				return nil, c.err
			}
			return &Outcome{Shared: true}, nil
		}
		c := &solving{done: make(chan struct{})}
		s.inflight[host] = c
		s.mu.Unlock()

		out, err := s.solve(ctx, b, id)
		if err != nil {
			err = fmt.Errorf("datadome: %w", err)
		}
		c.err = err

		s.mu.Lock()
		delete(s.inflight, host)
		s.mu.Unlock()
		close(c.done)
		return out, err
	}
}

func (s *Solver) solve(ctx context.Context, b *Block, id Identity) (*Outcome, error) {
	started := time.Now()
	s.log("datadome: %s on %s, solving", b.Kind, hostOf(b.URL))
	var (
		out *Outcome
		err error
	)
	if b.Kind == Captcha {
		out, err = s.solveCaptcha(ctx, b, id)
	} else {
		out, err = s.solveInterstitial(ctx, b, id)
	}
	switch {
	case err != nil:
		s.log("datadome: %s on %s failed after %s: %v", b.Kind, hostOf(b.URL), time.Since(started).Round(time.Millisecond), err)
	case out.Escalated:
		s.log("datadome: %s escalated the interstitial to a captcha", hostOf(b.URL))
	default:
		s.log("datadome: solved the %s on %s in %s", b.Kind, hostOf(b.URL), time.Since(started).Round(time.Millisecond))
	}
	return out, err
}

// adopt takes the client hints a payload was built with. The low-entropy
// brands are not negotiable: a different sec-ch-ua means the API built the
// payload for another build than the session's TLS and User-Agent claim.
func (s *Solver) adopt(hints map[string]string, id Identity) error {
	if len(hints) == 0 {
		return nil
	}
	lower := make(map[string]string, len(hints))
	for name, value := range hints {
		lower[strings.ToLower(name)] = value
	}
	if brands, ok := lower["sec-ch-ua"]; ok && id.SecChUa != "" && brands != id.SecChUa {
		return fmt.Errorf("the payload was built for sec-ch-ua %s but the session sends %s; use a preset whose browser the API supports", brands, id.SecChUa)
	}
	s.browser.AdoptClientHints(lower)
	return nil
}

// exitIP is the address the session's requests leave from, looked up through
// the session itself and kept per route.
func (s *Solver) exitIP(ctx context.Context, id Identity) (string, error) {
	proxy := s.browser.Proxy()
	s.ipMu.Lock()
	if s.ipAddress != "" && s.ipProxy == proxy && time.Now().Before(s.ipExpires) {
		ip := s.ipAddress
		s.ipMu.Unlock()
		return ip, nil
	}
	s.ipMu.Unlock()

	reply, err := s.browser.Send(ctx, &Request{
		Method: http.MethodGet,
		URL:    s.ipURL,
		Headers: []Header{
			{"user-agent", id.UserAgent},
			{"accept", "text/plain,*/*;q=0.8"},
			{"accept-encoding", "gzip, deflate, br"},
			{"accept-language", id.acceptLanguage()},
		},
	})
	if err != nil {
		return "", fmt.Errorf("exit IP lookup: %w", err)
	}
	ip := strings.TrimSpace(string(reply.Body))
	if reply.Status != http.StatusOK || net.ParseIP(ip) == nil {
		return "", fmt.Errorf("exit IP lookup answered [%d] %q instead of an address", reply.Status, truncate(ip, 120))
	}

	s.ipMu.Lock()
	s.ipProxy, s.ipAddress, s.ipExpires = proxy, ip, time.Now().Add(ipTTL)
	s.ipMu.Unlock()
	return ip, nil
}

// get sends a GET that has to answer 200 and returns its body.
func (s *Solver) get(ctx context.Context, what, rawURL string, headers []Header) ([]byte, error) {
	reply, err := s.browser.Send(ctx, &Request{Method: http.MethodGet, URL: rawURL, Headers: headers})
	if err != nil {
		return nil, fmt.Errorf("%s: %w", what, err)
	}
	if reply.Status != http.StatusOK {
		return nil, fmt.Errorf("%s answered [%d]", what, reply.Status)
	}
	return reply.Body, nil
}

func (s *Solver) log(format string, args ...any) {
	if s.logf != nil {
		s.logf(format, args...)
	}
}

func isContextError(err error) bool {
	return errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded)
}

func hostOf(rawURL string) string {
	u, err := url.Parse(rawURL)
	if err != nil {
		return rawURL
	}
	return u.Host
}

// originOf is scheme://host of rawURL.
func originOf(rawURL string) string {
	u, err := url.Parse(rawURL)
	if err != nil {
		return rawURL
	}
	return u.Scheme + "://" + u.Host
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "…"
}

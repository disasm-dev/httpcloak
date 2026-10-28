// Package cloudflare clears Cloudflare challenges through the cf.antibotapi.com
// solve service.
//
// A challenge page is handed to the service, which answers with the requests a
// Chrome on the page would make, one at a time, each exactly as Chrome sends
// it. The session sends them itself, so every one goes out with the session's
// own TLS fingerprint, connection and cookie jar, and hands back what came of
// each until the page's form is sent and Cloudflare sets cf_clearance in the
// jar. The service never makes a request to the site.
//
// httpcloak.WithCloudflare wires a Solver into a session so this happens on
// its own: a response that is a challenge is cleared and the request sent
// again, inside the one Do call.
package cloudflare

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
)

// ErrNotCleared means a solve ran to the end and Cloudflare did not let the
// session in: the page's form was answered with the challenge again.
var ErrNotCleared = errors.New("cloudflare: challenge not cleared")

// ErrStillChallenged means the request was challenged again after every solve
// it was allowed (Config.MaxSolves) had cleared.
var ErrStillChallenged = errors.New("cloudflare: still challenged after clearing")

// maxSteps bounds one solve's requests. A clear takes about ten; the service
// ends a solve long before this, so it only guards against a loop.
const maxSteps = 64

// Config configures a Solver.
type Config struct {
	// APIKey is the cf.antibotapi.com API key, sent as x-api-key.
	APIKey string

	// JWTSecret is the key's JWT secret, for a key that has JWT on: each call
	// to the service is then signed (x-signature). Leave it empty otherwise.
	JWTSecret string

	// ServiceURL is where the solve service is. Empty means DefaultServiceURL.
	ServiceURL string

	// MaxSolves is how many challenges one request may clear before it gives
	// up with ErrStillChallenged. 0 means 2: Cloudflare can answer a cleared
	// request with a fresh challenge once, never usefully more.
	MaxSolves int

	// HTTPClient makes the calls to the solve service, which go direct rather
	// than through the session's proxy. Nil means a client with a 30s timeout.
	HTTPClient *http.Client

	// Logf, when set, is told each solve's start and outcome.
	Logf func(format string, args ...any)
}

// Browser sends a solve's requests. It is the session the challenge stands in
// front of: the cf_clearance a solve ends with is for its jar, its IP and its
// TLS fingerprint, so nothing else can send them.
type Browser interface {
	// Send sends the step exactly as given, its empty cookie slot filled from
	// the jar, without following a redirect, and returns what came back. It
	// stops when ctx is done.
	Send(ctx context.Context, step *Step) (*Reply, error)
}

// Solver clears the challenges one session runs into. Clears of one host run
// one at a time: a request challenged while a clear of its host is under way
// waits for that clear instead of paying for a second.
type Solver struct {
	api       *api
	browser   Browser
	maxSolves int
	logf      func(format string, args ...any)

	mu       sync.Mutex
	inflight map[string]*clearing
}

type clearing struct {
	done chan struct{}
	err  error
}

// New returns a Solver that clears challenges through browser.
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
		maxSolves = 2
	}
	return &Solver{
		api:       &api{base: base, key: cfg.APIKey, jwtSecret: cfg.JWTSecret, client: client},
		browser:   browser,
		maxSolves: maxSolves,
		logf:      cfg.Logf,
		inflight:  make(map[string]*clearing),
	}
}

// MaxSolves is how many challenges one request may clear.
func (s *Solver) MaxSolves() int {
	return s.maxSolves
}

// IsChallenge reports whether a response's headers mark it as one Cloudflare
// may have served a challenge in: cf-mitigated: challenge, which Cloudflare
// puts on every challenge it serves, or a 403 or 503 from a Cloudflare server.
// Only the body says for sure (see IsChallengePage); this decides whether it
// is worth reading.
func IsChallenge(status int, headers map[string][]string) bool {
	if headerHas(headers, "cf-mitigated", "challenge") {
		return true
	}
	return (status == http.StatusForbidden || status == http.StatusServiceUnavailable) && headerHas(headers, "server", "cloudflare")
}

// IsChallengePage reports whether a body is a challenge page, the one a solve
// starts from: it boots the challenge with window._cf_chl_opt. A block page,
// error 1020 and the like, has none, and nothing clears it.
func IsChallengePage(body []byte) bool {
	return bytes.Contains(body, []byte("_cf_chl_opt"))
}

func headerHas(headers map[string][]string, name, value string) bool {
	for key, values := range headers {
		if !strings.EqualFold(key, name) {
			continue
		}
		for _, v := range values {
			if strings.EqualFold(strings.TrimSpace(v), value) {
				return true
			}
		}
	}
	return false
}

// Clear clears the challenge page html that page answered with, presenting as
// the browser whose User-Agent is userAgent, and returns once cf_clearance is
// in the session's jar. Its errors start "cloudflare:"; a refusal from the
// service is an *APIError underneath.
func (s *Solver) Clear(ctx context.Context, page *url.URL, html []byte, userAgent string) error {
	for {
		s.mu.Lock()
		if c, ok := s.inflight[page.Host]; ok {
			s.mu.Unlock()
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-c.done:
			}
			// The clear waited on was cut short by its own caller's context,
			// not refused, so this caller clears for itself.
			if isContextError(c.err) && ctx.Err() == nil {
				continue
			}
			return c.err
		}
		c := &clearing{done: make(chan struct{})}
		s.inflight[page.Host] = c
		s.mu.Unlock()

		c.err = s.solve(ctx, page, html, userAgent)
		if c.err != nil && !errors.Is(c.err, ErrNotCleared) {
			c.err = fmt.Errorf("cloudflare: %w", c.err)
		}

		s.mu.Lock()
		delete(s.inflight, page.Host)
		s.mu.Unlock()
		close(c.done)
		return c.err
	}
}

func isContextError(err error) bool {
	return errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded)
}

func (s *Solver) solve(ctx context.Context, page *url.URL, html []byte, userAgent string) error {
	started := time.Now()
	s.log("cloudflare: challenge on %s, solving", page.Host)
	solve, err := s.api.start(ctx, startRequest{URL: page.String(), HTML: string(html), UserAgent: userAgent})
	if err != nil {
		return err
	}
	step := solve.Request
	for sent := 1; ; sent++ {
		if step == nil {
			return errors.New("the solve service gave no request to send")
		}
		if sent > maxSteps {
			return fmt.Errorf("the solve service was still giving requests after %d", maxSteps)
		}
		reply, err := s.send(ctx, step)
		if err != nil {
			return fmt.Errorf("%s %s: %w", step.Method, step.URL, err)
		}
		next, err := s.api.next(ctx, solve.ID, reply)
		if err != nil {
			return err
		}
		if next.Done {
			if !next.Cleared {
				s.log("cloudflare: %s refused the solve after %d requests", page.Host, sent)
				return ErrNotCleared
			}
			s.log("cloudflare: cleared %s in %s (%d requests)", page.Host, time.Since(started).Round(time.Millisecond), sent)
			return nil
		}
		step = next.Request
	}
}

// send sends one step: it is held until its moment, and a step given up at its
// timeout answers status 0, as the page's own sender reports one that went
// unanswered.
func (s *Solver) send(ctx context.Context, step *Step) (*Reply, error) {
	if step.WaitMs > 0 {
		wait := time.NewTimer(time.Duration(step.WaitMs) * time.Millisecond)
		select {
		case <-ctx.Done():
			wait.Stop()
			return nil, ctx.Err()
		case <-wait.C:
		}
	}
	sendCtx := ctx
	if step.TimeoutMs > 0 {
		var cancel context.CancelFunc
		sendCtx, cancel = context.WithTimeout(ctx, time.Duration(step.TimeoutMs)*time.Millisecond)
		defer cancel()
	}
	reply, err := s.browser.Send(sendCtx, step)
	if err != nil {
		if ctx.Err() == nil && errors.Is(sendCtx.Err(), context.DeadlineExceeded) {
			reply = &Reply{}
		} else {
			return nil, err
		}
	}
	// The service takes every field: a nil body would go as null, not "".
	if reply.Headers == nil {
		reply.Headers = map[string]string{}
	}
	if reply.Body == nil {
		reply.Body = []byte{}
	}
	return reply, nil
}

func (s *Solver) log(format string, args ...any) {
	if s.logf != nil {
		s.logf(format, args...)
	}
}

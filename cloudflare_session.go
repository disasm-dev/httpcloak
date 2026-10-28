package httpcloak

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net/url"
	"strings"

	"github.com/sardanioss/httpcloak/cloudflare"
	"github.com/sardanioss/httpcloak/fingerprint"
)

// WithCloudflare clears the Cloudflare challenges the session runs into through
// the cf.antibotapi.com solve service, with the given API key. It works the way
// cloudscraper does: a response that is a challenge page is solved and the
// request sent again, inside the one Do call, and the caller gets the page
// behind the challenge. The cf_clearance the solve ends with stays in the
// session's jar, so the requests after it go straight through.
//
// The solve's requests go out on the session itself, with its fingerprint,
// proxy and jar, because cf_clearance is only good for the client that earned
// it. They present as the browser the session's User-Agent names, so the
// preset has to send one the service has a device for (chrome-latest-windows
// does); a session sending any other is refused with the list it has.
//
//	s := httpcloak.NewSession("chrome-latest-windows", httpcloak.WithCloudflare(apiKey))
//	resp, err := s.Get(ctx, "https://protected.example/")
//
// Do and DoWithBody clear challenges; DoStream does not. A request whose body
// is a stream with no GetBody cannot go out twice: its challenge is cleared,
// and the challenge response comes back with an error wrapping
// ErrBodyNotReplayable.
func WithCloudflare(apiKey string) SessionOption {
	return WithCloudflareConfig(cloudflare.Config{APIKey: apiKey})
}

// WithCloudflareConfig is WithCloudflare with the solver's other settings: a
// JWT secret for a key that has JWT on, another service address, how many
// challenges one request may clear, and a logger.
func WithCloudflareConfig(cfg cloudflare.Config) SessionOption {
	return func(c *sessionConfig) {
		c.cloudflare = &cfg
	}
}

// clearingKey marks a request the challenge handling sends itself, a solve's
// step or a request going out again, so Do sends it as it stands.
type clearingKey struct{}

func clearingChallenges(ctx context.Context) bool {
	marked, _ := ctx.Value(clearingKey{}).(bool)
	return marked
}

func (s *Session) enableCloudflare(cfg *cloudflare.Config) {
	if cfg == nil {
		return
	}
	s.cloudflareConfig = cfg
	s.cloudflare = cloudflare.New(*cfg, cloudflareBrowser{s})
}

// doClearing is Do for a session that clears Cloudflare challenges: while the
// response is a challenge page, the challenge is cleared and the request sent
// again. A challenge that cannot be cleared comes back with the error saying
// why.
func (s *Session) doClearing(ctx context.Context, req *Request) (*Response, error) {
	send := *req
	rewind := replayable(&send)
	marked := context.WithValue(ctx, clearingKey{}, true)

	resp, err := s.Do(marked, &send)
	for cleared := 0; err == nil; cleared++ {
		html, challenged := challengePage(resp)
		if !challenged {
			return resp, nil
		}
		if cleared == s.cloudflare.MaxSolves() {
			return resp, cloudflare.ErrStillChallenged
		}
		page := resp.FinalURL
		if page == "" {
			page = req.URL
		}
		pageURL, perr := url.Parse(page)
		if perr != nil {
			return resp, fmt.Errorf("cloudflare: %w", perr)
		}
		if cerr := s.cloudflare.Clear(ctx, pageURL, html, s.userAgent(req)); cerr != nil {
			return resp, cerr
		}
		if rewind == nil {
			return resp, fmt.Errorf("cloudflare: cleared, but the request cannot go out again: %w", ErrBodyNotReplayable)
		}
		if rerr := rewind(); rerr != nil {
			return resp, fmt.Errorf("cloudflare: reopen request body: %w", rerr)
		}
		resp, err = s.Do(marked, &send)
	}
	return resp, err
}

// replayable makes req's body one that can go out again and returns what
// rewinds it, or nil when it cannot. A body already in memory is read once and
// served fresh each time; a stream re-opens from GetBody.
func replayable(req *Request) func() error {
	switch body := req.Body.(type) {
	case nil:
		return func() error { return nil }
	case *bytes.Reader, *bytes.Buffer, *strings.Reader:
		data, _ := io.ReadAll(body)
		req.Body = bytes.NewReader(data)
		return func() error {
			req.Body = bytes.NewReader(data)
			return nil
		}
	}
	if req.GetBody == nil {
		return nil
	}
	return func() error {
		body, err := req.GetBody()
		req.Body = body
		return err
	}
}

// challengePage returns resp's body when it is a challenge page, leaving it
// readable for the caller either way.
func challengePage(resp *Response) ([]byte, bool) {
	if resp == nil || resp.Body == nil || !cloudflare.IsChallenge(resp.StatusCode, resp.Headers) {
		return nil, false
	}
	body, err := io.ReadAll(resp.Body)
	resp.Body.Close()
	resp.Body = io.NopCloser(bytes.NewReader(body))
	if err != nil {
		return nil, false
	}
	return body, cloudflare.IsChallengePage(body)
}

// userAgent is the User-Agent req goes out with: one it sets itself, else the
// preset's.
func (s *Session) userAgent(req *Request) string {
	for _, h := range req.ExactHeaders {
		if strings.EqualFold(h.Key, "user-agent") {
			return h.Value
		}
	}
	for name, values := range req.Headers {
		if strings.EqualFold(name, "user-agent") && len(values) > 0 {
			return values[0]
		}
	}
	return fingerprint.Get(s.inner.Config.Preset).UserAgent
}

// cloudflareBrowser sends a solve's steps on the session: exactly as given,
// the cookie slot filled from the jar, redirects handed back.
type cloudflareBrowser struct {
	s *Session
}

func (b cloudflareBrowser) Send(ctx context.Context, step *cloudflare.Step) (*cloudflare.Reply, error) {
	headers := make([]fingerprint.HeaderPair, 0, len(step.Headers))
	for _, h := range step.Headers {
		if len(h) != 2 {
			return nil, errors.New("the solve service gave a header that is not a name and a value")
		}
		headers = append(headers, fingerprint.HeaderPair{Key: h[0], Value: h[1]})
	}
	var body io.Reader
	if step.Body != nil {
		body = strings.NewReader(*step.Body)
	}
	follow := false
	resp, err := b.s.Do(context.WithValue(ctx, clearingKey{}, true), &Request{
		Method:                  step.Method,
		URL:                     step.URL,
		ExactHeaders:            headers,
		Body:                    body,
		FollowRedirects:         &follow,
		DisableConditionalCache: true,
	})
	if err != nil {
		return nil, err
	}
	defer resp.Close()
	data, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	reply := &cloudflare.Reply{Status: resp.StatusCode, Headers: make(map[string]string, len(resp.Headers)), Body: data}
	for name, values := range resp.Headers {
		reply.Headers[strings.ToLower(name)] = strings.Join(values, ", ")
	}
	return reply, nil
}

func (b cloudflareBrowser) DeleteCookie(target *url.URL, name string) {
	host := strings.ToLower(target.Hostname())
	for _, c := range b.s.inner.GetCookies() {
		if c.Name != name {
			continue
		}
		domain := strings.TrimPrefix(strings.ToLower(c.Domain), ".")
		if host == domain || strings.HasSuffix(host, "."+domain) {
			b.s.inner.DeleteCookie(name, c.Domain)
		}
	}
}

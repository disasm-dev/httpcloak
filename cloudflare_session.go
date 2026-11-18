package httpcloak

import (
	"context"
	"errors"
	"io"
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

func (s *Session) enableCloudflare(cfg *cloudflare.Config) {
	if cfg == nil {
		return
	}
	s.cloudflareConfig = cfg
	s.cloudflare = cloudflare.New(*cfg, cloudflareBrowser{s})
}

// challengePage returns resp's body when it is a challenge page, leaving it
// readable for the caller either way.
func challengePage(resp *Response) ([]byte, bool) {
	if resp == nil || resp.Body == nil || !cloudflare.IsChallenge(resp.StatusCode, resp.Headers) {
		return nil, false
	}
	body, err := readBody(resp)
	if err != nil {
		return nil, false
	}
	return body, cloudflare.IsChallengePage(body)
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

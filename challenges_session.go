package httpcloak

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net/url"
	"strings"

	"github.com/sardanioss/httpcloak/cloudflare"
	"github.com/sardanioss/httpcloak/fingerprint"
)

// clearingKey marks a request the challenge handling sends itself, a solve's
// step or a request going out again, so Do sends it as it stands.
type clearingKey struct{}

func clearingChallenges(ctx context.Context) bool {
	marked, _ := ctx.Value(clearingKey{}).(bool)
	return marked
}

// clearsChallenges reports whether the session answers anti-bot challenges
// itself (WithCloudflare, WithDatadome).
func (s *Session) clearsChallenges() bool {
	return s.cloudflare != nil || s.datadome != nil
}

// clearState counts what one request has answered so far.
type clearState struct {
	cloudflare  int  // Cloudflare challenges cleared
	datadome    int  // DataDome blocks answered
	hardCleared bool // a DataDome hard block already had its cookie dropped
}

// doClearing is Do for a session that answers anti-bot challenges: while the
// response is a challenge or block, it is answered and the request sent again.
// One that cannot be answered comes back with the error saying why.
func (s *Session) doClearing(ctx context.Context, req *Request) (*Response, error) {
	send := *req
	rewind := replayable(&send)
	marked := context.WithValue(ctx, clearingKey{}, true)

	var state clearState
	resp, err := s.Do(marked, &send)
	for err == nil {
		provider, aerr := s.answerChallenge(ctx, req, &send, resp, &state)
		if aerr != nil {
			return resp, aerr
		}
		if provider == "" {
			return resp, nil
		}
		if rewind == nil {
			return resp, fmt.Errorf("%s: cleared, but the request cannot go out again: %w", provider, ErrBodyNotReplayable)
		}
		if rerr := rewind(); rerr != nil {
			return resp, fmt.Errorf("%s: reopen request body: %w", provider, rerr)
		}
		resp, err = s.Do(marked, &send)
	}
	return resp, err
}

// answerChallenge answers the challenge resp is, if it is one, and names the
// provider whose challenge it answered; "" means resp is not a challenge and
// goes back to the caller as it is. send is the request as it goes out again,
// which an answer may rewrite.
func (s *Session) answerChallenge(ctx context.Context, req, send *Request, resp *Response, state *clearState) (string, error) {
	if s.cloudflare != nil {
		if html, challenged := challengePage(resp); challenged {
			if state.cloudflare == s.cloudflare.MaxSolves() {
				return "", cloudflare.ErrStillChallenged
			}
			state.cloudflare++
			page := resp.FinalURL
			if page == "" {
				page = req.URL
			}
			pageURL, err := url.Parse(page)
			if err != nil {
				return "", fmt.Errorf("cloudflare: %w", err)
			}
			if err := s.cloudflare.Clear(ctx, pageURL, html, s.userAgent(req)); err != nil {
				return "", err
			}
			return "cloudflare", nil
		}
	}
	if s.datadome != nil {
		answered, err := s.answerDatadome(ctx, send, resp, state)
		if err != nil || !answered {
			return "", err
		}
		return "datadome", nil
	}
	return "", nil
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

// readBody returns resp's body, leaving it readable for the caller.
func readBody(resp *Response) ([]byte, error) {
	body, err := io.ReadAll(resp.Body)
	resp.Body.Close()
	resp.Body = io.NopCloser(bytes.NewReader(body))
	return body, err
}

// userAgent is the User-Agent req goes out with: one it sets itself, else the
// preset's.
func (s *Session) userAgent(req *Request) string {
	if ua := requestHeader(req, "user-agent"); ua != "" {
		return ua
	}
	return fingerprint.Get(s.inner.Config.Preset).UserAgent
}

// requestHeader is the value req sets for name, from ExactHeaders when it
// has them, else from Headers.
func requestHeader(req *Request, name string) string {
	if len(req.ExactHeaders) > 0 {
		for _, h := range req.ExactHeaders {
			if strings.EqualFold(h.Key, name) {
				return h.Value
			}
		}
		return ""
	}
	for key, values := range req.Headers {
		if strings.EqualFold(key, name) && len(values) > 0 {
			return values[0]
		}
	}
	return ""
}

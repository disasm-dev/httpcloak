package cloudflare

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

// DefaultServiceURL is the solve service a Config without a ServiceURL uses.
const DefaultServiceURL = "https://cf.antibotapi.com"

// Step is a request a solve sends exactly as the service gives it: the headers
// as name, value pairs in the order Chrome sends them for that kind of request,
// the cookie one left empty for the session to fill from its jar. It is held
// WaitMs before going out, because Cloudflare refuses an answer that arrives
// sooner than the time it claims to have taken, and given up after TimeoutMs
// (0: no limit), which the service is told as status 0. DeleteCookies names the
// cookies to drop from the jar before it is sent.
type Step struct {
	Method        string     `json:"method"`
	URL           string     `json:"url"`
	Headers       [][]string `json:"headers"`
	Body          *string    `json:"body,omitempty"`
	WaitMs        int        `json:"wait_ms"`
	TimeoutMs     int        `json:"timeout_ms"`
	DeleteCookies []string   `json:"delete_cookies,omitempty"`
}

// Reply is what came of a Step: the status (0 when it was given up at its
// timeout), the response headers by name, and the body with its
// Content-Encoding removed.
type Reply struct {
	Status  int               `json:"status"`
	Headers map[string]string `json:"headers"`
	Body    []byte            `json:"body"`
}

// APIError is a refusal from the solve service.
type APIError struct {
	StatusCode int
	Message    string

	// UserAgents lists the User-Agents the service has a device for, when the
	// one the session sends is not among them. A solve presents as a real
	// browser, so the session has to be that browser: use a preset whose
	// User-Agent is listed here.
	UserAgents []string
}

func (e *APIError) Error() string {
	msg := e.Message
	if msg == "" {
		msg = http.StatusText(e.StatusCode)
	}
	if len(e.UserAgents) > 0 {
		return fmt.Sprintf("solve service answered %d: %s (it has a device for %s; use a preset that sends one of them)",
			e.StatusCode, msg, strings.Join(e.UserAgents, ", "))
	}
	return fmt.Sprintf("solve service answered %d: %s", e.StatusCode, msg)
}

type startRequest struct {
	URL       string `json:"url"`
	HTML      string `json:"html"`
	UserAgent string `json:"user_agent"`
}

type startResponse struct {
	ID      string `json:"id"`
	Request *Step  `json:"request"`
}

type nextResponse struct {
	Request *Step `json:"request"`
	Done    bool  `json:"done"`
	Cleared bool  `json:"cleared"`
}

// api is the solve service: POST /solves starts a solve from the challenge page
// and answers the first Step; POST /solves/{id}/next takes the Reply to the
// last one and answers the next, until it says done.
type api struct {
	base      string
	key       string
	jwtSecret string
	client    *http.Client
}

func (a *api) start(ctx context.Context, in startRequest) (*startResponse, error) {
	var out startResponse
	if err := a.post(ctx, "/solves", in, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

func (a *api) next(ctx context.Context, id string, reply *Reply) (*nextResponse, error) {
	var out nextResponse
	if err := a.post(ctx, "/solves/"+id+"/next", reply, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

func (a *api) post(ctx context.Context, path string, in, out any) error {
	body, err := json.Marshal(in)
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, a.base+path, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	if a.key != "" {
		req.Header.Set("x-api-key", a.key)
	}
	if a.jwtSecret != "" {
		req.Header.Set("x-signature", signature(a.key, a.jwtSecret, time.Now()))
	}
	resp, err := a.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	data, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return err
	}
	if resp.StatusCode != http.StatusOK {
		return refusal(resp.StatusCode, data)
	}
	return json.Unmarshal(data, out)
}

// refusal reads the service's error body. Its own refusals are {"error": "…"},
// with user_agents beside it for a User-Agent it has no device for; a key it
// does not let in is answered in disasm's envelope, {"error": {"message": "…"}}.
// A solve it no longer holds is a bare 404.
func refusal(status int, body []byte) *APIError {
	e := &APIError{StatusCode: status}
	var shape struct {
		Error      json.RawMessage `json:"error"`
		UserAgents []string        `json:"user_agents"`
	}
	if json.Unmarshal(body, &shape) == nil {
		e.UserAgents = shape.UserAgents
		if json.Unmarshal(shape.Error, &e.Message) != nil {
			var envelope struct {
				Message string `json:"message"`
			}
			if json.Unmarshal(shape.Error, &envelope) == nil {
				e.Message = envelope.Message
			}
		}
	}
	if e.Message == "" && status == http.StatusNotFound {
		e.Message = "the solve is not held any more (it expired or was ended)"
	}
	return e
}

// signature is the x-signature a key with JWT on has to send: an HS256 JWT,
// signed with the key's JWT secret, whose x-api-key claim is the key. It lives
// a minute, which covers one call with room for clock skew.
func signature(key, secret string, now time.Time) string {
	enc := base64.RawURLEncoding
	header := enc.EncodeToString([]byte(`{"alg":"HS256","typ":"JWT"}`))
	claims, _ := json.Marshal(map[string]any{
		"x-api-key": key,
		"iat":       now.Unix(),
		"exp":       now.Add(time.Minute).Unix(),
	})
	payload := enc.EncodeToString(claims)
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte(header + "." + payload))
	return header + "." + payload + "." + enc.EncodeToString(mac.Sum(nil))
}

package httpcloak

import (
	"context"
	"errors"
	"io"
	"strings"

	"github.com/sardanioss/httpcloak/datadome"
	"github.com/sardanioss/httpcloak/fingerprint"
	"github.com/sardanioss/httpcloak/transport"
)

// WithDatadome answers the DataDome blocks the session runs into through the
// disasm.dev DataDome payload API (dd.antibotapi.com), with the given API key.
// A response that is a block is solved and the request sent again, inside the
// one Do call, and the caller gets the page behind it:
//
//   - the interstitial ("Verifying your device") and the slider captcha are
//     loaded as the browser's iframe loads them, solved through the API and
//     submitted, and the datadome cookie DataDome answers with replaces the
//     old one in the session's jar. A blocked navigation then goes out again
//     as the reload DataDome's script starts (Cache-Control: max-age=0, the
//     page as its own Referer, no Sec-Fetch-User); a blocked XHR goes out
//     again unchanged.
//   - a hard block (t=bv) has nothing to answer. Its burned cookie is dropped
//     and the request sent once more like a fresh visitor; when that is
//     blocked too, the response comes back with an error wrapping
//     datadome.ErrHardBlocked, which means change proxy.
//
// Every request to DataDome goes out on the session itself, with its
// fingerprint, proxy and jar, because the cookie is only good for the client
// that earned it. The client hints the API built the payload with are adopted
// by the session and sent on every later request to a host that asks for
// them, since DataDome compares the two. The session needs its cookie jar
// (not WithoutCookieJar) and a Chrome-on-Windows preset, the one browser the
// API presents as (chrome-latest-windows).
//
//	s := httpcloak.NewSession("chrome-latest-windows", httpcloak.WithDatadome(apiKey))
//	resp, err := s.Get(ctx, "https://protected.example/")
//
// An HTML block on an XHR names the page the XHR ran on, which the session
// reads from the request's Referer: set one on API calls. Do and DoWithBody
// answer blocks; DoStream does not. A request whose body is a stream with no
// GetBody cannot go out twice: its block is solved, and the block comes back
// with an error wrapping ErrBodyNotReplayable.
func WithDatadome(apiKey string) SessionOption {
	return WithDatadomeConfig(datadome.Config{APIKey: apiKey})
}

// WithDatadomeConfig is WithDatadome with the solver's other settings: a
// signing secret for a key that has signing on, another API address, how many
// blocks one request may answer, the exit-IP lookup, and a logger.
func WithDatadomeConfig(cfg datadome.Config) SessionOption {
	return func(c *sessionConfig) {
		c.datadome = &cfg
	}
}

func (s *Session) enableDatadome(cfg *datadome.Config) {
	if cfg == nil {
		return
	}
	s.datadomeConfig = cfg
	s.datadome = datadome.New(*cfg, datadomeBrowser{s})
}

// answerDatadome answers the block resp is, if it is one, and reports whether
// the request should go out again. send is that request, which a solved
// interstitial on a navigation rewrites into the reload DataDome's script
// starts.
func (s *Session) answerDatadome(ctx context.Context, send *Request, resp *Response, state *clearState) (bool, error) {
	if resp == nil || resp.Body == nil || !datadome.MayBeBlock(resp.StatusCode, resp.Headers) {
		return false, nil
	}
	body, err := readBody(resp)
	if err != nil {
		return false, nil
	}
	kind := datadome.Classify(body)
	if kind == datadome.NotBlocked {
		return false, nil
	}
	// A second hard block after the burned cookie went is the exit, not the
	// cookie: going out again from the same IP gets the same answer.
	if kind == datadome.HardBlock && state.hardCleared {
		return false, datadome.ErrHardBlocked
	}
	if state.datadome == s.datadome.MaxSolves() {
		if kind == datadome.HardBlock {
			return false, datadome.ErrHardBlocked
		}
		return false, datadome.ErrStillBlocked
	}
	state.datadome++
	if kind == datadome.HardBlock {
		state.hardCleared = true
	}

	blocked := resp.FinalURL
	if blocked == "" {
		blocked = send.URL
	}
	navigation := s.isNavigation(send)
	out, err := s.datadome.Solve(ctx, &datadome.Block{
		Kind:    kind,
		URL:     blocked,
		Body:    body,
		XHR:     !navigation,
		PageURL: requestHeader(send, "referer"),
	}, s.identity(send))
	if err != nil {
		return false, err
	}
	if kind == datadome.Interstitial && navigation && !out.Escalated && !out.Shared {
		reload := out.RedirectURL
		if reload == "" {
			reload = blocked
		}
		asReload(send, reload)
	}
	return true, nil
}

// isNavigation reports whether req goes out as a top-level navigation: by the
// Sec-Fetch-Mode it lists when it lists its headers itself, else by the same
// reading of its shape the preset pipeline makes.
func (s *Session) isNavigation(req *Request) bool {
	if mode := requestHeader(req, "sec-fetch-mode"); mode != "" || len(req.ExactHeaders) > 0 {
		return strings.EqualFold(mode, "navigate")
	}
	tlsOnly := s.inner.Config.TLSOnly
	if req.TLSOnly != nil {
		tlsOnly = *req.TLSOnly
	}
	if tlsOnly {
		return false // no preset headers, so no Sec-Fetch-Mode either
	}
	return transport.IsNavigation(req.Method, req.Headers)
}

// asReload rewrites req into the navigation Chrome makes when DataDome's
// script sends the page to the URL it was blocked on: a reload, so
// Cache-Control: max-age=0, the page as its own Referer, Sec-Fetch-Site
// same-origin and no Sec-Fetch-User, every other header in its slot
// (recorded: powhttp Session 4, 01M1KR2FDKCNBKP5QKPHWQBPNY).
func asReload(req *Request, pageURL string) {
	if len(req.ExactHeaders) > 0 {
		req.ExactHeaders = reloadHeaders(req.ExactHeaders, pageURL)
		return
	}
	headers := make(map[string][]string, len(req.Headers)+3)
	for key, values := range req.Headers {
		switch strings.ToLower(key) {
		case "cache-control", "sec-fetch-site", "sec-fetch-user", "referer":
			continue
		}
		headers[key] = values
	}
	headers["Cache-Control"] = []string{"max-age=0"}
	headers["Sec-Fetch-Site"] = []string{"same-origin"}
	headers["Referer"] = []string{pageURL}
	req.Headers = headers
	req.omitHeaders = []string{"Sec-Fetch-User"}
}

// reloadHeaders is asReload for a request that lists its headers itself.
// Cache-Control goes straight after Connection (first, when there is none, as
// on HTTP/2), and the Referer takes the slot after Sec-Fetch-Dest. Names the
// list writes in lowercase get lowercase ones beside them.
func reloadHeaders(exact []fingerprint.HeaderPair, pageURL string) []fingerprint.HeaderPair {
	lower := true
	for _, h := range exact {
		if h.Key != strings.ToLower(h.Key) {
			lower = false
			break
		}
	}
	name := func(canonical string) string {
		if lower {
			return strings.ToLower(canonical)
		}
		return canonical
	}

	reload := make([]fingerprint.HeaderPair, 0, len(exact)+2)
	placed := false
	for _, h := range exact {
		switch strings.ToLower(h.Key) {
		case "cache-control", "sec-fetch-user", "referer":
			continue
		case "sec-fetch-site":
			reload = append(reload, fingerprint.HeaderPair{Key: h.Key, Value: "same-origin"})
			continue
		}
		reload = append(reload, h)
		switch strings.ToLower(h.Key) {
		case "connection":
			reload = append(reload, fingerprint.HeaderPair{Key: name("Cache-Control"), Value: "max-age=0"})
			placed = true
		case "sec-fetch-dest":
			reload = append(reload, fingerprint.HeaderPair{Key: name("Referer"), Value: pageURL})
		}
	}
	if !placed {
		reload = append([]fingerprint.HeaderPair{{Key: name("Cache-Control"), Value: "max-age=0"}}, reload...)
	}
	return reload
}

// identity is the browser req presents as: the headers it sets itself, else
// the preset's.
func (s *Session) identity(req *Request) datadome.Identity {
	preset := fingerprint.Get(s.inner.Config.Preset)
	header := func(name string) string {
		if v := requestHeader(req, name); v != "" {
			return v
		}
		for _, h := range preset.HeaderOrder {
			if strings.EqualFold(h.Key, name) {
				return h.Value
			}
		}
		for key, value := range preset.Headers {
			if strings.EqualFold(key, name) {
				return value
			}
		}
		return ""
	}
	return datadome.Identity{
		UserAgent:       s.userAgent(req),
		SecChUa:         header("sec-ch-ua"),
		SecChUaMobile:   header("sec-ch-ua-mobile"),
		SecChUaPlatform: header("sec-ch-ua-platform"),
		AcceptLanguage:  header("accept-language"),
		Accept:          preset.ResolveNavigationAccept(),
		ImageAccept:     preset.ResolveImageAccept(),
	}
}

// datadomeBrowser runs a solve's requests and cookie work on the session.
type datadomeBrowser struct {
	s *Session
}

func (b datadomeBrowser) Send(ctx context.Context, req *datadome.Request) (*datadome.Reply, error) {
	headers := make([]fingerprint.HeaderPair, 0, len(req.Headers))
	for _, h := range req.Headers {
		headers = append(headers, fingerprint.HeaderPair{Key: h.Name, Value: h.Value})
	}
	var body io.Reader
	if req.Body != "" {
		body = strings.NewReader(req.Body)
	}
	follow := false
	resp, err := b.s.Do(context.WithValue(ctx, clearingKey{}, true), &Request{
		Method:                  req.Method,
		URL:                     req.URL,
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
	return &datadome.Reply{Status: resp.StatusCode, Headers: resp.Headers, Body: data}, nil
}

func (b datadomeBrowser) Proxy() string {
	return b.s.GetProxy()
}

func (b datadomeBrowser) Cookie(rawURL string) string {
	c, _ := b.s.inner.CookieFor(rawURL, "datadome")
	return c.Value
}

func (b datadomeBrowser) StoreCookie(rawURL, setCookie string) error {
	b.s.inner.StoreSetCookie(rawURL, setCookie)
	value, _, _ := strings.Cut(strings.TrimPrefix(strings.TrimSpace(setCookie), "datadome="), ";")
	if c, ok := b.s.inner.CookieFor(rawURL, "datadome"); !ok || c.Value != value {
		return errors.New("the jar would not keep the datadome cookie for " + rawURL + " (a Secure cookie on http, or a Domain the URL is not in)")
	}
	return nil
}

func (b datadomeBrowser) ClearCookie(rawURL string) {
	b.s.inner.DeleteCookieFor(rawURL, "datadome")
}

func (b datadomeBrowser) AdoptClientHints(hints map[string]string) {
	b.s.inner.SetClientHintValues(hints)
}

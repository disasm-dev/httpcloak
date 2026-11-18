package httpcloak

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/sardanioss/httpcloak/datadome"
	"github.com/sardanioss/httpcloak/fingerprint"
)

// These run a real Session against three local servers standing in for the
// DataDome-protected site, DataDome's geo host and the payload API. What is
// asserted is what each one received, since that is what the real ones see.

const ddPreset = "chrome-latest-windows"

type ddRequest struct {
	method string
	path   string
	query  string
	header http.Header
	body   string
}

type ddRecorder struct {
	mu       sync.Mutex
	requests []ddRequest
}

func (rec *ddRecorder) record(r *http.Request) string {
	body, _ := io.ReadAll(r.Body)
	rec.mu.Lock()
	rec.requests = append(rec.requests, ddRequest{r.Method, r.URL.Path, r.URL.RawQuery, r.Header.Clone(), string(body)})
	rec.mu.Unlock()
	return string(body)
}

func (rec *ddRecorder) received(path string) []ddRequest {
	rec.mu.Lock()
	defer rec.mu.Unlock()
	var out []ddRequest
	for _, r := range rec.requests {
		if r.path == path {
			out = append(out, r)
		}
	}
	return out
}

// ddFixture is the three servers. The site blocks until the jar carries
// datadome=solved, with whatever block(r) answers.
type ddFixture struct {
	site, geo, api          *httptest.Server
	siteRec, geoRec, apiRec ddRecorder

	mu         sync.Mutex
	block      func(f *ddFixture, r *http.Request) string // the block body; "" lets the request through
	views      []string                                   // what the interstitial POST answers, in turn ("" pass)
	apiDelay   time.Duration
	apiRefusal string
}

func newDDFixture(t *testing.T) *ddFixture {
	t.Helper()
	f := &ddFixture{}
	f.site = httptest.NewServer(http.HandlerFunc(f.serveSite))
	f.geo = httptest.NewServer(http.HandlerFunc(f.serveGeo))
	f.api = httptest.NewServer(http.HandlerFunc(f.serveAPI))
	t.Cleanup(func() { f.site.Close(); f.geo.Close(); f.api.Close() })
	f.block = func(f *ddFixture, r *http.Request) string { return f.interstitialJSON(r) }
	return f
}

func (f *ddFixture) session(opts ...SessionOption) *Session {
	cfg := datadome.Config{APIKey: "key-1", ServiceURL: f.api.URL, IPLookupURL: f.site.URL + "/ip"}
	return NewSession(ddPreset, append([]SessionOption{WithDatadomeConfig(cfg)}, opts...)...)
}

func (f *ddFixture) interstitialLink() string {
	return f.geo.URL + "/interstitial/?initialCid=cid0&hash=HASH&cid=blocked&referer=x&dm=jd"
}

func (f *ddFixture) interstitialJSON(*http.Request) string {
	return `{"url":"` + f.interstitialLink() + `"}`
}

func (f *ddFixture) captchaLink() string {
	return f.geo.URL + "/captcha/?initialCid=cid0&hash=HASH&cid=blocked&t=fe&dm=cd"
}

func (f *ddFixture) serveSite(w http.ResponseWriter, r *http.Request) {
	f.siteRec.record(r)
	switch r.URL.Path {
	case "/ip":
		io.WriteString(w, "203.0.113.7\n")
		return
	}
	if c, err := r.Cookie("datadome"); err == nil && c.Value == "solved" {
		w.Header().Set("Content-Type", "application/json")
		io.WriteString(w, `{"ok":true}`)
		return
	}
	f.mu.Lock()
	block := f.block
	f.mu.Unlock()
	body := block(f, r)
	if body == "" {
		w.WriteHeader(http.StatusForbidden)
		io.WriteString(w, "<html>Forbidden</html>")
		return
	}
	http.SetCookie(w, &http.Cookie{Name: "datadome", Value: "blocked", Path: "/"})
	w.Header().Set("Accept-CH", "Sec-CH-UA,Sec-CH-UA-Mobile,Sec-CH-UA-Platform,Sec-CH-UA-Arch,Sec-CH-UA-Full-Version-List,Sec-CH-UA-Model,Sec-CH-Device-Memory")
	if strings.HasPrefix(body, "{") {
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
	} else {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
	}
	w.Header().Set("X-DataDome", "protected")
	w.WriteHeader(http.StatusForbidden)
	io.WriteString(w, body)
}

const (
	ddDeviceCheckPage = `<html><body>device check</body></html>`
	ddBackground      = "\xff\xd8\xff\xe0JFIF background"
	ddFragment        = "\x89PNG fragment"
)

func (f *ddFixture) serveGeo(w http.ResponseWriter, r *http.Request) {
	body := f.geoRec.record(r)
	switch r.URL.Path {
	case "/interstitial/":
		if r.Method == http.MethodGet {
			io.WriteString(w, ddDeviceCheckPage)
			return
		}
		if body != "payload-from-api" {
			http.Error(w, "bad payload", http.StatusBadRequest)
			return
		}
		f.mu.Lock()
		view := ""
		if len(f.views) > 0 {
			view, f.views = f.views[0], f.views[1:]
		}
		f.mu.Unlock()
		if view == "captcha" {
			io.WriteString(w, `{"cookie":"datadome=flagged; Path=/","view":"captcha","url":""}`)
			return
		}
		io.WriteString(w, `{"cookie":"datadome=solved; Max-Age=31536000; Path=/; SameSite=Lax","view":"redirect","url":"`+f.site.URL+`/landing"}`)
	case "/captcha/":
		io.WriteString(w, `<html><script>sliderCaptcha({'captchaChallengePath':'`+f.geo.URL+`/img/bg.jpg','noPuzzle':false})</script></html>`)
	case "/img/bg.jpg":
		io.WriteString(w, ddBackground)
	case "/img/bg.frag.png":
		io.WriteString(w, ddFragment)
	case "/captcha/check":
		io.WriteString(w, `{"cookie":"datadome=solved; Max-Age=31536000; Path=/; SameSite=Lax"}`)
	default:
		http.NotFound(w, r)
	}
}

const ddFullVersionList = `"Google Chrome";v="155.0.7520.12", "Chromium";v="155.0.7520.12", "Not A(Brand";v="24.0.0.0"`

func (f *ddFixture) serveAPI(w http.ResponseWriter, r *http.Request) {
	f.apiRec.record(r)
	f.mu.Lock()
	delay, refusal := f.apiDelay, f.apiRefusal
	f.mu.Unlock()
	time.Sleep(delay)
	if refusal != "" {
		w.WriteHeader(http.StatusForbidden)
		io.WriteString(w, `{"success":false,"error":"`+refusal+`"}`)
		return
	}
	hints, _ := json.Marshal(map[string]string{
		"sec-ch-ua":                   presetHeader(ddPreset, "sec-ch-ua"),
		"sec-ch-ua-full-version-list": ddFullVersionList,
		"sec-ch-device-memory":        "8",
	})
	switch r.URL.Path {
	case "/interstitial":
		io.WriteString(w, `{"success":true,"payload":"payload-from-api","headers":`+string(hints)+`}`)
	case "/captcha":
		io.WriteString(w, `{"success":true,"captcha_submit_url":"`+f.geo.URL+`/captcha/check?ans=1","payload":"ans=1","headers":`+string(hints)+`}`)
	default:
		http.NotFound(w, r)
	}
}

func presetHeader(preset, name string) string {
	for _, h := range fingerprint.Get(preset).HeaderOrder {
		if strings.EqualFold(h.Key, name) {
			return h.Value
		}
	}
	return ""
}

func decodeJSON(t *testing.T, body string) map[string]string {
	t.Helper()
	var out map[string]string
	if err := json.Unmarshal([]byte(body), &out); err != nil {
		t.Fatalf("not JSON: %v: %s", err, body)
	}
	return out
}

func readAll(t *testing.T, resp *Response) string {
	t.Helper()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	return string(body)
}

// A blocked XHR: the interstitial is loaded and solved through the API, the
// payload posted to DataDome, the cookie kept, and the request sent again
// unchanged, all inside one Do.
func TestDatadomeSolvesAnInterstitialOnAnXHR(t *testing.T) {
	f := newDDFixture(t)
	s := f.session()
	defer s.Close()

	resp, err := s.Do(context.Background(), &Request{
		Method:  "GET",
		URL:     f.site.URL + "/api/stock",
		Headers: map[string][]string{"Accept": {"application/json"}, "Referer": {f.site.URL + "/p/1"}},
	})
	if err != nil {
		t.Fatalf("Do: %v", err)
	}
	if resp.StatusCode != 200 || readAll(t, resp) != `{"ok":true}` {
		t.Fatalf("got %d, want the page behind the block", resp.StatusCode)
	}

	starts := f.apiRec.received("/interstitial")
	if len(starts) != 1 {
		t.Fatalf("API called %d times, want 1", len(starts))
	}
	if got := starts[0].header.Get("x-api-key"); got != "key-1" {
		t.Errorf("x-api-key = %q", got)
	}
	in := decodeJSON(t, starts[0].body)
	page, _ := base64.StdEncoding.DecodeString(in["device_check_page"])
	switch {
	case in["device_check_link"] != f.interstitialLink():
		t.Errorf("device_check_link = %q, want the block's", in["device_check_link"])
	case string(page) != ddDeviceCheckPage:
		t.Errorf("device_check_page = %q", page)
	case in["ip_address"] != "203.0.113.7":
		t.Errorf("ip_address = %q, want the looked-up exit", in["ip_address"])
	case in["user_agent"] != fingerprint.Get(ddPreset).UserAgent:
		t.Errorf("user_agent = %q", in["user_agent"])
	case in["language"] != "en-US":
		t.Errorf("language = %q, want the first tag of the preset's Accept-Language", in["language"])
	}

	pages := f.geoRec.received("/interstitial/")
	if len(pages) != 2 || pages[0].method != "GET" || pages[1].method != "POST" {
		t.Fatalf("geo got %d interstitial requests, want the page GET then the POST", len(pages))
	}
	if got := pages[0].header.Get("Sec-Fetch-Dest"); got != "iframe" {
		t.Errorf("device-check page Sec-Fetch-Dest = %q, want iframe", got)
	}
	if got := pages[0].header.Get("Referer"); got != f.site.URL+"/" {
		t.Errorf("device-check page Referer = %q, want the blocked origin", got)
	}
	post := pages[1]
	if got := post.header.Get("Origin"); got != f.geo.URL {
		t.Errorf("POST Origin = %q", got)
	}
	if got := post.header.Get("Referer"); got != f.interstitialLink() {
		t.Errorf("POST Referer = %q, want the device-check link", got)
	}
	if got := post.header.Get("Cookie"); got != "" {
		t.Errorf("POST carried Cookie %q; the iframe sends none", got)
	}

	tries := f.siteRec.received("/api/stock")
	if len(tries) != 2 {
		t.Fatalf("site got %d requests, want the blocked one and its retry", len(tries))
	}
	retry := tries[1].header
	if got := retry.Get("Cookie"); got != "datadome=solved" {
		t.Errorf("retry Cookie = %q, want the solved cookie alone", got)
	}
	if got := retry.Get("Referer"); got != f.site.URL+"/p/1" {
		t.Errorf("retry Referer = %q, want the XHR's own, unchanged", got)
	}
	if got := retry.Get("Cache-Control"); got != "" {
		t.Errorf("retry Cache-Control = %q; an XHR goes out again unchanged", got)
	}
}

// A blocked navigation goes out again as the reload DataDome's script
// starts, and carries the client hints the payload was built with.
func TestDatadomeReloadsANavigationWithTheAdoptedHints(t *testing.T) {
	f := newDDFixture(t)
	s := f.session()
	defer s.Close()

	resp, err := s.Get(context.Background(), f.site.URL+"/landing")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if resp.StatusCode != 200 {
		t.Fatalf("got %d", resp.StatusCode)
	}
	tries := f.siteRec.received("/landing")
	if len(tries) != 2 {
		t.Fatalf("site got %d requests, want 2", len(tries))
	}
	first, retry := tries[0].header, tries[1].header
	if first.Get("Sec-Fetch-User") != "?1" || first.Get("Sec-Fetch-Mode") != "navigate" {
		t.Fatalf("the first request was not a navigation: %v", first)
	}
	checks := map[string]string{
		"Cache-Control":               "max-age=0",
		"Sec-Fetch-Site":              "same-origin",
		"Sec-Fetch-Mode":              "navigate",
		"Sec-Fetch-User":              "",
		"Referer":                     f.site.URL + "/landing",
		"Sec-Ch-Ua-Full-Version-List": ddFullVersionList,
		"Sec-Ch-Device-Memory":        "8",
		"Sec-Ch-Ua":                   presetHeader(ddPreset, "sec-ch-ua"),
	}
	for name, want := range checks {
		if got := retry.Get(name); got != want {
			t.Errorf("retry %s = %q, want %q", name, got, want)
		}
	}
	if retry.Get("Sec-Ch-Ua-Arch") == "" {
		t.Error("retry dropped the preset's own sec-ch-ua-arch")
	}
}

// The slider captcha: page, both images as the bytes on the wire, the API,
// the submit URL, the cookie.
func TestDatadomeSolvesACaptcha(t *testing.T) {
	f := newDDFixture(t)
	f.block = func(f *ddFixture, r *http.Request) string { return `{"url":"` + f.captchaLink() + `"}` }
	s := f.session()
	defer s.Close()

	resp, err := s.Do(context.Background(), &Request{
		Method:  "POST",
		URL:     f.site.URL + "/api/cart",
		Headers: map[string][]string{"Content-Type": {"application/json"}, "Referer": {f.site.URL + "/p/1"}},
		Body:    strings.NewReader(`{"sku":1}`),
	})
	if err != nil {
		t.Fatalf("Do: %v", err)
	}
	if resp.StatusCode != 200 {
		t.Fatalf("got %d", resp.StatusCode)
	}
	calls := f.apiRec.received("/captcha")
	if len(calls) != 1 {
		t.Fatalf("API /captcha called %d times", len(calls))
	}
	in := decodeJSON(t, calls[0].body)
	bg, _ := base64.StdEncoding.DecodeString(in["background_image"])
	frag, _ := base64.StdEncoding.DecodeString(in["fragment_image"])
	if in["type"] != "image" || in["captcha_link"] != f.captchaLink() || string(bg) != ddBackground || string(frag) != ddFragment {
		t.Errorf("API got type=%q link=%q bg=%q frag=%q", in["type"], in["captcha_link"], bg, frag)
	}
	if got := f.geoRec.received("/img/bg.jpg"); len(got) != 1 || got[0].header.Get("Sec-Fetch-Dest") != "image" {
		t.Errorf("background image fetched %d times or not as an image", len(got))
	}
	if got := f.geoRec.received("/captcha/check"); len(got) != 1 || got[0].query != "ans=1" {
		t.Errorf("submit URL not fetched as the API gave it: %+v", got)
	}
	tries := f.siteRec.received("/api/cart")
	if len(tries) != 2 || tries[1].body != `{"sku":1}` {
		t.Fatalf("site got %d tries; the retry must carry the body again", len(tries))
	}
}

// An interstitial answered with a captcha is not a failure: the request goes
// out again unchanged and its fresh block is solved.
func TestDatadomeStartsOverWhenTheInterstitialEscalates(t *testing.T) {
	f := newDDFixture(t)
	f.views = []string{"captcha"}
	s := f.session()
	defer s.Close()

	resp, err := s.Get(context.Background(), f.site.URL+"/landing")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if resp.StatusCode != 200 {
		t.Fatalf("got %d", resp.StatusCode)
	}
	if n := len(f.apiRec.received("/interstitial")); n != 2 {
		t.Errorf("API called %d times, want 2", n)
	}
	tries := f.siteRec.received("/landing")
	if len(tries) != 3 {
		t.Fatalf("site got %d requests, want 3", len(tries))
	}
	if got := tries[1].header.Get("Cache-Control"); got != "" {
		t.Errorf("the request after an escalation went out as a reload (Cache-Control %q); nothing navigated", got)
	}
}

// A hard block drops the burned cookie and goes out once more; a second one
// is the exit, so it comes back with ErrHardBlocked and the API is never paid.
func TestDatadomeHardBlockDropsTheCookieThenGivesUp(t *testing.T) {
	f := newDDFixture(t)
	f.block = func(f *ddFixture, r *http.Request) string {
		return `{"url":"` + f.geo.URL + `/captcha/?initialCid=a&hash=b&cid=c&t=bv&dm=cd"}`
	}
	s := f.session()
	defer s.Close()

	resp, err := s.Get(context.Background(), f.site.URL+"/landing")
	if !errors.Is(err, datadome.ErrHardBlocked) {
		t.Fatalf("err = %v, want ErrHardBlocked", err)
	}
	if resp == nil || resp.StatusCode != 403 {
		t.Fatalf("the block must come back with the error")
	}
	tries := f.siteRec.received("/landing")
	if len(tries) != 2 {
		t.Fatalf("site got %d requests, want 2", len(tries))
	}
	if got := tries[1].header.Get("Cookie"); got != "" {
		t.Errorf("the second try carried Cookie %q; the burned cookie must be gone", got)
	}
	if n := len(f.apiRec.requests); n != 0 {
		t.Errorf("API called %d times for a hard block", n)
	}
}

// A request blocked after every solve it may answer gives up.
func TestDatadomeGivesUpAfterMaxSolves(t *testing.T) {
	f := newDDFixture(t)
	f.views = []string{"captcha", "captcha", "captcha"}
	s := NewSession(ddPreset, WithDatadomeConfig(datadome.Config{
		APIKey: "key-1", ServiceURL: f.api.URL, IPLookupURL: f.site.URL + "/ip", MaxSolves: 2,
	}))
	defer s.Close()

	resp, err := s.Get(context.Background(), f.site.URL+"/landing")
	if !errors.Is(err, datadome.ErrStillBlocked) {
		t.Fatalf("err = %v, want ErrStillBlocked", err)
	}
	if resp == nil || resp.StatusCode != 403 {
		t.Fatal("the block must come back with the error")
	}
	if n := len(f.apiRec.received("/interstitial")); n != 2 {
		t.Errorf("API called %d times, want MaxSolves (2)", n)
	}
}

// A 403 that is not DataDome's goes back as it is, body intact.
func TestDatadomeLeavesAnOrdinary403Alone(t *testing.T) {
	f := newDDFixture(t)
	f.block = func(*ddFixture, *http.Request) string { return "" }
	s := f.session()
	defer s.Close()

	resp, err := s.Get(context.Background(), f.site.URL+"/landing")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if resp.StatusCode != 403 || readAll(t, resp) != "<html>Forbidden</html>" {
		t.Fatalf("got %d, want the 403 with its body", resp.StatusCode)
	}
	if len(f.apiRec.requests) != 0 || len(f.siteRec.received("/landing")) != 1 {
		t.Error("an ordinary 403 was treated as a block")
	}
}

// The API's refusal comes back as an *APIError, with the block.
func TestDatadomeAPIRefusal(t *testing.T) {
	f := newDDFixture(t)
	f.apiRefusal = "site not approved"
	s := f.session()
	defer s.Close()

	resp, err := s.Get(context.Background(), f.site.URL+"/landing")
	var apiErr *datadome.APIError
	if !errors.As(err, &apiErr) || apiErr.Message != "site not approved" {
		t.Fatalf("err = %v, want the API's refusal", err)
	}
	if resp == nil || resp.StatusCode != 403 {
		t.Fatal("the block must come back with the error")
	}
}

// Requests blocked while a solve of their host runs wait for it rather than
// paying for their own.
func TestDatadomeConcurrentBlocksShareOneSolve(t *testing.T) {
	f := newDDFixture(t)
	f.apiDelay = 300 * time.Millisecond
	s := f.session()
	defer s.Close()

	var wg sync.WaitGroup
	errs := make(chan error, 3)
	for i := 0; i < 3; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			resp, err := s.Do(context.Background(), &Request{
				Method:  "GET",
				URL:     f.site.URL + "/api/stock",
				Headers: map[string][]string{"Accept": {"application/json"}, "Referer": {f.site.URL + "/"}},
			})
			if err == nil && resp.StatusCode != 200 {
				err = errors.New(http.StatusText(resp.StatusCode))
			}
			errs <- err
		}()
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Errorf("request: %v", err)
		}
	}
	if n := len(f.apiRec.received("/interstitial")); n != 1 {
		t.Errorf("API called %d times, want one shared solve", n)
	}
}

// A request that lists its headers itself is rewritten in place: Cache-Control
// after Connection, the Referer after Sec-Fetch-Dest, no Sec-Fetch-User.
func TestReloadHeadersKeepTheListedOrder(t *testing.T) {
	in := []fingerprint.HeaderPair{
		{Key: "Connection", Value: "keep-alive"},
		{Key: "sec-ch-ua", Value: "x"},
		{Key: "Upgrade-Insecure-Requests", Value: "1"},
		{Key: "Sec-Fetch-Site", Value: "none"},
		{Key: "Sec-Fetch-Mode", Value: "navigate"},
		{Key: "Sec-Fetch-User", Value: "?1"},
		{Key: "Sec-Fetch-Dest", Value: "document"},
		{Key: "Accept-Encoding", Value: "gzip"},
		{Key: "Cookie", Value: ""},
	}
	got := reloadHeaders(in, "https://shop.example/p")
	want := []fingerprint.HeaderPair{
		{Key: "Connection", Value: "keep-alive"},
		{Key: "Cache-Control", Value: "max-age=0"},
		{Key: "sec-ch-ua", Value: "x"},
		{Key: "Upgrade-Insecure-Requests", Value: "1"},
		{Key: "Sec-Fetch-Site", Value: "same-origin"},
		{Key: "Sec-Fetch-Mode", Value: "navigate"},
		{Key: "Sec-Fetch-Dest", Value: "document"},
		{Key: "Referer", Value: "https://shop.example/p"},
		{Key: "Accept-Encoding", Value: "gzip"},
		{Key: "Cookie", Value: ""},
	}
	if len(got) != len(want) {
		t.Fatalf("got %v\nwant %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("slot %d: got %v, want %v\nfull: %v", i, got[i], want[i], got)
		}
	}

	// An HTTP/2 list (lowercase, no Connection) gets a lowercase
	// cache-control in front.
	h2 := reloadHeaders([]fingerprint.HeaderPair{{Key: "sec-fetch-dest", Value: "document"}}, "u")
	if h2[0] != (fingerprint.HeaderPair{Key: "cache-control", Value: "max-age=0"}) || h2[2].Key != "referer" {
		t.Errorf("h2 reload = %v", h2)
	}
}

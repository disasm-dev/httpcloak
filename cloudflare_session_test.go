package httpcloak

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/sardanioss/httpcloak/cloudflare"
	"github.com/sardanioss/httpcloak/fingerprint"
)

// These run a real Session against two local servers: a site that serves
// Cloudflare's challenge until the jar carries cf_clearance=ok, and a fake
// solve service that answers with a scripted list of steps. What is asserted is
// what each server received, since that is what the real ones see.

const challengeHTML = `<!DOCTYPE html><html><head><title>Just a moment...</title></head><body>` +
	`<script>(function(){window._cf_chl_opt={cvId:'3',cZone:'site',cType:'managed'};}());</script></body></html>`

type siteRequest struct {
	method string
	path   string
	header http.Header
	body   string
}

type fakeSite struct {
	url string

	// hold, when set, keeps that many challenge responses back until they
	// have all been asked for, so that many requests are challenged at once.
	hold    int
	arrived chan struct{}

	mu       sync.Mutex
	requests []siteRequest
	held     int
}

func newFakeSite(t *testing.T) *fakeSite {
	t.Helper()
	site := &fakeSite{arrived: make(chan struct{})}
	srv := httptest.NewServer(http.HandlerFunc(site.serve))
	t.Cleanup(srv.Close)
	site.url = srv.URL
	return site
}

func (site *fakeSite) serve(w http.ResponseWriter, r *http.Request) {
	body, _ := io.ReadAll(r.Body)
	site.mu.Lock()
	site.requests = append(site.requests, siteRequest{r.Method, r.URL.Path, r.Header.Clone(), string(body)})
	site.mu.Unlock()

	switch r.URL.Path {
	case "/", "/submit":
		if c, err := r.Cookie("cf_clearance"); err == nil && c.Value == "ok" {
			io.WriteString(w, "behind the challenge "+string(body))
			return
		}
		site.waitForHeld()
		http.SetCookie(w, &http.Cookie{Name: "cf_chl_rc_m", Value: "1", Path: "/"})
		w.Header().Set("Server", "cloudflare")
		w.Header().Set("Cf-Mitigated", "challenge")
		w.WriteHeader(http.StatusForbidden)
		io.WriteString(w, challengeHTML)
	case "/orchestrate.js":
		io.WriteString(w, "orchestrate")
	case "/form":
		if string(body) == "md=answer" {
			http.SetCookie(w, &http.Cookie{Name: "cf_clearance", Value: "ok", Path: "/"})
		}
		http.Redirect(w, r, "/", http.StatusFound)
	case "/slow":
		select {
		case <-r.Context().Done():
		case <-time.After(5 * time.Second):
		}
	case "/blocked":
		w.Header().Set("Server", "cloudflare")
		w.WriteHeader(http.StatusForbidden)
		io.WriteString(w, "Sorry, you have been blocked")
	default:
		http.NotFound(w, r)
	}
}

func (site *fakeSite) waitForHeld() {
	site.mu.Lock()
	if site.hold == 0 {
		site.mu.Unlock()
		return
	}
	site.held++
	if site.held == site.hold {
		close(site.arrived)
	}
	site.mu.Unlock()
	<-site.arrived
}

func (site *fakeSite) received(path string) []siteRequest {
	site.mu.Lock()
	defer site.mu.Unlock()
	var out []siteRequest
	for _, r := range site.requests {
		if r.path == path {
			out = append(out, r)
		}
	}
	return out
}

type solveStart struct {
	key       string
	URL       string `json:"url"`
	HTML      string `json:"html"`
	UserAgent string `json:"user_agent"`
}

// fakeSolveService answers /solves with its first step and each /next with
// the one after, then ends the solve, cleared or not as it is told. refusal,
// when set, is how it answers /solves instead.
type fakeSolveService struct {
	url     string
	steps   []cloudflare.Step
	cleared bool
	refusal func(w http.ResponseWriter)

	mu      sync.Mutex
	starts  []solveStart
	replies []cloudflare.Reply
	raw     []string
	turn    int
}

func newFakeSolveService(t *testing.T, cleared bool, steps ...cloudflare.Step) *fakeSolveService {
	t.Helper()
	svc := &fakeSolveService{steps: steps, cleared: cleared}
	srv := httptest.NewServer(http.HandlerFunc(svc.serve))
	t.Cleanup(srv.Close)
	svc.url = srv.URL
	return svc
}

func (svc *fakeSolveService) serve(w http.ResponseWriter, r *http.Request) {
	body, _ := io.ReadAll(r.Body)
	svc.mu.Lock()
	defer svc.mu.Unlock()
	switch {
	case r.Method == http.MethodPost && r.URL.Path == "/solves":
		if svc.refusal != nil {
			svc.refusal(w)
			return
		}
		start := solveStart{key: r.Header.Get("x-api-key")}
		json.Unmarshal(body, &start)
		svc.starts = append(svc.starts, start)
		svc.turn = 0
		json.NewEncoder(w).Encode(map[string]any{"id": "7d1c", "request": svc.steps[0]})
	case r.Method == http.MethodPost && r.URL.Path == "/solves/7d1c/next":
		var reply cloudflare.Reply
		json.Unmarshal(body, &reply)
		svc.replies = append(svc.replies, reply)
		svc.raw = append(svc.raw, string(body))
		svc.turn++
		if svc.turn < len(svc.steps) {
			json.NewEncoder(w).Encode(map[string]any{"request": svc.steps[svc.turn]})
			return
		}
		json.NewEncoder(w).Encode(map[string]any{"done": true, "cleared": svc.cleared})
	default:
		w.WriteHeader(http.StatusNotFound)
	}
}

func (svc *fakeSolveService) startCount() int {
	starts, _, _ := svc.record()
	return len(starts)
}

// record is what the service was sent: each solve's start, each reply as read
// and as it went on the wire.
func (svc *fakeSolveService) record() ([]solveStart, []cloudflare.Reply, []string) {
	svc.mu.Lock()
	defer svc.mu.Unlock()
	return append([]solveStart(nil), svc.starts...), append([]cloudflare.Reply(nil), svc.replies...), append([]string(nil), svc.raw...)
}

// The two steps a scripted solve takes: the orchestrate script, then the
// form, whose answer sets cf_clearance when it carries md=answer.
func scriptStep(site string) cloudflare.Step {
	return cloudflare.Step{
		Method:  "GET",
		URL:     site + "/orchestrate.js",
		Headers: [][]string{{"user-agent", "solve-ua"}, {"accept", "*/*"}, {"x-step", "orchestrate"}, {"cookie", ""}},
		WaitMs:  30,
	}
}

func formStep(site, body string) cloudflare.Step {
	return cloudflare.Step{
		Method: "POST",
		URL:    site + "/form",
		Headers: [][]string{{"content-length", strconv.Itoa(len(body))}, {"content-type", "application/x-www-form-urlencoded"},
			{"user-agent", "solve-ua"}, {"cookie", ""}},
		Body: &body,
	}
}

func cloudflareSession(svc *fakeSolveService) *Session {
	return NewSession("chrome-latest-windows", WithCloudflareConfig(cloudflare.Config{APIKey: "key-1", ServiceURL: svc.url}))
}

func TestCloudflareClearsTheChallengeAndSendsTheRequestAgain(t *testing.T) {
	site := newFakeSite(t)
	svc := newFakeSolveService(t, true, scriptStep(site.url), formStep(site.url, "md=answer"))
	s := cloudflareSession(svc)
	defer s.Close()

	resp, err := s.Get(context.Background(), site.url+"/")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	text, _ := resp.Text()
	if resp.StatusCode != 200 || !strings.HasPrefix(text, "behind the challenge") {
		t.Fatalf("got %d %q, want the page behind the challenge", resp.StatusCode, text)
	}

	starts, replies, _ := svc.record()
	if len(starts) != 1 {
		t.Fatalf("service started %d solves, want 1", len(starts))
	}
	start := starts[0]
	if start.key != "key-1" || start.URL != site.url+"/" || start.HTML != challengeHTML {
		t.Errorf("solve started with key %q, url %q, html %q", start.key, start.URL, start.HTML)
	}
	if want := fingerprint.Get("chrome-latest-windows").UserAgent; start.UserAgent != want {
		t.Errorf("solve started as %q, want the session's own %q", start.UserAgent, want)
	}

	if len(replies) != 2 {
		t.Fatalf("service was handed %d replies, want 2", len(replies))
	}
	if r := replies[0]; r.Status != 200 || string(r.Body) != "orchestrate" {
		t.Errorf("orchestrate reply %d %q", r.Status, r.Body)
	}
	// The form's 302 goes back to the service as it came, not followed.
	if r := replies[1]; r.Status != 302 || r.Headers["location"] != "/" {
		t.Errorf("form reply %d, location %q; want the 302 itself", r.Status, r.Headers["location"])
	}

	script := site.received("/orchestrate.js")
	if len(script) != 1 {
		t.Fatalf("site got %d orchestrate requests", len(script))
	}
	h := script[0].header
	if h.Get("X-Step") != "orchestrate" || h.Get("User-Agent") != "solve-ua" {
		t.Errorf("orchestrate went out without the step's own headers: %v", h)
	}
	if h.Get("Sec-Fetch-Mode") != "" || h.Get("Sec-Ch-Ua") != "" {
		t.Errorf("the preset's headers were added to an exact step: %v", h)
	}
	if !strings.Contains(h.Get("Cookie"), "cf_chl_rc_m=1") {
		t.Errorf("the empty cookie slot was not filled from the jar: %q", h.Get("Cookie"))
	}

	form := site.received("/form")
	if len(form) != 1 || form[0].body != "md=answer" {
		t.Fatalf("form requests %+v", form)
	}

	pages := site.received("/")
	if len(pages) != 2 || !strings.Contains(pages[1].header.Get("Cookie"), "cf_clearance=ok") {
		t.Errorf("the request did not go out again with cf_clearance: %+v", pages)
	}
}

func TestCloudflareSendsAPostAgainWithItsBody(t *testing.T) {
	site := newFakeSite(t)
	svc := newFakeSolveService(t, true, scriptStep(site.url), formStep(site.url, "md=answer"))
	s := cloudflareSession(svc)
	defer s.Close()

	resp, err := s.Do(context.Background(), &Request{
		Method:  "POST",
		URL:     site.url + "/submit",
		Headers: map[string][]string{"Content-Type": {"application/x-www-form-urlencoded"}},
		Body:    strings.NewReader("x=1"),
	})
	if err != nil {
		t.Fatalf("Do: %v", err)
	}
	if text, _ := resp.Text(); text != "behind the challenge x=1" {
		t.Fatalf("got %q", text)
	}
	submits := site.received("/submit")
	if len(submits) != 2 || submits[0].body != "x=1" || submits[1].body != "x=1" {
		t.Fatalf("submits %+v, want the body on both", submits)
	}
}

func TestCloudflareChallengeTheServiceCannotClear(t *testing.T) {
	site := newFakeSite(t)
	svc := newFakeSolveService(t, false, scriptStep(site.url), formStep(site.url, "md=wrong"))
	s := cloudflareSession(svc)
	defer s.Close()

	resp, err := s.Get(context.Background(), site.url+"/")
	if !errors.Is(err, cloudflare.ErrNotCleared) {
		t.Fatalf("err %v, want ErrNotCleared", err)
	}
	if resp == nil || resp.StatusCode != 403 {
		t.Fatalf("want the challenge response alongside the error, got %+v", resp)
	}
	if text, _ := resp.Text(); text != challengeHTML {
		t.Errorf("the challenge body was not left readable: %q", text)
	}
}

func TestCloudflareClearedButChallengedAgain(t *testing.T) {
	site := newFakeSite(t)
	// The service says cleared, but the form carried the wrong answer, so the
	// site never set cf_clearance: every solve is followed by a challenge.
	svc := newFakeSolveService(t, true, scriptStep(site.url), formStep(site.url, "md=wrong"))
	s := cloudflareSession(svc)
	defer s.Close()

	resp, err := s.Get(context.Background(), site.url+"/")
	if !errors.Is(err, cloudflare.ErrStillChallenged) {
		t.Fatalf("err %v, want ErrStillChallenged", err)
	}
	if resp == nil || resp.StatusCode != 403 {
		t.Fatalf("want the last challenge response, got %+v", resp)
	}
	if svc.startCount() != 2 {
		t.Errorf("service started %d solves, want 2 (MaxSolves' default)", svc.startCount())
	}
}

func TestCloudflareUserAgentTheServiceHasNoDeviceFor(t *testing.T) {
	site := newFakeSite(t)
	svc := newFakeSolveService(t, true, scriptStep(site.url))
	svc.refusal = func(w http.ResponseWriter) {
		w.WriteHeader(http.StatusBadRequest)
		io.WriteString(w, `{"error":"No device sends this User-Agent","user_agents":["Chrome/155 on Windows"]}`)
	}
	s := cloudflareSession(svc)
	defer s.Close()

	_, err := s.Get(context.Background(), site.url+"/")
	var refused *cloudflare.APIError
	if !errors.As(err, &refused) {
		t.Fatalf("err %v, want an *APIError", err)
	}
	if refused.StatusCode != 400 || len(refused.UserAgents) != 1 || refused.UserAgents[0] != "Chrome/155 on Windows" {
		t.Errorf("refusal %+v", refused)
	}
	if !strings.HasPrefix(err.Error(), "cloudflare: ") || !strings.Contains(err.Error(), "Chrome/155 on Windows") {
		t.Errorf("error %q should say it is Cloudflare's and name the User-Agents to use", err)
	}
}

func TestCloudflareStepGivenUpAtItsTimeoutAnswersStatusZero(t *testing.T) {
	site := newFakeSite(t)
	slow := cloudflare.Step{Method: "GET", URL: site.url + "/slow", Headers: [][]string{{"accept", "*/*"}}, TimeoutMs: 100}
	svc := newFakeSolveService(t, true, slow, formStep(site.url, "md=answer"))
	s := cloudflareSession(svc)
	defer s.Close()

	resp, err := s.Get(context.Background(), site.url+"/")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	resp.Close()
	_, replies, raw := svc.record()
	if len(replies) < 1 || replies[0].Status != 0 {
		t.Fatalf("replies %+v, want status 0 for the step given up", replies)
	}
	// The service reads every field: an empty body has to go as "", not null.
	if !strings.Contains(raw[0], `"body":""`) || !strings.Contains(raw[0], `"headers":{}`) {
		t.Errorf("status-0 reply went as %s", raw[0])
	}
}

func TestCloudflareRequestsChallengedTogetherShareOneSolve(t *testing.T) {
	const requests = 4
	site := newFakeSite(t)
	site.hold = requests
	step := scriptStep(site.url)
	step.WaitMs = 150
	svc := newFakeSolveService(t, true, step, formStep(site.url, "md=answer"))
	s := cloudflareSession(svc)
	defer s.Close()

	var wg sync.WaitGroup
	errs := make(chan error, requests)
	for range requests {
		wg.Add(1)
		go func() {
			defer wg.Done()
			resp, err := s.Get(context.Background(), site.url+"/")
			if err == nil && resp.StatusCode != 200 {
				err = errors.New(resp.Protocol + " " + http.StatusText(resp.StatusCode))
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
	if n := svc.startCount(); n != 1 {
		t.Errorf("service started %d solves for %d requests challenged together, want 1", n, requests)
	}
}

func TestCloudflareLeavesABlockPageAlone(t *testing.T) {
	site := newFakeSite(t)
	svc := newFakeSolveService(t, true, scriptStep(site.url))
	s := cloudflareSession(svc)
	defer s.Close()

	resp, err := s.Get(context.Background(), site.url+"/blocked")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if text, _ := resp.Text(); resp.StatusCode != 403 || text != "Sorry, you have been blocked" {
		t.Errorf("got %d %q, want the block page as it came", resp.StatusCode, text)
	}
	if svc.startCount() != 0 {
		t.Errorf("a block page started a solve")
	}
}

func TestCloudflareForksClearChallengesToo(t *testing.T) {
	site := newFakeSite(t)
	svc := newFakeSolveService(t, true, scriptStep(site.url), formStep(site.url, "md=answer"))
	s := cloudflareSession(svc)
	defer s.Close()

	forks := s.Fork(1)
	if len(forks) != 1 {
		t.Fatalf("Fork gave %d sessions", len(forks))
	}
	defer forks[0].Close()
	resp, err := forks[0].Get(context.Background(), site.url+"/")
	if err != nil || resp.StatusCode != 200 {
		t.Fatalf("fork: %v %+v", err, resp)
	}
}

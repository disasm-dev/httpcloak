package transport

import (
	"context"
	"io"
	stdhttp "net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"
)

// When an auto-mode request failed on HTTP/2 (or the H3/H2 race) for any
// reason other than an ALPN downgrade, doAuto sent it again on a fresh
// HTTP/1.1 connection. For a POST whose stream was reset after the server had
// read it, that sent it twice, and a body given as a reader went out empty the
// second time because the first attempt had consumed it; the caller got the
// second answer and no sign of either problem. Chrome fails such a request.
// The fallback now runs only when nothing was sent, or when the request is
// idempotent and its body can be sent again.

// resetOnH2Server reads each request, records it, and resets the stream on
// HTTP/2 after the body has arrived. HTTP/1.1 requests get a 200.
func resetOnH2Server(t *testing.T) (*httptest.Server, func() []string) {
	t.Helper()
	var mu sync.Mutex
	var seen []string
	srv := httptest.NewUnstartedServer(stdhttp.HandlerFunc(func(w stdhttp.ResponseWriter, r *stdhttp.Request) {
		b, _ := io.ReadAll(r.Body)
		mu.Lock()
		seen = append(seen, r.Proto+" "+r.Method+" "+string(b))
		mu.Unlock()
		if r.ProtoMajor == 2 {
			panic(stdhttp.ErrAbortHandler)
		}
		w.Write([]byte("ok"))
	}))
	srv.EnableHTTP2 = true
	srv.StartTLS()
	t.Cleanup(srv.Close)
	return srv, func() []string {
		mu.Lock()
		defer mu.Unlock()
		return append([]string(nil), seen...)
	}
}

func doReq(tr *Transport, req *Request) error {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	_, err := tr.Do(ctx, req)
	return err
}

func TestAutoDoesNotResendAPostThatWasSent(t *testing.T) {
	for _, preset := range []string{"firefox-148", "chrome-146"} {
		for _, body := range []string{"reader", "bytes"} {
			t.Run(preset+"/"+body, func(t *testing.T) {
				tr := autoTransport(t, preset)
				srv, seen := resetOnH2Server(t)
				req := &Request{Method: "POST", URL: srv.URL + "/pay"}
				if body == "reader" {
					req.BodyReader = strings.NewReader("charge=100")
				} else {
					req.Body = []byte("charge=100")
				}

				if err := doReq(tr, req); err == nil {
					t.Fatal("a POST whose HTTP/2 stream was reset after it was sent should fail")
				}
				if got := seen(); len(got) != 1 || got[0] != "HTTP/2.0 POST charge=100" {
					t.Fatalf("server saw %q, want the POST once, over HTTP/2", got)
				}
			})
		}
	}
}

// A reset stream is the host's answer even for an idempotent request: the host
// spoke HTTP/2, so Chrome fails the request rather than resend it over
// HTTP/1.1 (see isHTTP2StreamError).
func TestAutoDoesNotResendAGetAfterAStreamReset(t *testing.T) {
	for _, preset := range []string{"firefox-148", "chrome-146"} {
		t.Run(preset, func(t *testing.T) {
			tr := autoTransport(t, preset)
			srv, seen := resetOnH2Server(t)
			if err := doReq(tr, &Request{Method: "GET", URL: srv.URL}); err == nil {
				t.Fatal("a GET whose HTTP/2 stream was reset should fail")
			}
			if got := seen(); len(got) != 1 || got[0] != "HTTP/2.0 GET " {
				t.Fatalf("server saw %q, want the GET once, over HTTP/2", got)
			}
		})
	}
}

// When no connection could be had, nothing was sent, so even a POST may try
// HTTP/1.1. The server drops every connection, so that attempt fails too, but
// it is made.
func TestAutoFallsBackForAPostThatWasNeverSent(t *testing.T) {
	tr := autoTransport(t, "firefox-148")
	srv := httptest.NewUnstartedServer(stdhttp.NotFoundHandler())
	l := &countingListener{Listener: srv.Listener, dropAll: true}
	srv.Listener = l
	srv.EnableHTTP2 = true
	srv.StartTLS()
	t.Cleanup(srv.Close)

	if err := doReq(tr, &Request{Method: "POST", URL: srv.URL, BodyReader: strings.NewReader("x")}); err == nil {
		t.Fatal("request against a server that drops every connection should fail")
	}
	if got := l.accepted.Load(); got != 2 {
		t.Errorf("server saw %d connection attempts, want 2 (H2 dial, then the HTTP/1.1 fallback)", got)
	}
}

// A host cached as HTTP/3 whose QUIC dial now fails never had the request on
// HTTP/3, so a POST still goes out over HTTP/2, once. Before, any HTTP/3
// failure counted as possibly sent, and the host stayed cached as HTTP/3, so
// every later POST stream to it failed.
func TestAutoStreamPostFallsBackWhenHTTP3NeverConnected(t *testing.T) {
	tr := autoTransport(t, "chrome-155")
	var mu sync.Mutex
	var seen []string
	srv := httptest.NewUnstartedServer(stdhttp.HandlerFunc(func(w stdhttp.ResponseWriter, r *stdhttp.Request) {
		b, _ := io.ReadAll(r.Body)
		mu.Lock()
		seen = append(seen, r.Proto+" "+r.Method+" "+string(b))
		mu.Unlock()
		w.Write([]byte("ok"))
	}))
	srv.EnableHTTP2 = true
	srv.StartTLS() // TCP only: nothing answers QUIC on this port
	t.Cleanup(srv.Close)
	tr.cacheProtocol(extractHost(srv.URL), ProtocolHTTP3)

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	resp, err := tr.DoStream(ctx, &Request{Method: "POST", URL: srv.URL + "/pay", Body: []byte("charge=100"), Timeout: 3 * time.Second})
	if err != nil {
		t.Fatalf("POST should have gone out over HTTP/2 after HTTP/3 never connected: %v", err)
	}
	resp.Close()
	mu.Lock()
	defer mu.Unlock()
	if len(seen) != 1 || seen[0] != "HTTP/2.0 POST charge=100" {
		t.Fatalf("server saw %q, want the POST once, over HTTP/2", seen)
	}
}

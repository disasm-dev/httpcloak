package transport

import (
	"bytes"
	"context"
	"encoding/binary"
	"io"
	"testing"
	"time"

	http "github.com/sardanioss/http"
	"github.com/sardanioss/httpcloak/dns"
	"github.com/sardanioss/httpcloak/fingerprint"
)

// frameWriter is the raw frame writer AfterResponse hands a test.
type frameWriter = func(typ, flags byte, streamID uint32, payload []byte)

func h2Get(t *testing.T, tr *HTTP2Transport, url string) {
	t.Helper()
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		t.Fatal(err)
	}
	resp, err := tr.RoundTrip(req)
	if err != nil {
		t.Fatalf("request: %v", err)
	}
	io.Copy(io.Discard, resp.Body)
	resp.Body.Close()
}

// connEnded waits up to within for the server to have seen n connections end.
func connEnded(s *h2Server, n int32, within time.Duration) bool {
	deadline := time.Now().Add(within)
	for s.ended.Load() < n && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	return s.ended.Load() >= n
}

func goAwayFields(t *testing.T, f h2Frame) (last, code uint32, debug string) {
	t.Helper()
	if len(f.Payload) < 8 {
		t.Fatalf("GOAWAY payload of %d bytes", len(f.Payload))
	}
	return binary.BigEndian.Uint32(f.Payload) & 0x7fffffff, binary.BigEndian.Uint32(f.Payload[4:]), string(f.Payload[8:])
}

// A PING ACK the client never asked for. Chromium treats it as a protocol
// error: GOAWAY(0, PROTOCOL_ERROR, "Unexpected PING ACK.") and the connection
// closes. Firefox ignores it, so that profile keeps the connection.
func TestH2StrayPingAckFollowsTheProfile(t *testing.T) {
	for _, tc := range []struct {
		preset    string
		wantClose bool
	}{
		{"chrome-latest", true},
		{"firefox-133", false},
	} {
		t.Run(tc.preset, func(t *testing.T) {
			s := startH2Server(t, h2Config{AfterResponse: func(w frameWriter, _ uint32) {
				w(frPing, flAck, 0, []byte("cp-probe"))
			}})
			tr := NewHTTP2Transport(fingerprint.Get(tc.preset), dns.NewCache())
			tr.SetInsecureSkipVerify(true)
			defer tr.Close()

			h2Get(t, tr, s.url("/"))
			closed := connEnded(s, 1, 500*time.Millisecond)
			goaways := s.only(frGoAway)
			if !tc.wantClose {
				if closed || len(goaways) != 0 {
					t.Fatalf("closed=%v goaways=%d, want the stray ACK ignored\n%s", closed, len(goaways), s.dump())
				}
				return
			}
			if !closed {
				t.Fatalf("connection still open after a stray PING ACK\n%s", s.dump())
			}
			if len(goaways) != 1 {
				t.Fatalf("%d GOAWAY frames, want 1\n%s", len(goaways), s.dump())
			}
			last, code, debug := goAwayFields(t, goaways[0])
			if last != 0 || code != 1 || debug != "Unexpected PING ACK." {
				t.Errorf("GOAWAY last=%d code=%d debug=%q, want 0, 1, %q", last, code, debug, "Unexpected PING ACK.")
			}
		})
	}
}

// PUSH_PROMISE after SETTINGS_ENABLE_PUSH=0 is a connection error for every
// profile. The GOAWAY has to reach the peer, which it did not while it sat
// unflushed; Chromium's also carries "PUSH_PROMISE received".
func TestH2PushPromiseGetsAGoAway(t *testing.T) {
	for _, tc := range []struct {
		preset    string
		wantDebug string
	}{
		{"chrome-latest", "PUSH_PROMISE received"},
		{"firefox-133", ""},
	} {
		t.Run(tc.preset, func(t *testing.T) {
			s := startH2Server(t, h2Config{AfterResponse: func(w frameWriter, streamID uint32) {
				// Promised stream 2, header block ":method: GET" (static 2).
				w(frPushPromise, flEndHeaders, streamID, []byte{0, 0, 0, 2, 0x82})
			}})
			tr := NewHTTP2Transport(fingerprint.Get(tc.preset), dns.NewCache())
			tr.SetInsecureSkipVerify(true)
			defer tr.Close()

			h2Get(t, tr, s.url("/"))
			if !connEnded(s, 1, 2*time.Second) {
				t.Fatalf("connection still open after PUSH_PROMISE\n%s", s.dump())
			}
			goaways := s.only(frGoAway)
			if len(goaways) != 1 {
				t.Fatalf("%d GOAWAY frames, want 1\n%s", len(goaways), s.dump())
			}
			last, code, debug := goAwayFields(t, goaways[0])
			if last != 0 || code != 1 || debug != tc.wantDebug {
				t.Errorf("GOAWAY last=%d code=%d debug=%q, want 0, 1, %q", last, code, debug, tc.wantDebug)
			}
		})
	}
}

// A GOAWAY that leaves nothing to finish closes the connection there and then,
// as Chromium's MaybeFinishGoingAway does, and without a GOAWAY of the
// client's own. The next request goes out on a new connection.
func TestH2IdleGoAwayClosesTheConnection(t *testing.T) {
	s := startH2Server(t, h2Config{AfterResponse: func(w frameWriter, streamID uint32) {
		// Let the client finish with the stream first, so the GOAWAY lands on
		// an idle connection rather than racing the stream's own cleanup.
		time.Sleep(150 * time.Millisecond)
		var p [8]byte
		binary.BigEndian.PutUint32(p[:], streamID)
		w(frGoAway, 0, 0, p[:])
	}})
	tr := newChromeH2(t)

	h2Get(t, tr, s.url("/"))
	sent := time.Now()
	if !connEnded(s, 1, time.Second) {
		t.Fatalf("connection still open a second after an idle GOAWAY\n%s", s.dump())
	}
	if d := time.Since(sent); d > 600*time.Millisecond {
		t.Errorf("closed %v after the response, want within milliseconds of the GOAWAY", d)
	}
	if n := len(s.only(frGoAway)); n != 0 {
		t.Errorf("client sent %d GOAWAY frames on a graceful close, want none", n)
	}

	h2Get(t, tr, s.url("/"))
	if n := s.connCount(); n != 2 {
		t.Errorf("%d connections, want the second request on a new one", n)
	}
}

// With the whole Content-Length body in and END_STREAM held back, the stream is
// left to end on its own instead of being reset, as Chromium does: its
// SpdyHttpStream only calls a body complete once the stream has closed.
func TestH2LeavesACompleteBodyToEndOnItsOwn(t *testing.T) {
	release := make(chan struct{})
	body := bytes.Repeat([]byte("x"), 5000)
	s := startH2Server(t, h2Config{
		Body:              body,
		SendContentLength: true,
		HoldEndStream:     release,
		OnRequest: func(uint32, int) {
			time.AfterFunc(300*time.Millisecond, func() { close(release) })
		},
	})

	tr := NewTransport("chrome-latest")
	tr.SetInsecureSkipVerify(true)
	tr.SetDisableECH(true)
	defer tr.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	resp, err := tr.Do(ctx, &Request{Method: "GET", URL: s.url("/")})
	if err != nil {
		t.Fatalf("request: %v", err)
	}
	if resp.Protocol != "h2" {
		t.Fatalf("served over %q, want h2", resp.Protocol)
	}
	got, err := resp.Bytes()
	if err != nil || len(got) != len(body) {
		t.Fatalf("body %d bytes, err %v; want %d", len(got), err, len(body))
	}
	// Past the server's END_STREAM, so a reset at any point would be seen.
	time.Sleep(500 * time.Millisecond)
	if rst := s.only(frRSTStream); len(rst) != 0 {
		t.Fatalf("client reset a stream whose body was complete\n%s", s.dump())
	}
}

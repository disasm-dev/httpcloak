package transport

import (
	"encoding/binary"
	"io"
	"strings"
	"testing"
	"time"

	http "github.com/sardanioss/http"
	"github.com/sardanioss/httpcloak/dns"
	"github.com/sardanioss/httpcloak/fingerprint"
)

// headersPriority reads the priority fields off a recorded HEADERS frame.
func headersPriority(t *testing.T, f h2Frame) (dep uint32, exclusive bool, weight uint8) {
	t.Helper()
	if f.Type != frHeaders || f.Flags&flPriority == 0 {
		t.Fatalf("stream %d: HEADERS without priority fields", f.StreamID)
	}
	p := f.Payload
	if f.Flags&flPadded != 0 {
		p = p[1:]
	}
	v := binary.BigEndian.Uint32(p)
	return v & 0x7fffffff, v>>31 == 1, p[4]
}

func newChromeH2(t *testing.T) *HTTP2Transport {
	t.Helper()
	preset := fingerprint.Get("chrome-latest")
	if preset == nil {
		t.Fatal("chrome-latest preset missing")
	}
	tr := NewHTTP2Transport(preset, dns.NewCache())
	tr.SetInsecureSkipVerify(true)
	t.Cleanup(func() { tr.Close() })
	return tr
}

// Chromium's Http2PriorityDependencies: a stream that opens while others are
// running depends on the newest open stream at the same or a higher priority,
// exclusively. Only a stream with nothing open above it depends on stream 0.
// Every stream here stays open, because the server holds END_STREAM.
func TestH2ConcurrentStreamsChainLikeChrome(t *testing.T) {
	hold := make(chan struct{})
	s := startH2Server(t, h2Config{HoldEndStream: hold})
	tr := newChromeH2(t)

	var open []*http.Response
	send := func(dest string) {
		t.Helper()
		req, err := http.NewRequest("GET", s.url("/"+dest), nil)
		if err != nil {
			t.Fatal(err)
		}
		req.Header.Set("Sec-Fetch-Dest", dest)
		resp, err := tr.RoundTrip(req)
		if err != nil {
			t.Fatalf("%s: %v", dest, err)
		}
		open = append(open, resp)
	}
	closeAll := func() {
		for _, resp := range open {
			io.Copy(io.Discard, resp.Body)
			resp.Body.Close()
		}
		open = nil
	}

	// document and style are band 0 (weight 256), script band 1 (220),
	// image band 2 (183).
	send("document") // 1: nothing open             -> 0
	send("script")   // 3: band 1 empty, band 0 = 1 -> 1
	send("image")    // 5: band 2 empty, band 1 = 3 -> 3
	send("style")    // 7: band 0 newest = 1        -> 1
	send("script")   // 9: band 1 newest = 3        -> 3
	send("image")    // 11: band 2 newest = 5       -> 5

	close(hold)
	closeAll()
	// The client forgets a stream just after it reads END_STREAM, on the
	// request's own goroutine, so give that a moment before the next one.
	time.Sleep(100 * time.Millisecond)
	send("image") // 13: every earlier stream has closed -> 0
	closeAll()

	want := []struct {
		stream, dep uint32
		weight      uint8
	}{
		{1, 0, 255}, {3, 1, 219}, {5, 3, 182}, {7, 1, 255},
		{9, 3, 219}, {11, 5, 182}, {13, 0, 182},
	}
	got := s.only(frHeaders)
	if len(got) != len(want) {
		t.Fatalf("server saw %d HEADERS frames, want %d;\n%s", len(got), len(want), s.dump())
	}
	for i, w := range want {
		f := got[i]
		if f.StreamID != w.stream {
			t.Fatalf("HEADERS %d is stream %d, want %d", i, f.StreamID, w.stream)
		}
		dep, excl, weight := headersPriority(t, f)
		if dep != w.dep || !excl || weight != w.weight {
			t.Errorf("stream %d: depends on %d exclusive=%v weight=%d, want %d exclusive=true weight=%d",
				f.StreamID, dep, excl, weight, w.dep, w.weight)
		}
	}
}

// A header block over 16KB goes out as HEADERS plus CONTINUATION. quiche caps
// every one of those frames at kHttp2MaxControlFrameSendSize, 16383 bytes with
// the frame header, so the payload is 16374 at most, and the first frame spends
// 5 of those on its priority fields. It used to be the peer's 16384 of block
// plus the 5 priority bytes: a 16389-byte HEADERS payload, over the limit.
func TestH2LargeHeaderBlockSplitsLikeChrome(t *testing.T) {
	s := startH2Server(t, h2Config{})
	tr := newChromeH2(t)

	big := strings.Repeat("0123456789abcdef", 3000) // ~48KB before HPACK
	req, err := http.NewRequest("GET", s.url("/big"), nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("X-Big", big)
	resp, err := tr.RoundTrip(req)
	if err != nil {
		t.Fatalf("request: %v", err)
	}
	io.Copy(io.Discard, resp.Body)
	resp.Body.Close()

	var frames []h2Frame
	for _, f := range s.recorded() {
		if f.Type == frHeaders || f.Type == frContinuation {
			frames = append(frames, f)
		}
	}
	if len(frames) < 3 {
		t.Fatalf("got %d HEADERS/CONTINUATION frames for a ~30KB block, want at least 3;\n%s", len(frames), s.dump())
	}
	if frames[0].Type != frHeaders || frames[0].Flags&flPriority == 0 {
		t.Fatalf("first frame is %s flags=%#x, want HEADERS with priority", frames[0].name(), frames[0].Flags)
	}
	for i, f := range frames {
		last := i == len(frames)-1
		if !last && len(f.Payload) != 16374 {
			t.Errorf("%s %d: payload %d bytes, want 16374", f.name(), i, len(f.Payload))
		}
		if last && len(f.Payload) > 16374 {
			t.Errorf("final %s: payload %d bytes, over 16374", f.name(), len(f.Payload))
		}
		if endHeaders := f.Flags&flEndHeaders != 0; endHeaders != last {
			t.Errorf("%s %d: END_HEADERS=%v, want %v", f.name(), i, endHeaders, last)
		}
	}
	decoded := s.decoded()
	if len(decoded) != 1 || decoded[0]["x-big"] != big {
		t.Fatal("the reassembled block did not decode back to the header that was sent")
	}
}

// Chromium ends a connection at the TCP layer: SSLClientSocketImpl::Disconnect
// never calls SSL_shutdown, so no close_notify goes out. NSS does send one, so
// the Firefox profile still does. Measured below the record layer, because an
// alert decrypts to nothing the H2 server would record.
func TestTLSCloseNotifyFollowsTheProfile(t *testing.T) {
	for _, tc := range []struct {
		preset    string
		wantAlert bool
	}{
		{"chrome-latest", false},
		{"firefox-133", true},
	} {
		t.Run(tc.preset, func(t *testing.T) {
			preset := fingerprint.Get(tc.preset)
			if preset == nil {
				t.Fatalf("%s preset missing", tc.preset)
			}
			s := startH2Server(t, h2Config{})
			tr := NewHTTP2Transport(preset, dns.NewCache())
			tr.SetInsecureSkipVerify(true)

			req, err := http.NewRequest("GET", s.url("/"), nil)
			if err != nil {
				t.Fatal(err)
			}
			resp, err := tr.RoundTrip(req)
			if err != nil {
				t.Fatalf("request: %v", err)
			}
			io.Copy(io.Discard, resp.Body)
			resp.Body.Close()

			// Let the exchange settle, then see what closing adds.
			time.Sleep(200 * time.Millisecond)
			before := s.rawIn.Load()
			tr.Close()
			deadline := time.Now().Add(3 * time.Second)
			for s.ended.Load() == 0 && time.Now().Before(deadline) {
				time.Sleep(10 * time.Millisecond)
			}
			if s.ended.Load() == 0 {
				t.Fatal("the server never saw the connection end")
			}
			sent := s.rawIn.Load() - before
			if gotAlert := sent > 0; gotAlert != tc.wantAlert {
				t.Errorf("closing sent %d bytes; want a close_notify record: %v", sent, tc.wantAlert)
			}
		})
	}
}

// Firefox fills the frame the peer allows, so it keeps the peer's 16384. The
// priority bytes still come out of that budget: 16379 of block, 5 of priority.
func TestH2LargeHeaderBlockStaysInsidePeerLimit(t *testing.T) {
	preset := fingerprint.Get("firefox-133")
	if preset == nil {
		t.Fatal("firefox-133 preset missing")
	}
	s := startH2Server(t, h2Config{})
	tr := NewHTTP2Transport(preset, dns.NewCache())
	tr.SetInsecureSkipVerify(true)
	defer tr.Close()

	req, err := http.NewRequest("GET", s.url("/big"), nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("X-Big", strings.Repeat("0123456789abcdef", 3000))
	resp, err := tr.RoundTrip(req)
	if err != nil {
		t.Fatalf("request: %v", err)
	}
	io.Copy(io.Discard, resp.Body)
	resp.Body.Close()

	first := s.only(frHeaders)
	if len(first) != 1 {
		t.Fatalf("got %d HEADERS frames, want 1;\n%s", len(first), s.dump())
	}
	if first[0].Flags&flPriority == 0 {
		t.Fatal("firefox-133 HEADERS carries no priority, so this does not exercise the priority budget")
	}
	if n := len(first[0].Payload); n != 16384 {
		t.Errorf("HEADERS payload %d bytes, want exactly the peer's 16384", n)
	}
	for _, f := range s.only(frContinuation) {
		if len(f.Payload) > 16384 {
			t.Errorf("CONTINUATION payload %d bytes, over the peer's 16384", len(f.Payload))
		}
	}
}

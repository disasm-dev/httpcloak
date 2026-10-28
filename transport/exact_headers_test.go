package transport

import (
	"bufio"
	"bytes"
	"strings"
	"testing"

	http "github.com/sardanioss/http"

	"github.com/sardanioss/httpcloak/fingerprint"
)

func hp(k, v string) fingerprint.HeaderPair { return fingerprint.HeaderPair{Key: k, Value: v} }

// The normal path is opinionated in three ways a mirror cannot live with: it
// always injects the preset block, it appends unknown caller headers sorted
// alphabetically at the end, and Header.Set canonicalises the casing. Exact
// mode has to defeat all three.
func TestExactHeadersReplaceThePipeline(t *testing.T) {
	req, _ := http.NewRequest("GET", "https://example.com/", nil)
	// Something already in the map, to prove exact mode clears rather than merges.
	req.Header.Set("X-Leftover", "1")

	exact := []fingerprint.HeaderPair{
		hp("Zeta-Header", "1"),
		hp("alpha-header", "2"),
		hp("X-MiXeD-CaSe", "3"),
	}
	if !applyExactHeaders(req, exact, fingerprint.Get("chrome-latest"), nil, "h2") {
		t.Fatal("applyExactHeaders returned false for a non-empty list")
	}

	if _, ok := req.Header["X-Leftover"]; ok {
		t.Error("exact mode merged with the existing header map instead of replacing it")
	}
	// Order is the caller's, not alphabetical. Sorting would put alpha first.
	got := req.Header[http.HeaderOrderKey]
	want := []string{"Zeta-Header", "alpha-header", "X-MiXeD-CaSe"}
	if len(got) != len(want) {
		t.Fatalf("header order = %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("header order = %v, want %v (alphabetical sorting is still happening)", got, want)
		}
	}
	// Casing survives. Header.Set would have produced X-Mixed-Case.
	if _, ok := req.Header["X-MiXeD-CaSe"]; !ok {
		t.Errorf("casing was canonicalised; map keys are %v", keysOf(req.Header))
	}
	// No preset headers were injected.
	for _, banned := range []string{"User-Agent", "user-agent", "sec-ch-ua", "accept"} {
		if _, ok := req.Header[banned]; ok {
			t.Errorf("preset header %q was injected in exact mode", banned)
		}
	}
}

// A map[string]string cannot express two Cookie headers at all, which is the
// shape a captured HTTP/1.1 request often has.
func TestExactHeadersCarryRepeatedNames(t *testing.T) {
	req, _ := http.NewRequest("GET", "https://example.com/", nil)
	applyExactHeaders(req, []fingerprint.HeaderPair{
		hp("Cookie", "a=1"),
		hp("Accept", "*/*"),
		hp("Cookie", "b=2"),
	}, nil, nil, "h1")

	if vals := req.Header["Cookie"]; len(vals) != 2 || vals[0] != "a=1" || vals[1] != "b=2" {
		t.Errorf("Cookie = %v, want both values in order", vals)
	}
	// One order slot per pair, so the second Cookie keeps its own position
	// after the Accept. Deduplicating the names here, which is what this used
	// to do, is what forced the encoders to hoist the second Cookie up next to
	// the first.
	order := req.Header[http.HeaderOrderKey]
	want := []string{"Cookie", "Accept", "Cookie"}
	if len(order) != len(want) {
		t.Fatalf("header order = %v, want %v", order, want)
	}
	for i := range want {
		if order[i] != want[i] {
			t.Fatalf("header order = %v, want %v", order, want)
		}
	}
}

// The slot list has to stay index-aligned with the value slices the encoders
// read, and the value slices are per name in order of appearance.
func TestExactHeadersSlotsAlignWithValues(t *testing.T) {
	req, _ := http.NewRequest("GET", "https://example.com/", nil)
	applyExactHeaders(req, []fingerprint.HeaderPair{
		hp("x-a", "1"),
		hp("x-b", "z"),
		hp("x-a", "2"),
		hp("x-a", "3"),
	}, nil, nil, "h2")

	order := req.Header[http.HeaderOrderKey]
	if len(order) != 4 {
		t.Fatalf("header order = %v, want one slot per pair", order)
	}
	vals := req.Header["x-a"]
	if len(vals) != 3 || vals[0] != "1" || vals[1] != "2" || vals[2] != "3" {
		t.Fatalf("x-a = %v, want [1 2 3] in the order given", vals)
	}
	// Slot count for a name must equal its value count, or the encoders hand a
	// slot the wrong value with nothing to report the mismatch.
	n := 0
	for _, k := range order {
		if k == "x-a" {
			n++
		}
	}
	if n != len(vals) {
		t.Errorf("x-a has %d slots against %d values", n, len(vals))
	}
}

// An empty list must leave the normal pipeline alone, or every request in the
// library changes behaviour.
func TestExactHeadersEmptyIsANoOp(t *testing.T) {
	req, _ := http.NewRequest("GET", "https://example.com/", nil)
	req.Header.Set("X-Keep", "1")
	if applyExactHeaders(req, nil, nil, nil, "h2") {
		t.Fatal("an empty list took over the pipeline")
	}
	if req.Header.Get("X-Keep") != "1" {
		t.Error("an empty list still modified the header map")
	}
}

// Pseudo-header order is protocol framing rather than something the caller
// listed, so it still comes from the preset.
func TestExactHeadersKeepPresetPseudoOrder(t *testing.T) {
	req, _ := http.NewRequest("GET", "https://example.com/", nil)
	applyExactHeaders(req, []fingerprint.HeaderPair{hp("Accept", "*/*")},
		fingerprint.Get("chrome-latest"), nil, "h2")
	if order := req.Header[http.PHeaderOrderKey]; len(order) != 4 {
		t.Errorf("pseudo order = %v, want the preset's four entries", order)
	}
}

func keysOf(h http.Header) []string {
	out := make([]string, 0, len(h))
	for k := range h {
		out = append(out, k)
	}
	return out
}

// The tests above exercise applyExactHeaders directly, which does not prove the
// pipeline actually consults it. This one goes through applyPresetHeaders, the
// real entry point, so deleting the short circuit fails here.
func TestExactHeadersShortCircuitIsWired(t *testing.T) {
	req, _ := http.NewRequest("GET", "https://example.com/", nil)
	applyPresetHeaders(req, newPresetWireHeaders(fingerprint.Get("chrome-latest")), nil, nil, false, "h2",
		map[string][]string{"X-User": {"1"}}, false,
		[]fingerprint.HeaderPair{hp("Only-This", "1")})

	if _, ok := req.Header["User-Agent"]; ok {
		t.Error("preset headers were applied despite ExactHeaders being set; " +
			"applyPresetHeaders is not consulting it")
	}
	if _, ok := req.Header["X-User"]; ok {
		t.Error("the ordinary Headers map was merged in; ExactHeaders must replace it")
	}
	order := req.Header[http.HeaderOrderKey]
	if len(order) != 1 || order[0] != "Only-This" {
		t.Errorf("header order = %v, want exactly [Only-This]", order)
	}
}

// Host and Connection are written ahead of the ordered block, which is right
// for a browser and wrong for a client that orders them differently: Android's
// HttpURLConnection sends User-Agent, Host, Connection, Accept-Encoding. In
// exact mode a listed Host or Connection keeps its slot; an unlisted Host is
// still written first, since the request cannot go out without one.
// A listed content-length went out twice on HTTP/1.1: once as Content-Length
// from the body, once as the caller's own pair from the remainder. It goes out
// once, under the listed name at the listed slot, with the body's length.
func TestExactHeadersSendOneContentLength(t *testing.T) {
	body := "md=answer"
	req, _ := http.NewRequest("POST", "https://example.com/form", strings.NewReader(body))
	applyExactHeaders(req, []fingerprint.HeaderPair{
		hp("content-length", "0"),
		hp("content-type", "application/x-www-form-urlencoded"),
		hp("user-agent", "mirror"),
	}, nil, nil, "h1")
	var buf bytes.Buffer
	conn := &http1Conn{bw: bufio.NewWriter(&buf)}
	if err := (&HTTP1Transport{}).writeRequest(conn, req); err != nil {
		t.Fatalf("writeRequest: %v", err)
	}
	want := "POST /form HTTP/1.1\r\nHost: example.com\r\n" +
		"content-length: 9\r\n" +
		"content-type: application/x-www-form-urlencoded\r\n" +
		"user-agent: mirror\r\n\r\n" + body
	if got := buf.String(); got != want {
		t.Errorf("\n got: %q\nwant: %q", got, want)
	}
}

func TestExactHeadersKeepHostAndConnectionSlots(t *testing.T) {
	write := func(t *testing.T, exact []fingerprint.HeaderPair) string {
		t.Helper()
		req, _ := http.NewRequest("GET", "https://api.example.com/_bm/get_info?deviceId=1", nil)
		applyExactHeaders(req, exact, nil, nil, "h1")
		var buf bytes.Buffer
		conn := &http1Conn{bw: bufio.NewWriter(&buf)}
		if err := (&HTTP1Transport{}).writeRequest(conn, req); err != nil {
			t.Fatalf("writeRequest: %v", err)
		}
		return buf.String()
	}

	got := write(t, []fingerprint.HeaderPair{
		hp("User-Agent", "Akamai BAPSDK/4.3.0-rc2 (Android; 13; Google; Pixel 4 XL; en)"),
		hp("Host", "api.example.com"),
		hp("Connection", "Keep-Alive"),
		hp("Accept-Encoding", "gzip"),
	})
	want := "GET /_bm/get_info?deviceId=1 HTTP/1.1\r\n" +
		"User-Agent: Akamai BAPSDK/4.3.0-rc2 (Android; 13; Google; Pixel 4 XL; en)\r\n" +
		"Host: api.example.com\r\n" +
		"Connection: Keep-Alive\r\n" +
		"Accept-Encoding: gzip\r\n\r\n"
	if got != want {
		t.Errorf("listed Host and Connection lost their slots\n got: %q\nwant: %q", got, want)
	}

	got = write(t, []fingerprint.HeaderPair{hp("User-Agent", "mirror"), hp("Accept", "*/*")})
	want = "GET /_bm/get_info?deviceId=1 HTTP/1.1\r\nHost: api.example.com\r\nUser-Agent: mirror\r\nAccept: */*\r\n\r\n"
	if got != want {
		t.Errorf("unlisted Host must still lead, and no Connection may be added\n got: %q\nwant: %q", got, want)
	}
}

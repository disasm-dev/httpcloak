package altsvc

import (
	"testing"
	"time"
)

func TestParse(t *testing.T) {
	for _, tc := range []struct {
		in      string
		ok      bool
		want    []Alternative
		comment string
	}{
		{`clear`, true, nil, "clear parses to nothing"},
		{`h3=":443"`, true, []Alternative{{"h3", "", 443, 24 * time.Hour}}, "ma defaults to a day"},
		{`h3=":443"; ma=3600, h3-29=":443"; ma=3600`, true, []Alternative{
			{"h3", "", 443, time.Hour}, {"h3-29", "", 443, time.Hour}}, "list with params"},
		{`h2="alt.example.com:8443"; ma=60; persist=1`, true, []Alternative{
			{"h2", "alt.example.com", 8443, time.Minute}}, "alt host"},
		{`h3=":0"`, true, nil, "a bad port drops only that alternative"},
		{`h3=:443`, false, nil, "authority must be quoted"},
		{`h3=":443"; ma=soon`, false, nil, "an unparsable ma rejects the header"},
		{`h%33=":443"`, true, []Alternative{{"h3", "", 443, 24 * time.Hour}}, "protocol-id is percent-decoded"},
	} {
		got, ok := Parse(tc.in)
		if ok != tc.ok {
			t.Errorf("%s (%q): ok = %v, want %v", tc.comment, tc.in, ok, tc.ok)
			continue
		}
		if len(got) != len(tc.want) {
			t.Errorf("%s (%q): got %v, want %v", tc.comment, tc.in, got, tc.want)
			continue
		}
		for i := range got {
			if got[i] != tc.want[i] {
				t.Errorf("%s (%q): alternative %d = %+v, want %+v", tc.comment, tc.in, i, got[i], tc.want[i])
			}
		}
	}
}

// A parsed header replaces what was known, so it can withdraw h3 as well as
// add it, and only h3 on the origin's own host and port counts.
func TestCacheLearn(t *testing.T) {
	now := time.Now()
	var c Cache
	h3 := func() bool { return c.AdvertisesH3("example.com", "443", now) }

	c.Learn("example.com", "443", []string{`h2=":443"`}, now)
	if h3() {
		t.Fatal("h2 alternative counted as HTTP/3")
	}
	c.Learn("example.com", "443", []string{`h3=":8443"`}, now)
	if h3() {
		t.Fatal("h3 on another port counted; the QUIC dial goes to the origin's port")
	}
	c.Learn("example.com", "443", []string{`h3="other.example.com:443"`}, now)
	if h3() {
		t.Fatal("h3 on another host counted")
	}
	c.Learn("example.com", "443", []string{`h3=":443"; ma=60`}, now)
	if !h3() {
		t.Fatal("h3 on the origin's port was not recorded")
	}
	if c.AdvertisesH3("example.com", "443", now.Add(61*time.Second)) {
		t.Fatal("h3 outlived its ma")
	}
	c.Learn("example.com", "443", []string{`h3=":443"; ma=soon`}, now)
	if !h3() {
		t.Fatal("a malformed header changed what was known; it should be ignored")
	}
	c.Learn("example.com", "443", nil, now)
	if !h3() {
		t.Fatal("a response without Alt-Svc changed what was known")
	}
	c.Learn("example.com", "443", []string{`h2=":443"`, `h3="EXAMPLE.com:443"`}, now)
	if !h3() {
		t.Fatal("h3 in a second header line, or with the origin's host spelled out, was missed")
	}
	c.Learn("example.com", "443", []string{"clear"}, now)
	if h3() {
		t.Fatal("clear did not withdraw h3")
	}

	c.LearnFromURL("https://Example.com/path", []string{`h3=":443"`}, now)
	if !h3() {
		t.Fatal("LearnFromURL did not record an https origin on its default port")
	}
	c.LearnFromURL("http://plain.example/", []string{`h3=":443"`}, now)
	if c.AdvertisesH3("plain.example", "443", now) {
		t.Fatal("Alt-Svc on a plaintext response was honoured")
	}
}

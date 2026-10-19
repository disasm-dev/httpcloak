package session

import (
	"context"
	"reflect"
	"strings"
	"testing"

	"github.com/sardanioss/httpcloak/fingerprint"
	"github.com/sardanioss/httpcloak/protocol"
	"github.com/sardanioss/httpcloak/transport"
)

func exactCookieHop(t *testing.T, jarCookie bool, exact []fingerprint.HeaderPair) hopRecord {
	t.Helper()
	srv := newBodyCapture(t, 200)
	s := newBodyTestSession(t, &protocol.SessionConfig{})
	if jarCookie {
		host, _, _ := strings.Cut(strings.TrimPrefix(strings.TrimSuffix(srv.url, "/"), "http://"), ":")
		s.SetCookie("jar", "yes", host, "/", false, false, "", 0, nil)
	}
	if _, err := s.Request(context.Background(), &transport.Request{
		Method: "GET", URL: srv.url + "x", ExactHeaders: exact,
	}); err != nil {
		t.Fatalf("request: %v", err)
	}
	srv.mu.Lock()
	defer srv.mu.Unlock()
	return srv.hops[0]
}

// An empty Cookie pair is a slot: the jar's header goes out in that position.
func TestExactHeadersFillTheCookieSlotFromTheJar(t *testing.T) {
	exact := []fingerprint.HeaderPair{
		{Key: "user-agent", Value: "mirror/1"},
		{Key: "Cookie", Value: ""},
		{Key: "accept", Value: "*/*"},
	}
	hop := exactCookieHop(t, true, exact)
	if want := []string{"user-agent", "cookie", "accept"}; !reflect.DeepEqual(hop.headers, want) {
		t.Errorf("wire carried %v, want %v", hop.headers, want)
	}
	if got := hop.values["cookie"]; got != "jar=yes" {
		t.Errorf("cookie = %q, want the jar's", got)
	}
	if exact[1].Value != "" {
		t.Error("the caller's slice was written to")
	}
}

// With nothing in the jar the slot is dropped rather than sent empty.
func TestExactHeadersDropAnEmptyCookieSlot(t *testing.T) {
	hop := exactCookieHop(t, false, []fingerprint.HeaderPair{
		{Key: "user-agent", Value: "mirror/1"},
		{Key: "Cookie", Value: ""},
		{Key: "accept", Value: "*/*"},
	})
	if want := []string{"user-agent", "accept"}; !reflect.DeepEqual(hop.headers, want) {
		t.Errorf("wire carried %v, want %v", hop.headers, want)
	}
}

// A Cookie pair that carries a value is the caller's and the jar stays out of it.
func TestExactHeadersKeepAListedCookie(t *testing.T) {
	hop := exactCookieHop(t, true, []fingerprint.HeaderPair{
		{Key: "user-agent", Value: "mirror/1"},
		{Key: "Cookie", Value: "mine=1"},
	})
	if got := hop.values["cookie"]; got != "mine=1" {
		t.Errorf("cookie = %q, want the caller's", got)
	}
}

// The response reports the list as it went out, the jar's cookie in the slot.
func TestExactHeadersReportTheListAsSent(t *testing.T) {
	srv := newBodyCapture(t, 200)
	s := newBodyTestSession(t, &protocol.SessionConfig{})
	host, _, _ := strings.Cut(strings.TrimPrefix(strings.TrimSuffix(srv.url, "/"), "http://"), ":")
	s.SetCookie("jar", "yes", host, "/", false, false, "", 0, nil)

	resp, err := s.Request(context.Background(), &transport.Request{
		Method: "GET", URL: srv.url + "x", ExactHeaders: []fingerprint.HeaderPair{
			{Key: "user-agent", Value: "mirror/1"},
			{Key: "Cookie", Value: ""},
			{Key: "accept", Value: "*/*"},
		},
	})
	if err != nil {
		t.Fatalf("request: %v", err)
	}

	var reported []string
	for _, hp := range resp.RequestHeaders {
		reported = append(reported, strings.ToLower(hp.Key)+": "+hp.Value)
	}
	srv.mu.Lock()
	defer srv.mu.Unlock()
	var wire []string
	for _, pair := range srv.hops[0].pairs {
		if !strings.HasPrefix(pair, "host: ") {
			wire = append(wire, pair)
		}
	}
	if !reflect.DeepEqual(reported, wire) {
		t.Errorf("reported %v, wire carried %v", reported, wire)
	}
}

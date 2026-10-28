package httpcloak

import (
	"context"
	"os"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/sardanioss/httpcloak/cloudflare"
)

// TestCloudflareLive clears a real challenge. HTTPCLOAK_CF_LIVE_URL names a
// page behind Cloudflare's challenge, HTTPCLOAK_CF_API_KEY the
// cf.antibotapi.com key, and HTTPCLOAK_CF_SERVICE_URL, when set, another solve
// service, such as a local Cf.Api run as the bot's child, which takes no key.
// Skipped unless the URL is set.
func TestCloudflareLive(t *testing.T) {
	target := os.Getenv("HTTPCLOAK_CF_LIVE_URL")
	if target == "" {
		t.Skip("HTTPCLOAK_CF_LIVE_URL not set")
	}
	var solves atomic.Int32
	s := NewSession("chrome-latest-windows", WithCloudflareConfig(cloudflare.Config{
		APIKey:     os.Getenv("HTTPCLOAK_CF_API_KEY"),
		ServiceURL: os.Getenv("HTTPCLOAK_CF_SERVICE_URL"),
		Logf: func(format string, args ...any) {
			if strings.HasSuffix(format, "solving") {
				solves.Add(1)
			}
			t.Logf(format, args...)
		},
	}))
	defer s.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	resp, err := s.Get(ctx, target)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	body, _ := resp.Bytes()
	if resp.StatusCode >= 400 || cloudflare.IsChallengePage(body) {
		t.Fatalf("still challenged: %d over %s, %d bytes", resp.StatusCode, resp.Protocol, len(body))
	}
	t.Logf("got %d over %s, %d bytes, after %d solve(s)", resp.StatusCode, resp.Protocol, len(body), solves.Load())

	var clearance bool
	for _, c := range s.GetCookies() {
		clearance = clearance || c.Name == "cf_clearance"
	}
	if solves.Load() > 0 && !clearance {
		t.Errorf("solved, but no cf_clearance in the jar")
	}

	before := solves.Load()
	again, err := s.Get(ctx, target)
	if err != nil {
		t.Fatalf("second Get: %v", err)
	}
	again.Close()
	if solves.Load() != before || again.StatusCode >= 400 {
		t.Errorf("second request: %d with %d more solve(s); cf_clearance should carry it straight through", again.StatusCode, solves.Load()-before)
	}
}

package httpcloak

import (
	"context"
	"os"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/sardanioss/httpcloak/datadome"
)

// TestDatadomeLive answers a real DataDome block. HTTPCLOAK_DD_LIVE_URL names
// a page behind DataDome, HTTPCLOAK_DD_API_KEY the dd.antibotapi.com key, and
// HTTPCLOAK_DD_PROXY, when set, the proxy to go out through (a datacenter IP
// usually draws the block a residential one does not). Skipped unless the URL
// is set.
func TestDatadomeLive(t *testing.T) {
	target := os.Getenv("HTTPCLOAK_DD_LIVE_URL")
	if target == "" {
		t.Skip("HTTPCLOAK_DD_LIVE_URL not set")
	}
	var solves atomic.Int32
	opts := []SessionOption{WithDatadomeConfig(datadome.Config{
		APIKey: os.Getenv("HTTPCLOAK_DD_API_KEY"),
		Logf: func(format string, args ...any) {
			if strings.HasSuffix(format, "solving") {
				solves.Add(1)
			}
			t.Logf(format, args...)
		},
	})}
	if proxy := os.Getenv("HTTPCLOAK_DD_PROXY"); proxy != "" {
		opts = append(opts, WithSessionProxy(proxy))
	}
	s := NewSession("chrome-latest-windows", opts...)
	defer s.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	resp, err := s.Get(ctx, target)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	body, _ := resp.Bytes()
	if resp.StatusCode >= 400 || datadome.Classify(body) != datadome.NotBlocked {
		t.Fatalf("still blocked: %d over %s, %d bytes", resp.StatusCode, resp.Protocol, len(body))
	}
	t.Logf("got %d over %s, %d bytes, after %d solve(s)", resp.StatusCode, resp.Protocol, len(body), solves.Load())

	before := solves.Load()
	again, err := s.Get(ctx, target)
	if err != nil {
		t.Fatalf("second Get: %v", err)
	}
	again.Close()
	if solves.Load() != before || again.StatusCode >= 400 {
		t.Errorf("second request: %d with %d more solve(s); the datadome cookie should carry it straight through", again.StatusCode, solves.Load()-before)
	}
}

package transport

import (
	"context"
	"net"
	"sync/atomic"
	"testing"
	"time"
)

// udpCounter binds the UDP side of a port and counts every datagram that
// arrives, which is every QUIC packet a client sends there.
func udpCounter(t *testing.T, addr string) *atomic.Int32 {
	t.Helper()
	pc, err := net.ListenPacket("udp", addr)
	if err != nil {
		t.Fatalf("bind UDP %s: %v", addr, err)
	}
	t.Cleanup(func() { pc.Close() })
	var n atomic.Int32
	go func() {
		buf := make([]byte, 2048)
		for {
			if _, _, err := pc.ReadFrom(buf); err != nil {
				return
			}
			n.Add(1)
		}
	}()
	return &n
}

// Auto mode used to race QUIC against TCP on the first request to any host.
// Chrome opens no QUIC connection until the server has advertised HTTP/3, and
// then brings it up beside the live TCP connection rather than instead of it.
// The UDP port behind the test server shows exactly when a QUIC packet leaves.
func TestAutoModeOpensQUICOnlyAfterAltSvc(t *testing.T) {
	var advertise atomic.Pointer[string]
	s := startH2Server(t, h2Config{ResponseHeaders: func() map[string]string {
		if v := advertise.Load(); v != nil {
			return map[string]string{"alt-svc": *v}
		}
		return nil
	}})
	quicPackets := udpCounter(t, s.addr)
	_, port, _ := net.SplitHostPort(s.addr)

	tr := NewTransport("chrome-latest")
	tr.SetInsecureSkipVerify(true)
	// No ECH lookup: it would hold an H3 probe back long enough for a local
	// TCP handshake to win and cancel it, hiding a QUIC attempt this checks for.
	tr.SetDisableECH(true)
	defer tr.Close()

	get := func() {
		t.Helper()
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		resp, err := tr.Do(ctx, &Request{Method: "GET", URL: s.url("/")})
		if err != nil {
			t.Fatalf("request: %v", err)
		}
		if resp.Protocol != "h2" {
			t.Fatalf("served over %q, want h2", resp.Protocol)
		}
	}

	get()
	get()
	time.Sleep(300 * time.Millisecond)
	if n := quicPackets.Load(); n != 0 {
		t.Fatalf("%d QUIC packets sent to a host that never advertised HTTP/3", n)
	}

	altSvc := `h3=":` + port + `"; ma=86400`
	advertise.Store(&altSvc)
	get() // carries Alt-Svc; this request itself is not held back for QUIC
	get() // served on TCP while QUIC comes up in the background
	deadline := time.Now().Add(3 * time.Second)
	for quicPackets.Load() == 0 && time.Now().Before(deadline) {
		time.Sleep(20 * time.Millisecond)
	}
	if quicPackets.Load() == 0 {
		t.Fatal("no QUIC attempt after the host advertised h3 on its own port")
	}
}

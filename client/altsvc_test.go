package client

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"
)

// The stream path in auto mode used to try HTTP/3 first against any host, so
// the first streamed request to a site that never offered HTTP/3 opened a QUIC
// connection, which Chrome never does. A direct connection now waits for the
// host's Alt-Svc. A UDP listener on the server's port sees any QUIC packet.
func TestAutoStreamOpensQUICOnlyAfterAltSvc(t *testing.T) {
	var advertise atomic.Pointer[string]
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if v := advertise.Load(); v != nil {
			w.Header().Set("Alt-Svc", *v)
		}
		fmt.Fprint(w, "ok")
	}))
	server.EnableHTTP2 = true
	server.StartTLS()
	defer server.Close()
	addr := server.Listener.Addr().String()
	_, port, _ := net.SplitHostPort(addr)

	pc, err := net.ListenPacket("udp", addr)
	if err != nil {
		t.Fatalf("bind UDP %s: %v", addr, err)
	}
	defer pc.Close()
	var quicPackets atomic.Int32
	go func() {
		buf := make([]byte, 2048)
		for {
			if _, _, err := pc.ReadFrom(buf); err != nil {
				return
			}
			quicPackets.Add(1)
		}
	}()

	c := NewClient("chrome-latest", WithInsecureSkipVerify(), WithTimeout(10*time.Second))
	defer c.Close()
	stream := func(ctx context.Context) error {
		s, err := c.DoStream(ctx, &Request{Method: http.MethodGet, URL: server.URL})
		if err != nil {
			return err
		}
		io.Copy(io.Discard, s)
		return s.Close()
	}

	for i := 0; i < 2; i++ {
		if err := stream(context.Background()); err != nil {
			t.Fatalf("stream %d: %v", i+1, err)
		}
	}
	time.Sleep(300 * time.Millisecond)
	if n := quicPackets.Load(); n != 0 {
		t.Fatalf("%d QUIC packets sent to a host that never advertised HTTP/3", n)
	}

	altSvc := `h3=":` + port + `"; ma=86400`
	advertise.Store(&altSvc)
	if err := stream(context.Background()); err != nil { // carries Alt-Svc
		t.Fatalf("stream: %v", err)
	}
	// Now HTTP/3 goes first. Nothing answers QUIC here, so stop the request
	// once its first packet has been seen.
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { defer close(done); stream(ctx) }()
	deadline := time.Now().Add(3 * time.Second)
	for quicPackets.Load() == 0 && time.Now().Before(deadline) {
		time.Sleep(20 * time.Millisecond)
	}
	cancel()
	<-done
	if quicPackets.Load() == 0 {
		t.Fatal("no QUIC attempt after the host advertised h3 on its own port")
	}
}

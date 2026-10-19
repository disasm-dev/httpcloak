package dns

import (
	"context"
	"net"
	"testing"

	"github.com/miekg/dns"
)

// startHTTPSRecordServer answers HTTPS queries from records, keyed by FQDN,
// and points the HTTPS lookups at itself for the duration of the test.
func startHTTPSRecordServer(t *testing.T, records map[string][]*dns.HTTPS) {
	t.Helper()
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	srv := &dns.Server{PacketConn: pc, Handler: dns.HandlerFunc(func(w dns.ResponseWriter, q *dns.Msg) {
		m := new(dns.Msg)
		m.SetReply(q)
		for _, rr := range records[q.Question[0].Name] {
			rr.Hdr = dns.RR_Header{Name: q.Question[0].Name, Rrtype: dns.TypeHTTPS, Class: dns.ClassINET, Ttl: 60}
			m.Answer = append(m.Answer, rr)
		}
		w.WriteMsg(m)
	})}
	go srv.ActivateAndServe()
	t.Cleanup(func() {
		srv.Shutdown()
		SetECHDNSServers(nil)
	})
	SetECHDNSServers([]string{pc.LocalAddr().String()})
}

func service(target string, params ...dns.SVCBKeyValue) *dns.HTTPS {
	return &dns.HTTPS{SVCB: dns.SVCB{Priority: 1, Target: target, Value: params}}
}

// Chrome tries QUIC on a first request only when an HTTPS record for the name
// offers h3. Everything else in the record set is a no.
func TestAdvertisesH3FromHTTPSRecord(t *testing.T) {
	h3h2 := &dns.SVCBAlpn{Alpn: []string{"h3", "h2"}}
	startHTTPSRecordServer(t, map[string][]*dns.HTTPS{
		"h3.alpn.test.":     {service(".", h3h2)},
		"named.alpn.test.":  {service("named.alpn.test.", h3h2)},
		"h2only.alpn.test.": {service(".", &dns.SVCBAlpn{Alpn: []string{"h2"}})},
		"alias.alpn.test.":  {{SVCB: dns.SVCB{Priority: 0, Target: "cdn.example."}}},
		"port.alpn.test.":   {service(".", h3h2, &dns.SVCBPort{Port: 8443})},
		"elsewhere.test.":   {service("cdn.example.", h3h2)},
		"ech.alpn.test.":    {service(".", h3h2, &dns.SVCBECHConfig{ECH: []byte{0xfe, 0x0d}})},
	})

	ctx := context.Background()
	for host, want := range map[string]bool{
		"h3.alpn.test":     true,
		"named.alpn.test":  true,
		"h2only.alpn.test": false,
		"alias.alpn.test":  false,
		"port.alpn.test":   false,
		"elsewhere.test":   false,
		"none.alpn.test":   false, // no record at all
		"ech.alpn.test":    true,
	} {
		if got := AdvertisesH3(ctx, host); got != want {
			t.Errorf("%s: AdvertisesH3 = %v, want %v", host, got, want)
		}
	}

	// The same lookup still feeds ECH.
	if ech, _ := FetchECHConfigs(ctx, "ech.alpn.test"); len(ech) != 2 {
		t.Errorf("ECH config from the shared lookup: %x, want fe0d", ech)
	}
}

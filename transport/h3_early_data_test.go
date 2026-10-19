package transport

import (
	"crypto/rand"
	"fmt"
	"io"
	"net"
	"sort"
	"testing"
	"time"

	shttp "github.com/sardanioss/http"
	"github.com/sardanioss/httpcloak/dns"
	"github.com/sardanioss/httpcloak/fingerprint"
	quic "github.com/sardanioss/quic-go"
	"github.com/sardanioss/quic-go/http3"
	utls "github.com/sardanioss/utls"
)

// firstFlightPayload decrypts the leading Initial packet of a datagram with
// keys derived from the packet's own destination connection ID. That only
// works for a connection's first flight: later client Initials are addressed
// to an ID the server chose, and those return ok=false rather than failing.
func firstFlightPayload(d []byte) (dcid, payload []byte, ok bool) {
	defer func() {
		if recover() != nil {
			ok = false
		}
	}()
	if len(d) < 7 || d[0]&0x80 == 0 || (d[0]>>4)&0x3 != 0 {
		return nil, nil, false
	}
	pos := 5
	dcid = d[pos+1 : pos+1+int(d[pos])]
	pos += 1 + len(dcid)
	pos += 1 + int(d[pos])
	tokenLen, n := readVarint(d[pos:])
	pos += n + int(tokenLen)
	length, n := readVarint(d[pos:])
	pos += n
	pnOffset := pos

	o := clientInitialOpener(&testing.T{}, dcid)
	mask := make([]byte, 16)
	o.hp.Encrypt(mask, d[pnOffset+4:pnOffset+20])
	hdr := append([]byte(nil), d[:pnOffset+4]...)
	hdr[0] ^= mask[0] & 0x0f
	pnLen := int(hdr[0]&0x03) + 1
	var pn uint64
	for i := 0; i < pnLen; i++ {
		hdr[pnOffset+i] ^= mask[1+i]
		pn = pn<<8 | uint64(hdr[pnOffset+i])
	}
	nonce := append([]byte(nil), o.iv...)
	for i := 0; i < 8; i++ {
		nonce[len(nonce)-1-i] ^= byte(pn >> (8 * i))
	}
	out, err := o.aead.Open(nil, nonce, d[pnOffset+pnLen:pnOffset+int(length)], hdr[:pnOffset+pnLen])
	if err != nil {
		return nil, nil, false
	}
	return dcid, out, true
}

// quicClientHellos returns the ClientHello of every connection in a capture of
// client datagrams, in the order the connections started.
func quicClientHellos(t *testing.T, sent [][]byte) []*utls.PubClientHelloMsg {
	t.Helper()
	crypto := map[string]map[uint64][]byte{}
	var order []string
	for _, d := range sent {
		dcid, payload, ok := firstFlightPayload(d)
		if !ok {
			continue
		}
		k := string(dcid)
		if crypto[k] == nil {
			crypto[k] = map[uint64][]byte{}
			order = append(order, k)
		}
		for off, data := range walkInitial(t, payload).crypto {
			crypto[k][off] = data
		}
	}
	var hellos []*utls.PubClientHelloMsg
	for _, k := range order {
		offs := make([]uint64, 0, len(crypto[k]))
		for off := range crypto[k] {
			offs = append(offs, off)
		}
		sort.Slice(offs, func(i, j int) bool { return offs[i] < offs[j] })
		var buf []byte
		for _, off := range offs {
			data := crypto[k][off]
			if int(off) > len(buf) {
				break
			}
			if end := int(off) + len(data); end > len(buf) {
				buf = append(buf, data[len(buf)-int(off):]...)
			}
		}
		if len(buf) < 4 {
			continue
		}
		n := 4 + (int(buf[1])<<16 | int(buf[2])<<8 | int(buf[3]))
		if len(buf) < n {
			continue
		}
		if m := utls.UnmarshalClientHello(buf[:n]); m != nil {
			hellos = append(hellos, m)
		}
	}
	return hellos
}

// serveH3 answers HTTP/3 on conn, issuing tickets that allow 0-RTT or not.
func serveH3(t *testing.T, conn net.PacketConn, tlsConf *utls.Config, allow0RTT bool) *http3.Server {
	t.Helper()
	srv := &http3.Server{
		TLSConfig:  tlsConf,
		QUICConfig: &quic.Config{Allow0RTT: allow0RTT},
		Handler: shttp.HandlerFunc(func(w shttp.ResponseWriter, r *shttp.Request) {
			w.WriteHeader(200)
		}),
	}
	go srv.Serve(conn)
	t.Cleanup(func() { srv.Close() })
	return srv
}

func h3Get(tr *HTTP3Transport, url string) error {
	req, err := shttp.NewRequest("GET", url, nil)
	if err != nil {
		return err
	}
	resp, err := tr.RoundTrip(req)
	if err != nil {
		return err
	}
	io.Copy(io.Discard, resp.Body)
	return resp.Body.Close()
}

// earlyDataScenario serves one request, drops the connection, optionally swaps
// the server, then resumes, and returns the resumed request's error and every
// ClientHello the client sent.
func earlyDataScenario(t *testing.T, firstAllows, secondAllows bool) (error, []*utls.PubClientHelloMsg) {
	t.Helper()
	conn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	addr := conn.LocalAddr().(*net.UDPAddr)
	tlsConf := h3RaceTestTLS(t)
	// Shared ticket keys, so a replacement server can still resume the
	// first one's sessions and only its early data policy differs.
	var key [32]byte
	rand.Read(key[:])
	tlsConf.SetSessionTicketKeys([][32]byte{key})
	first := serveH3(t, conn, tlsConf, firstAllows)
	relay := startQUICRelay(t, "udp4", addr, 0)

	tr, err := NewHTTP3Transport(fingerprint.Get("chrome-latest"), dns.NewCache())
	if err != nil {
		t.Fatal(err)
	}
	tr.SetInsecureSkipVerify(true)
	tr.SetDisableECH(true)
	defer tr.Close()

	url := fmt.Sprintf("https://127.0.0.1:%d/", relay.addr.Port)
	if err := h3Get(tr, url); err != nil {
		t.Fatalf("first request: %v", err)
	}
	time.Sleep(300 * time.Millisecond) // the tickets follow the handshake
	tr.Refresh()

	if secondAllows != firstAllows {
		first.Close()
		conn.Close()
		conn2, err := net.ListenUDP("udp4", addr)
		if err != nil {
			t.Fatalf("reopen %v: %v", addr, err)
		}
		serveH3(t, conn2, tlsConf, secondAllows)
	}
	err = h3Get(tr, url)
	sent, _ := relay.datagrams()
	return err, quicClientHellos(t, sent)
}

// A ticket issued without early data (a Cloudflare zone with 0-RTT off, for
// one) is resumed without offering it, as BoringSSL does. The resumed hello
// used to carry early_data regardless, the server rejected the 0-RTT, and the
// request failed with "0-RTT rejected".
func TestH3ResumptionOmitsEarlyDataTheTicketForbids(t *testing.T) {
	err, hellos := earlyDataScenario(t, false, false)
	if err != nil {
		t.Fatalf("resumed request: %v", err)
	}
	if len(hellos) < 2 {
		t.Fatalf("%d ClientHellos captured, want 2", len(hellos))
	}
	resumed := hellos[len(hellos)-1]
	if len(resumed.PskIdentities) == 0 {
		t.Fatal("the second connection did not offer the session")
	}
	if resumed.EarlyData {
		t.Error("offered early data on a ticket that does not allow it")
	}
}

// A ticket that allowed early data meets a server that now rejects it. The
// retry has to resume without early data; it used to offer it again, be
// rejected again, and fail after three attempts.
func TestH3ZeroRTTRejectionRetriesWithoutEarlyData(t *testing.T) {
	err, hellos := earlyDataScenario(t, true, false)
	if err != nil {
		t.Fatalf("resumed request: %v", err)
	}
	if len(hellos) < 3 {
		t.Fatalf("%d ClientHellos captured, want the fresh one, the rejected 0-RTT and the retry", len(hellos))
	}
	rejected, retry := hellos[1], hellos[len(hellos)-1]
	if !rejected.EarlyData {
		t.Fatal("the first resumption did not offer early data, so nothing was rejected")
	}
	if retry.EarlyData {
		t.Error("the retry offered early data again")
	}
	if len(retry.PskIdentities) == 0 {
		t.Error("the retry gave up resumption as well as early data")
	}
}

// Where the ticket allows it and the server takes it, 0-RTT is still offered,
// as Chrome offers it.
func TestH3ResumptionOffersEarlyDataTheTicketAllows(t *testing.T) {
	err, hellos := earlyDataScenario(t, true, true)
	if err != nil {
		t.Fatalf("resumed request: %v", err)
	}
	if len(hellos) != 2 {
		t.Fatalf("%d ClientHellos captured, want 2", len(hellos))
	}
	if !hellos[1].EarlyData {
		t.Error("early data was not offered on a ticket that allows it")
	}
}

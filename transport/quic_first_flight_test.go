package transport

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hkdf"
	"crypto/sha256"
	"encoding/binary"
	"net"
	"strconv"
	"sync"
	"testing"
	"time"

	shttp "github.com/sardanioss/http"
	"github.com/sardanioss/httpcloak/dns"
	"github.com/sardanioss/httpcloak/fingerprint"
	"github.com/sardanioss/quic-go/http3"
)

// Wire locks on the client's QUIC first flight, read the way an on-path
// observer reads it: Initial packets are encrypted with keys anyone can derive
// from the destination connection ID (RFC 9001 section 5.2), so the test
// decrypts them itself rather than asking quic-go what it meant to send.

// ------------------------------------------------------------ Initial keys

var quicV1InitialSalt = []byte{0x38, 0x76, 0x2c, 0xf7, 0xf5, 0x59, 0x34, 0xb3, 0x4d, 0x17, 0x9a, 0xe6, 0xa4, 0xc8, 0x0c, 0xad, 0xcc, 0xbb, 0x7f, 0x0a}

func hkdfExpandLabel(t *testing.T, secret []byte, label string, length int) []byte {
	t.Helper()
	full := "tls13 " + label
	info := make([]byte, 0, 4+len(full))
	info = binary.BigEndian.AppendUint16(info, uint16(length))
	info = append(info, byte(len(full)))
	info = append(info, full...)
	info = append(info, 0) // empty context
	out, err := hkdf.Expand(sha256.New, secret, string(info), length)
	if err != nil {
		t.Fatal(err)
	}
	return out
}

type initialOpener struct {
	aead cipher.AEAD
	iv   []byte
	hp   cipher.Block
}

func clientInitialOpener(t *testing.T, dcid []byte) *initialOpener {
	t.Helper()
	initialSecret, err := hkdf.Extract(sha256.New, dcid, quicV1InitialSalt)
	if err != nil {
		t.Fatal(err)
	}
	clientSecret := hkdfExpandLabel(t, initialSecret, "client in", 32)
	block, err := aes.NewCipher(hkdfExpandLabel(t, clientSecret, "quic key", 16))
	if err != nil {
		t.Fatal(err)
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		t.Fatal(err)
	}
	hp, err := aes.NewCipher(hkdfExpandLabel(t, clientSecret, "quic hp", 16))
	if err != nil {
		t.Fatal(err)
	}
	return &initialOpener{aead: aead, iv: hkdfExpandLabel(t, clientSecret, "quic iv", 12), hp: hp}
}

func readVarint(b []byte) (uint64, int) {
	n := 1 << (b[0] >> 6)
	v := uint64(b[0] & 0x3f)
	for i := 1; i < n; i++ {
		v = v<<8 | uint64(b[i])
	}
	return v, n
}

// initialPacket is one decrypted client Initial packet.
type initialPacket struct {
	dcid      []byte
	pn        uint64
	pnLen     int
	payload   []byte
	datagram  int // length of the UDP payload it arrived in
	sentAfter time.Duration
}

// parseInitial reads the leading long-header packet of a datagram. ok is false
// for anything that is not an Initial.
func parseInitial(t *testing.T, d []byte, opener func(dcid []byte) *initialOpener) (p initialPacket, ok bool) {
	t.Helper()
	if len(d) < 7 || d[0]&0x80 == 0 || (d[0]>>4)&0x3 != 0 {
		return p, false
	}
	pos := 5
	dcidLen := int(d[pos])
	p.dcid = d[pos+1 : pos+1+dcidLen]
	pos += 1 + dcidLen
	pos += 1 + int(d[pos]) // source connection ID
	tokenLen, n := readVarint(d[pos:])
	pos += n + int(tokenLen)
	length, n := readVarint(d[pos:])
	pos += n
	pnOffset := pos

	o := opener(p.dcid)
	mask := make([]byte, 16)
	o.hp.Encrypt(mask, d[pnOffset+4:pnOffset+20])
	hdr := append([]byte(nil), d[:pnOffset+4]...)
	hdr[0] ^= mask[0] & 0x0f
	p.pnLen = int(hdr[0]&0x03) + 1
	for i := 0; i < p.pnLen; i++ {
		hdr[pnOffset+i] ^= mask[1+i]
		p.pn = p.pn<<8 | uint64(hdr[pnOffset+i])
	}
	nonce := append([]byte(nil), o.iv...)
	for i := 0; i < 8; i++ {
		nonce[len(nonce)-1-i] ^= byte(p.pn >> (8 * i))
	}
	end := pnOffset + int(length)
	payload, err := o.aead.Open(nil, nonce, d[pnOffset+p.pnLen:end], hdr[:pnOffset+p.pnLen])
	if err != nil {
		t.Fatalf("Initial packet did not decrypt: %v", err)
	}
	p.payload = payload
	p.datagram = len(d)
	return p, true
}

// initialFrames is what a decrypted Initial payload holds.
type initialFrames struct {
	crypto  map[uint64][]byte // offset -> data
	pings   int
	padRuns int
	pad     int
}

func walkInitial(t *testing.T, b []byte) initialFrames {
	t.Helper()
	f := initialFrames{crypto: map[uint64][]byte{}}
	for len(b) > 0 {
		switch b[0] {
		case 0x00:
			f.padRuns++
			for len(b) > 0 && b[0] == 0 {
				f.pad++
				b = b[1:]
			}
		case 0x01:
			f.pings++
			b = b[1:]
		case 0x06:
			off, n1 := readVarint(b[1:])
			l, n2 := readVarint(b[1+n1:])
			start := 1 + n1 + n2
			f.crypto[off] = b[start : start+int(l)]
			b = b[start+int(l):]
		default:
			t.Fatalf("unexpected frame %#x in a first-flight Initial", b[0])
		}
	}
	return f
}

// ------------------------------------------------------------ relay

// quicRelay sits between the client and a local HTTP/3 server, recording each
// client datagram with the time it arrived. drop discards the first n client
// datagrams, the way a lossy path would.
type quicRelay struct {
	addr  *net.UDPAddr
	start time.Time

	mu   sync.Mutex
	sent [][]byte
	at   []time.Duration
	drop int
}

func startQUICRelay(t *testing.T, network string, server *net.UDPAddr, drop int) *quicRelay {
	t.Helper()
	front, err := net.ListenUDP(network, &net.UDPAddr{IP: server.IP})
	if err != nil {
		t.Fatalf("relay listen: %v", err)
	}
	back, err := net.DialUDP(network, nil, server)
	if err != nil {
		t.Fatalf("relay dial: %v", err)
	}
	t.Cleanup(func() { front.Close(); back.Close() })
	r := &quicRelay{addr: front.LocalAddr().(*net.UDPAddr), start: time.Now(), drop: drop}

	var client *net.UDPAddr
	var clientMu sync.Mutex
	go func() {
		buf := make([]byte, 2048)
		for {
			n, from, err := front.ReadFromUDP(buf)
			if err != nil {
				return
			}
			clientMu.Lock()
			client = from
			clientMu.Unlock()
			r.mu.Lock()
			r.sent = append(r.sent, append([]byte(nil), buf[:n]...))
			r.at = append(r.at, time.Since(r.start))
			dropIt := len(r.sent) <= r.drop
			r.mu.Unlock()
			if !dropIt {
				back.Write(buf[:n])
			}
		}
	}()
	go func() {
		buf := make([]byte, 2048)
		for {
			n, err := back.Read(buf)
			if err != nil {
				return
			}
			clientMu.Lock()
			to := client
			clientMu.Unlock()
			if to != nil {
				front.WriteToUDP(buf[:n], to)
			}
		}
	}()
	return r
}

func (r *quicRelay) datagrams() ([][]byte, []time.Duration) {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([][]byte(nil), r.sent...), append([]time.Duration(nil), r.at...)
}

func startLocalH3Server(t *testing.T, network string, ip net.IP) *net.UDPAddr {
	t.Helper()
	conn, err := net.ListenUDP(network, &net.UDPAddr{IP: ip})
	if err != nil {
		return nil
	}
	srv := &http3.Server{
		TLSConfig: h3RaceTestTLS(t),
		Handler: shttp.HandlerFunc(func(w shttp.ResponseWriter, r *shttp.Request) {
			w.WriteHeader(200)
		}),
	}
	go srv.Serve(conn)
	t.Cleanup(func() { srv.Close(); conn.Close() })
	return conn.LocalAddr().(*net.UDPAddr)
}

// firstFlight connects through a relay and returns the client's Initial
// packets in the order they were sent.
func firstFlight(t *testing.T, network string, ip net.IP, drop int) []initialPacket {
	t.Helper()
	server := startLocalH3Server(t, network, ip)
	if server == nil {
		t.Skipf("no %s loopback to listen on", network)
	}
	relay := startQUICRelay(t, network, server, drop)

	tr, err := NewHTTP3Transport(fingerprint.Get("chrome-latest"), dns.NewCache())
	if err != nil {
		t.Fatal(err)
	}
	tr.SetInsecureSkipVerify(true)
	tr.SetDisableECH(true)
	defer tr.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := tr.Connect(ctx, ip.String(), strconv.Itoa(relay.addr.Port)); err != nil {
		t.Fatalf("QUIC handshake through the relay failed: %v", err)
	}

	sent, at := relay.datagrams()
	// Initial keys come from the destination connection ID of the client's
	// first packet and stay with the connection after the server picks a new
	// one.
	var keys *initialOpener
	opener := func(dcid []byte) *initialOpener {
		if keys == nil {
			keys = clientInitialOpener(t, dcid)
		}
		return keys
	}
	var out []initialPacket
	for i, d := range sent {
		if p, ok := parseInitial(t, d, opener); ok {
			p.sentAfter = at[i]
			out = append(out, p)
		}
	}
	return out
}

// The ClientHello's own length, from its handshake header. The header can be
// split over several CRYPTO frames, so the first four bytes are gathered from
// wherever they landed.
func helloLength(t *testing.T, packets []initialPacket) int {
	t.Helper()
	var hdr [4]byte
	found := 0
	for _, p := range packets {
		for off, data := range walkInitial(t, p.payload).crypto {
			for j := range data {
				if pos := int(off) + j; pos < 4 {
					hdr[pos] = data[j]
					found |= 1 << pos
				}
			}
		}
	}
	if found != 0xf {
		t.Fatal("the ClientHello's handshake header is not in the captured Initials")
	}
	return 4 + (int(hdr[1])<<16 | int(hdr[2])<<8 | int(hdr[3]))
}

// ------------------------------------------------------------ the locks

// Chrome's first flight for a ClientHello that needs two packets: full-size
// datagrams, 1-byte packet numbers, the head and the tail of the hello in the
// first packet and the middle in the second, and inside each one CRYPTO frames
// split at random points with PING frames and padding scattered between them.
// It used to be equal 75-byte CRYPTO pieces, a PING after every second one,
// and 2-byte packet numbers.
func TestQUICFirstFlightLooksLikeChrome(t *testing.T) {
	packets := firstFlight(t, "udp4", net.IPv4(127, 0, 0, 1), 0)
	if len(packets) < 2 {
		t.Fatalf("got %d Initial packets, want the ClientHello across at least 2", len(packets))
	}
	w := helloLength(t, packets[:2])
	first, second := walkInitial(t, packets[0].payload), walkInitial(t, packets[1].payload)

	for i, p := range packets[:2] {
		if p.datagram != 1250 {
			t.Errorf("Initial %d went out in a %d-byte datagram, want 1250", i+1, p.datagram)
		}
		if p.pnLen != 1 {
			t.Errorf("Initial %d has a %d-byte packet number, want 1", i+1, p.pnLen)
		}
	}
	if packets[0].pn != 1 || packets[1].pn != 2 {
		t.Errorf("packet numbers %d, %d; want 1, 2", packets[0].pn, packets[1].pn)
	}

	// Head and tail in the first packet, the middle in the second, all of
	// it exactly once.
	covered := make([]int, w)
	cover := func(f initialFrames) (lo, hi int) {
		lo, hi = w, 0
		for off, data := range f.crypto {
			for j := range data {
				covered[int(off)+j]++
			}
			lo, hi = min(lo, int(off)), max(hi, int(off)+len(data))
		}
		return lo, hi
	}
	lo1, hi1 := cover(first)
	lo2, hi2 := cover(second)
	for j, n := range covered {
		if n != 1 {
			t.Fatalf("ClientHello byte %d of %d went out %d times in the first two packets", j, w, n)
		}
	}
	if lo1 != 0 || hi1 != w {
		t.Errorf("first packet covers [%d, %d), want the head and the tail of the %d-byte hello", lo1, hi1, w)
	}
	head := 0
	for covered := true; covered; {
		covered = false
		for off, data := range first.crypto {
			if int(off) == head {
				head += len(data)
				covered = true
			}
		}
	}
	if head < 55 || head > 86 {
		t.Errorf("first packet starts with %d contiguous bytes of the hello, want 55 to 86", head)
	}
	if lo2 != head || hi2 >= w {
		t.Errorf("second packet covers [%d, %d), want the middle from %d", lo2, hi2, head)
	}

	for i, f := range []initialFrames{first, second} {
		if len(f.crypto) < 3 {
			t.Errorf("Initial %d carries %d CRYPTO frames; chaos protection splits at least twice", i+1, len(f.crypto))
		}
		if f.pings < 2 || f.pings > 10 {
			t.Errorf("Initial %d carries %d PINGs, want 2 to 10", i+1, f.pings)
		}
		if f.pad == 0 {
			t.Errorf("Initial %d carries no padding", i+1)
		}
	}
}

// Over IPv6 Chrome's packets are 20 bytes shorter: 1230.
func TestQUICFirstFlightOverIPv6(t *testing.T) {
	packets := firstFlight(t, "udp6", net.IPv6loopback, 0)
	if len(packets) == 0 {
		t.Fatal("no Initial packets captured")
	}
	for i, p := range packets {
		if p.datagram != 1230 {
			t.Errorf("Initial %d over IPv6 went out in a %d-byte datagram, want 1230", i+1, p.datagram)
		}
	}
}

// With the first flight lost, the ClientHello goes out again one PTO later,
// which before any RTT sample is three times the initial RTT: 300ms. It was
// 200ms.
func TestQUICFirstRetransmissionAfter300ms(t *testing.T) {
	packets := firstFlight(t, "udp4", net.IPv4(127, 0, 0, 1), 2)
	// The first flight leaves in one burst; the retransmission is the first
	// Initial after it.
	burstEnd := 1
	for burstEnd < len(packets) && packets[burstEnd].sentAfter-packets[0].sentAfter < 50*time.Millisecond {
		burstEnd++
	}
	if burstEnd != 2 {
		t.Fatalf("the first flight was %d packets; this lock drops exactly the first 2", burstEnd)
	}
	if burstEnd == len(packets) {
		t.Fatal("no retransmission after the lost first flight")
	}
	gap := packets[burstEnd].sentAfter - packets[burstEnd-1].sentAfter
	if gap < 280*time.Millisecond || gap > 450*time.Millisecond {
		t.Errorf("first retransmission %v after the first flight, want about 300ms", gap)
	}
}

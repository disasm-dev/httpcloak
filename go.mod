module github.com/sardanioss/httpcloak

go 1.26.0

retract (
	v1.6.9 // Tagged from a pre-fix commit: TLS verification fails open. Use v1.6.10.
	v1.4.0 // Published prematurely, use v1.1.x instead
	v1.3.0 // Published prematurely, use v1.1.x instead
	v1.2.0 // Published prematurely, use v1.1.x instead
)

require (
	github.com/andybalholm/brotli v1.2.0
	github.com/klauspost/compress v1.18.2
	github.com/miekg/dns v1.1.69
	github.com/sardanioss/http v1.2.0
	github.com/sardanioss/net v1.2.12
	github.com/sardanioss/quic-go v1.2.30
	github.com/sardanioss/udpbara v1.1.0
	github.com/sardanioss/utls v1.10.5
	golang.org/x/net v0.48.0
	golang.org/x/sync v0.19.0
)

require (
	github.com/sardanioss/qpack v0.6.3 // indirect
	golang.org/x/crypto v0.46.0 // indirect
	golang.org/x/mod v0.30.0 // indirect
	golang.org/x/sys v0.39.0 // indirect
	golang.org/x/text v0.32.0 // indirect
	golang.org/x/tools v0.39.0 // indirect
)

// disasm-dev's forks carrying the Chrome-parity fixes. A replace only holds in
// the module that declares it, so a project using this fork needs the same
// three in its own go.mod (see README).
replace (
	github.com/sardanioss/net => github.com/disasm-dev/net v1.2.1200
	github.com/sardanioss/quic-go => github.com/disasm-dev/quic-go v1.2.3000
	github.com/sardanioss/utls => github.com/disasm-dev/utls v1.10.500
)

package transport

import "testing"

// Amazon answers its turbo weblab POST with a 204 that still says Content-Encoding: gzip.
func TestDecompressEmptyBody(t *testing.T) {
	for _, encoding := range []string{"gzip", "br", "zstd", "deflate"} {
		body, err := decompress(nil, encoding)
		if err != nil || len(body) != 0 {
			t.Errorf("%s: got %q, %v; want an empty body and no error", encoding, body, err)
		}
	}
}

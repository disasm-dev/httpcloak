package fingerprint

import "testing"

// BoringSSL reports a resumed ticket's age in whole seconds and NSS to the
// millisecond, so the setting follows the TLS stack behind each profile:
// Chromium on every platform and Apple's stack (Safari, and Chrome on iOS)
// are BoringSSL, Firefox is NSS.
func TestTLSTicketAgeWholeSecondsFollowsTheTLSStack(t *testing.T) {
	for name, want := range map[string]bool{
		"chrome-latest":      true,
		"chrome-152-windows": true,
		"chrome-146-android": true,
		"chrome-146-ios":     true,
		"safari-18":          true,
		"safari-18-ios":      true,
		"firefox-133":        false,
		"firefox-148":        false,
	} {
		p := Get(name)
		if p == nil {
			t.Fatalf("preset %s missing", name)
		}
		if got := p.TLSTicketAgeWholeSeconds(); got != want {
			t.Errorf("%s: TLSTicketAgeWholeSeconds = %v, want %v", name, got, want)
		}
	}
}

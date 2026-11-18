package datadome

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestClassify(t *testing.T) {
	cases := []struct {
		name string
		body string
		want Kind
	}{
		{"json interstitial", `{"url":"https://geo.captcha-delivery.com/interstitial/?initialCid=a&hash=b&cid=c&dm=jd"}`, Interstitial},
		{"json captcha", `{"url":"https://geo.captcha-delivery.com/captcha/?initialCid=a&hash=b&cid=c&t=fe&dm=cd"}`, Captcha},
		{"json hard block", `{"url":"https://geo.captcha-delivery.com/captcha/?initialCid=a&hash=b&cid=c&t=bv&dm=cd"}`, HardBlock},
		{"html interstitial", `<html><script>var dd={'rt':'i','cid':'a','hsh':'b','b':1,'s':2,'e':'x'}</script><script src="https://ct.captcha-delivery.com/i.js"></script></html>`, Interstitial},
		{"html captcha", `<html><script>var dd={'rt':'c','cid':'a','hsh':'b','t':'fe','host':'geo.captcha-delivery.com'}</script><script src="https://ct.captcha-delivery.com/c.js"></script></html>`, Captcha},
		{"html hard block", `<html><script>var dd={'rt':'c','cid':'a','hsh':'b','t':'bv','host':'geo.captcha-delivery.com'}</script><script src="https://ct.captcha-delivery.com/c.js"></script></html>`, HardBlock},
		{"ordinary 403", `<html><body>Forbidden</body></html>`, NotBlocked},
		{"other json", `{"error":"forbidden"}`, NotBlocked},
		{"json url elsewhere", `{"url":"https://example.com/login"}`, NotBlocked},
	}
	for _, c := range cases {
		if got := Classify([]byte(c.body)); got != c.want {
			t.Errorf("%s: Classify = %v, want %v", c.name, got, c.want)
		}
	}
}

func TestMayBeBlock(t *testing.T) {
	cases := []struct {
		status int
		ct     string
		want   bool
	}{
		{200, "text/html", false},
		{403, "text/html; charset=utf-8", true},
		{403, "application/json", true},
		{403, "", true},
		{403, "image/png", false},
		{503, "text/plain", true},
	}
	for _, c := range cases {
		headers := map[string][]string{}
		if c.ct != "" {
			headers["Content-Type"] = []string{c.ct}
		}
		if got := MayBeBlock(c.status, headers); got != c.want {
			t.Errorf("MayBeBlock(%d, %q) = %v, want %v", c.status, c.ct, got, c.want)
		}
	}
}

const navigationBlock = `<html><head><script>var dd={'rt':'i','cid':'AHrlqA~~','hsh':'14D062F60A4BDE8CE8647DFC720349','b':1291887,'s':45568,'e':'f3a8/b+c','qp':'','host':'geo.captcha-delivery.com','cookie':'abc'}</script>` +
	`<script data-cfasync="false" src="https://ct.captcha-delivery.com/i.js"></script></head></html>`

// The navigation link is i.js's: escaped ids, the jar's cookie, the blocked
// page as referer, s and b raw, e escaped, display mode cd.
func TestDeviceCheckLinkForANavigation(t *testing.T) {
	link, err := deviceCheckLink([]byte(navigationBlock), "jar~cookie", "https://shop.example/p/1?x=1", "", false)
	if err != nil {
		t.Fatal(err)
	}
	want := "https://geo.captcha-delivery.com/interstitial/?initialCid=AHrlqA~~&hash=14D062F60A4BDE8CE8647DFC720349" +
		"&cid=jar~cookie&referer=https%3A%2F%2Fshop.example%2Fp%2F1%3Fx%3D1&s=45568&e=f3a8%2Fb%2Bc&b=1291887&dm=cd"
	if link != want {
		t.Errorf("link\n got %s\nwant %s", link, want)
	}
}

// An HTML block on an XHR is built by tags.js: raw ids, its own order, the
// page the XHR ran on as referer, display mode jd.
func TestDeviceCheckLinkForAnXHR(t *testing.T) {
	link, err := deviceCheckLink([]byte(navigationBlock), "jarcookie", "https://shop.example/api/cart", "https://shop.example/p/1", true)
	if err != nil {
		t.Fatal(err)
	}
	want := "https://geo.captcha-delivery.com/interstitial/?initialCid=AHrlqA~~&hash=14D062F60A4BDE8CE8647DFC720349" +
		"&s=45568&referer=https%3A%2F%2Fshop.example%2Fp%2F1&e=f3a8/b+c&b=1291887&cid=jarcookie&dm=jd"
	if link != want {
		t.Errorf("link\n got %s\nwant %s", link, want)
	}

	if _, err := deviceCheckLink([]byte(navigationBlock), "c", "https://shop.example/api/cart", "", true); err == nil {
		t.Error("an HTML block on an XHR with no page must fail, not guess the referer")
	}
}

func TestDeviceCheckLinkFromAJSONBlock(t *testing.T) {
	const want = "https://geo.captcha-delivery.com/interstitial/?initialCid=a&hash=b&cid=c&referer=https%3A%2F%2Fx&dm=jd"
	link, err := deviceCheckLink([]byte(`{"url":"`+want+`"}`), "ignored", "https://x/api", "", true)
	if err != nil || link != want {
		t.Errorf("link = %q, %v; want %q", link, err, want)
	}
}

// The captcha link is c.js's: dd.host with its hyphens unescaped, dd.cookie
// over the jar's, and the optional cp pair last. The dd object nests cp, which
// the object reader has to get past.
func TestCaptchaLink(t *testing.T) {
	block := `<script>var dd={'rt':'c','cid':'AHrl~','hsh':'HASH','t':'fe','s':17434,'e':'abc','host':'geo.captcha&#x2d;delivery.com','cookie':'ddcookie','cp':{'name':'x-cp','value':'v 1'}}</script>` +
		`<script src="https://ct.captcha-delivery.com/c.js"></script>`
	link, err := captchaLink([]byte(block), "jar", "https://shop.example/")
	if err != nil {
		t.Fatal(err)
	}
	want := "https://geo.captcha-delivery.com/captcha/?initialCid=AHrl~&hash=HASH&cid=ddcookie&t=fe" +
		"&referer=https%3A%2F%2Fshop.example%2F&s=17434&e=abc&dm=cd&x-cp=v%201"
	if link != want {
		t.Errorf("link\n got %s\nwant %s", link, want)
	}
}

func TestIdentityLanguage(t *testing.T) {
	cases := map[string]string{
		"en-US,en;q=0.9":             "en-US",
		"en-GB,en-US;q=0.9,en;q=0.8": "en-GB",
		"fr-FR;q=1":                  "fr-FR",
		"":                           DefaultLanguage,
	}
	for header, want := range cases {
		if got := (Identity{AcceptLanguage: header}).language(); got != want {
			t.Errorf("language(%q) = %q, want %q", header, got, want)
		}
	}
}

func TestEscapeDataString(t *testing.T) {
	if got, want := escapeDataString("a b/c?d=e&f~g_h.i-j+k"), "a%20b%2Fc%3Fd%3De%26f~g_h.i-j%2Bk"; got != want {
		t.Errorf("escapeDataString = %q, want %q", got, want)
	}
}

// A refusal carries the API's own message, and success: false on a 200 is a
// refusal too.
func TestAPIRefusal(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("x-api-key") != "key-1" {
			t.Errorf("x-api-key = %q", r.Header.Get("x-api-key"))
		}
		if r.URL.Path == "/captcha" {
			w.Write([]byte(`{"success":false,"error":"captcha unsolvable"}`))
			return
		}
		w.WriteHeader(http.StatusForbidden)
		w.Write([]byte(`{"success":false,"error":"site not approved"}`))
	}))
	defer srv.Close()
	a := &api{base: srv.URL, key: "key-1", client: srv.Client()}

	_, err := a.interstitial(context.Background(), interstitialRequest{})
	var apiErr *APIError
	if !errors.As(err, &apiErr) || apiErr.StatusCode != 403 || apiErr.Message != "site not approved" {
		t.Fatalf("err = %v, want a 403 APIError carrying the message", err)
	}
	_, err = a.captcha(context.Background(), captchaRequest{})
	if !errors.As(err, &apiErr) || !strings.Contains(err.Error(), "captcha unsolvable") {
		t.Fatalf("err = %v, want success:false read as a refusal", err)
	}
}

package datadome

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"
)

// Chrome's navigation and image Accept, used when the session's preset names
// neither.
const (
	defaultNavigationAccept = "text/html,application/xhtml+xml,application/xml;q=0.9,image/jxl,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7"
	defaultImageAccept      = "image/jxl,image/avif,image/webp,image/apng,image/svg+xml,image/*,*/*;q=0.8"
	acceptEncoding          = "gzip, deflate, br, zstd"
)

// Current builds load the challenge bundle from an external <script src>
// instead of inlining it; the API needs those bytes, so the page's script is
// fetched the way Chrome fetches it. Only the versioned bundle matches, so an
// older inline page or a loader such as i.js or c.js is not mistaken for it.
var (
	interstitialScriptRe = regexp.MustCompile(`<script[^>]+src="(https://ct\.captcha-delivery\.com/interstitial\.[0-9][0-9A-Za-z.]*\.js)"`)
	captchaScriptRe      = regexp.MustCompile(`<script[^>]+src="(https://ct\.captcha-delivery\.com/captcha\.[0-9][0-9A-Za-z.]*\.js)"`)
	ddObjectRe           = regexp.MustCompile(`var dd\s*=\s*\{`)
	sliderRe             = regexp.MustCompile(`sliderCaptcha\(\s*\{`)
)

// result is DataDome's answer to a submitted payload: the cookie to keep, and
// for the interstitial what to do next.
type result struct {
	Cookie string `json:"cookie"`
	View   string `json:"view"`
	URL    string `json:"url"`
}

// --- interstitial -----------------------------------------------------------

// solveInterstitial follows docs.disasm.dev/datadome/interstitial: build the
// device-check link from the block, load that page as the browser's iframe
// would, hand both to the API, POST the payload back and keep the datadome
// cookie it answers with. Header blocks are transcribed from a recorded
// Chrome session.
func (s *Solver) solveInterstitial(ctx context.Context, b *Block, id Identity) (*Outcome, error) {
	link, err := deviceCheckLink(b.Body, s.browser.Cookie(b.URL), b.URL, b.PageURL, b.XHR)
	if err != nil {
		return nil, err
	}
	linkOrigin := originOf(link)

	page, err := s.get(ctx, "device-check page", link, iframeHeaders(id, originOf(b.URL)+"/"))
	if err != nil {
		return nil, err
	}
	var script string
	if m := interstitialScriptRe.FindSubmatch(page); m != nil {
		body, err := s.get(ctx, "challenge script", string(m[1]), scriptHeaders(id, linkOrigin+"/"))
		if err != nil {
			return nil, err
		}
		script = base64.StdEncoding.EncodeToString(body)
	}
	ip, err := s.exitIP(ctx, id)
	if err != nil {
		return nil, err
	}
	solved, err := s.api.interstitial(ctx, interstitialRequest{
		DeviceCheckLink:   link,
		DeviceCheckPage:   base64.StdEncoding.EncodeToString(page),
		DeviceCheckScript: script,
		Language:          id.language(),
		UserAgent:         id.UserAgent,
		IPAddress:         ip,
	})
	if err != nil {
		return nil, err
	}
	if err := s.adopt(solved.Headers, id); err != nil {
		return nil, err
	}

	// The payload goes on the wire byte for byte as the API returned it.
	reply, err := s.browser.Send(ctx, &Request{
		Method:  http.MethodPost,
		URL:     linkOrigin + "/interstitial/",
		Headers: interstitialPostHeaders(id, linkOrigin, link, len(solved.Payload)),
		Body:    solved.Payload,
	})
	if err != nil {
		return nil, fmt.Errorf("interstitial POST: %w", err)
	}
	res, err := readResult("interstitial POST", reply)
	if err != nil {
		return nil, err
	}
	if res.View == "captcha" {
		// Not a failure to give up on: the docs read it as something about
		// the request being off and say to start over. The caller sends the
		// blocked request again; its block replaces the flagged cookie in the
		// jar and whatever comes back is answered in turn.
		return &Outcome{Escalated: true}, nil
	}
	if err := s.store(b.URL, res.Cookie); err != nil {
		return nil, err
	}
	out := &Outcome{}
	if res.View == "redirect" {
		out.RedirectURL = res.URL
	}
	return out, nil
}

// deviceCheckLink is the iframe URL the browser would load for an
// interstitial. A JSON block (an XHR the page made) carries it finished; an
// HTML block carries the dd object the page's script builds it from.
func deviceCheckLink(body []byte, cookie, blockedURL, pageURL string, xhr bool) (string, error) {
	if link, ok := jsonBlockURL(body); ok {
		return link.String(), nil
	}
	dd, err := ddObject(body)
	if err != nil {
		return "", fmt.Errorf("interstitial block: %w", err)
	}
	cid, hsh := ddValue(dd, "cid"), ddValue(dd, "hsh")
	if cid == "" || hsh == "" {
		return "", errors.New("interstitial block: the dd object has no cid or hsh")
	}
	if xhr {
		if pageURL == "" {
			return "", fmt.Errorf("blocked XHR to %s has no Referer naming the page it ran on; set one", blockedURL)
		}
		// An HTML block on an XHR is turned into the link by the page's
		// tags.js, not i.js: its own order, raw ids, the page as referer and
		// display mode jd. A parameter the dd object has no value for is left
		// out.
		var link strings.Builder
		link.WriteString(geoOrigin + "/interstitial/?initialCid=" + cid + "&hash=" + hsh)
		optionalParam(&link, dd, "t")
		optionalParam(&link, dd, "s")
		link.WriteString("&referer=" + escapeDataString(pageURL))
		optionalParam(&link, dd, "e")
		optionalParam(&link, dd, "b")
		link.WriteString("&cid=" + cookie + "&dm=jd")
		return link.String(), nil
	}
	// i.js, parameter order as recorded.
	return geoOrigin + "/interstitial/?initialCid=" + escapeDataString(cid) +
		"&hash=" + escapeDataString(hsh) +
		"&cid=" + escapeDataString(cookie) +
		"&referer=" + escapeDataString(blockedURL) +
		"&s=" + ddValue(dd, "s") +
		"&e=" + escapeDataString(ddValue(dd, "e")) +
		"&b=" + ddValue(dd, "b") +
		"&dm=cd", nil
}

func optionalParam(link *strings.Builder, dd map[string]any, key string) {
	if v := ddValue(dd, key); v != "" {
		link.WriteString("&" + key + "=" + v)
	}
}

// --- captcha ----------------------------------------------------------------

// solveCaptcha follows docs.disasm.dev/datadome/slider-captcha: build the
// captcha link from the block, load that page as the browser's iframe would,
// download the puzzle's two images, hand all of it to the API, GET the submit
// URL it answers with and keep the datadome cookie that comes back.
//
// No captcha was served in the recorded session, so unlike the interstitial
// the image and submit header blocks are reconstructed from what Chrome sends
// for an image subresource and a same-origin XHR.
func (s *Solver) solveCaptcha(ctx context.Context, b *Block, id Identity) (*Outcome, error) {
	link, err := captchaLink(b.Body, s.browser.Cookie(b.URL), b.URL)
	if err != nil {
		return nil, err
	}
	page, err := s.get(ctx, "captcha page", link, iframeHeaders(id, originOf(b.URL)+"/"))
	if err != nil {
		return nil, err
	}
	var script string
	if m := captchaScriptRe.FindSubmatch(page); m != nil {
		body, err := s.get(ctx, "captcha script", string(m[1]), scriptHeaders(id, originOf(link)+"/"))
		if err != nil {
			return nil, err
		}
		script = base64.StdEncoding.EncodeToString(body)
	}
	background, fragment, err := s.puzzleImages(ctx, page, link, id)
	if err != nil {
		return nil, err
	}
	ip, err := s.exitIP(ctx, id)
	if err != nil {
		return nil, err
	}
	solved, err := s.api.captcha(ctx, captchaRequest{
		Type:            "image",
		CaptchaLink:     link,
		HTML:            base64.StdEncoding.EncodeToString(page),
		CaptchaScript:   script,
		BackgroundImage: background,
		FragmentImage:   fragment,
		Language:        id.language(),
		UserAgent:       id.UserAgent,
		IPAddress:       ip,
	})
	if err != nil {
		return nil, err
	}
	if err := s.adopt(solved.Headers, id); err != nil {
		return nil, err
	}
	reply, err := s.browser.Send(ctx, &Request{
		Method:  http.MethodGet,
		URL:     solved.CaptchaSubmitURL,
		Headers: captchaSubmitHeaders(id, link),
	})
	if err != nil {
		return nil, fmt.Errorf("captcha submit: %w", err)
	}
	res, err := readResult("captcha submit", reply)
	if err != nil {
		return nil, err
	}
	if err := s.store(b.URL, res.Cookie); err != nil {
		return nil, err
	}
	return &Outcome{}, nil
}

// captchaLink is the iframe URL the browser would load for a captcha,
// transcribed from c.js: the host is dd.host (its hyphens arrive
// HTML-escaped), cid is dd.cookie and only reads the jar when the block
// carries none, s and e go on raw because the script encodes neither, and
// the optional dd.cp pair goes last.
func captchaLink(body []byte, cookie, blockedURL string) (string, error) {
	if link, ok := jsonBlockURL(body); ok {
		return link.String(), nil
	}
	dd, err := ddObject(body)
	if err != nil {
		return "", fmt.Errorf("captcha block: %w", err)
	}
	host := strings.ReplaceAll(ddValue(dd, "host"), "&#x2d;", "-")
	if host == "" {
		return "", errors.New("captcha block: the dd object has no host")
	}
	cid, hsh := ddValue(dd, "cid"), ddValue(dd, "hsh")
	if cid == "" || hsh == "" {
		return "", errors.New("captcha block: the dd object has no cid or hsh")
	}
	if c := ddValue(dd, "cookie"); c != "" {
		cookie = c
	}
	link := "https://" + host + "/captcha/?initialCid=" + escapeDataString(cid) +
		"&hash=" + escapeDataString(hsh) +
		"&cid=" + escapeDataString(cookie) +
		"&t=" + escapeDataString(ddValue(dd, "t")) +
		"&referer=" + escapeDataString(blockedURL) +
		"&s=" + ddValue(dd, "s") + "&e=" + ddValue(dd, "e") + "&dm=cd"
	if cp, ok := dd["cp"].(map[string]any); ok {
		name, value := ddValue(cp, "name"), ddValue(cp, "value")
		if name != "" && cp["value"] != nil {
			link += "&" + escapeDataString(name) + "=" + escapeDataString(value)
		}
	}
	return link, nil
}

// puzzleImages downloads the slider's two images as base64 of the bytes on
// the wire. noPuzzle means there is nothing to line up and the API works
// from the page alone; otherwise the background is the challenge path and
// the fragment is the same file with its extension swapped.
func (s *Solver) puzzleImages(ctx context.Context, page []byte, link string, id Identity) (string, string, error) {
	slider, err := jsObject(page, sliderRe)
	if err != nil {
		return "", "", fmt.Errorf("captcha page: no sliderCaptcha object: %w", err)
	}
	if noPuzzle, _ := slider["noPuzzle"].(bool); noPuzzle {
		return "", "", nil
	}
	backgroundURL := ddValue(slider, "captchaChallengePath")
	if backgroundURL == "" {
		return "", "", errors.New("captcha puzzle has no challenge path")
	}
	fragmentURL := strings.Replace(backgroundURL, ".jpg", ".frag.png", 1)

	var images [2]string
	for i, u := range []string{backgroundURL, fragmentURL} {
		body, err := s.get(ctx, "captcha image", u, imageHeaders(id, link))
		if err != nil {
			return "", "", err
		}
		if len(body) == 0 {
			return "", "", fmt.Errorf("captcha image came back empty: %s", u)
		}
		images[i] = base64.StdEncoding.EncodeToString(body)
	}
	return images[0], images[1], nil
}

// --- shared -----------------------------------------------------------------

// store keeps the datadome cookie from a Set-Cookie line DataDome handed back
// in a JSON field, e.g. "datadome=...; Max-Age=31536000; Domain=.example.com;
// Path=/; Secure; SameSite=Lax". It goes in as though the blocked site had set
// it, because the line names the site's domain, not DataDome's.
func (s *Solver) store(blockedURL, setCookie string) error {
	if !strings.HasPrefix(strings.TrimSpace(setCookie), "datadome=") {
		return fmt.Errorf("DataDome answered without a usable cookie: %q", truncate(setCookie, 120))
	}
	return s.browser.StoreCookie(blockedURL, setCookie)
}

func readResult(what string, reply *Reply) (*result, error) {
	if reply.Status != http.StatusOK {
		return nil, fmt.Errorf("%s answered [%d] %s", what, reply.Status, truncate(string(reply.Body), 200))
	}
	var res result
	if err := json.Unmarshal(reply.Body, &res); err != nil {
		return nil, fmt.Errorf("%s answered something that is not JSON: %w", what, err)
	}
	return &res, nil
}

// jsonBlockURL reads the challenge URL from a JSON block, the shape an XHR is
// blocked with: {"url":"https://geo.captcha-delivery.com/captcha/?..."}.
func jsonBlockURL(body []byte) (*url.URL, bool) {
	trimmed := bytes.TrimSpace(body)
	if !bytes.HasPrefix(trimmed, []byte(`{"url":"`)) {
		return nil, false
	}
	var block struct {
		URL string `json:"url"`
	}
	if json.Unmarshal(trimmed, &block) != nil || block.URL == "" {
		return nil, false
	}
	link, err := url.Parse(block.URL)
	if err != nil || link.Host == "" {
		return nil, false
	}
	return link, true
}

// ddObject reads the page's `var dd = {...}`, the block's parameters.
func ddObject(body []byte) (map[string]any, error) {
	return jsObject(body, ddObjectRe)
}

// jsObject reads the object literal that opens where re matches. The pages
// write it with single quotes, which are swapped for double ones as the
// browser-side reference implementation does. The object can nest (dd.cp),
// so its end is found by counting braces outside strings.
func jsObject(body []byte, re *regexp.Regexp) (map[string]any, error) {
	loc := re.FindIndex(body)
	if loc == nil {
		return nil, errors.New("no object found")
	}
	start := loc[1] - 1 // the opening brace
	depth := 0
	var quote byte
	end := -1
	for i := start; i < len(body) && end < 0; i++ {
		c := body[i]
		switch {
		case quote != 0:
			if c == '\\' {
				i++
			} else if c == quote {
				quote = 0
			}
		case c == '\'' || c == '"':
			quote = c
		case c == '{':
			depth++
		case c == '}':
			depth--
			if depth == 0 {
				end = i + 1
			}
		}
	}
	if end < 0 {
		return nil, errors.New("the object never closes")
	}
	literal := bytes.ReplaceAll(body[start:end], []byte("'"), []byte(`"`))
	dec := json.NewDecoder(bytes.NewReader(literal))
	dec.UseNumber()
	var obj map[string]any
	if err := dec.Decode(&obj); err != nil {
		return nil, err
	}
	return obj, nil
}

// ddValue is a dd field as the page's script writes it into a URL: a string
// as it is, a number as its digits.
func ddValue(dd map[string]any, key string) string {
	switch v := dd[key].(type) {
	case nil:
		return ""
	case string:
		return v
	case json.Number:
		return v.String()
	case bool:
		return strconv.FormatBool(v)
	default:
		return fmt.Sprint(v)
	}
}

// escapeDataString percent-encodes everything but RFC 3986's unreserved
// characters, as encodeURIComponent and .NET's Uri.EscapeDataString do (Go's
// QueryEscape writes a space as +, which these links never carry).
func escapeDataString(s string) string {
	const hex = "0123456789ABCDEF"
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		c := s[i]
		if 'A' <= c && c <= 'Z' || 'a' <= c && c <= 'z' || '0' <= c && c <= '9' || c == '-' || c == '.' || c == '_' || c == '~' {
			b.WriteByte(c)
			continue
		}
		b.WriteByte('%')
		b.WriteByte(hex[c>>4])
		b.WriteByte(hex[c&15])
	}
	return b.String()
}

// --- header blocks ----------------------------------------------------------
//
// DataDome's own origins never send Accept-CH, so only the three low-entropy
// hints travel to them.

// iframeHeaders is the cross-site iframe navigation that loads a challenge
// page (HTTP/1.1, recorded).
func iframeHeaders(id Identity, referer string) []Header {
	return []Header{
		{"Connection", "keep-alive"},
		{"sec-ch-ua", id.SecChUa},
		{"sec-ch-ua-mobile", id.SecChUaMobile},
		{"sec-ch-ua-platform", id.SecChUaPlatform},
		{"Upgrade-Insecure-Requests", "1"},
		{"User-Agent", id.UserAgent},
		{"Accept", or(id.Accept, defaultNavigationAccept)},
		{"Sec-Fetch-Site", "cross-site"},
		{"Sec-Fetch-Mode", "navigate"},
		{"Sec-Fetch-Dest", "iframe"},
		{"Sec-Fetch-Storage-Access", "none"},
		{"Referer", referer},
		{"Accept-Encoding", acceptEncoding},
		{"Accept-Language", id.acceptLanguage()},
	}
}

// scriptHeaders is the iframe's <script src> for the challenge bundle
// (HTTP/2 to ct.captcha-delivery.com, recorded).
func scriptHeaders(id Identity, referer string) []Header {
	return []Header{
		{"sec-ch-ua-platform", id.SecChUaPlatform},
		{"user-agent", id.UserAgent},
		{"sec-ch-ua", id.SecChUa},
		{"sec-ch-ua-mobile", id.SecChUaMobile},
		{"accept", "*/*"},
		{"sec-fetch-site", "same-site"},
		{"sec-fetch-mode", "no-cors"},
		{"sec-fetch-dest", "script"},
		{"sec-fetch-storage-access", "none"},
		{"referer", referer},
		{"accept-encoding", acceptEncoding},
		{"accept-language", id.acceptLanguage()},
	}
}

// interstitialPostHeaders is the page's XHR that submits the payload
// (HTTP/1.1, recorded).
func interstitialPostHeaders(id Identity, origin, link string, length int) []Header {
	return []Header{
		{"Connection", "keep-alive"},
		{"Content-Length", strconv.Itoa(length)},
		{"sec-ch-ua-platform", id.SecChUaPlatform},
		{"User-Agent", id.UserAgent},
		{"sec-ch-ua", id.SecChUa},
		{"Content-Type", "application/x-www-form-urlencoded; charset=UTF-8"},
		{"sec-ch-ua-mobile", id.SecChUaMobile},
		{"Accept", "*/*"},
		{"Origin", origin},
		{"Sec-Fetch-Site", "same-origin"},
		{"Sec-Fetch-Mode", "cors"},
		{"Sec-Fetch-Dest", "empty"},
		{"Sec-Fetch-Storage-Access", "none"},
		{"Referer", link},
		{"Accept-Encoding", acceptEncoding},
		{"Accept-Language", id.acceptLanguage()},
	}
}

// imageHeaders is a puzzle image load inside the captcha iframe.
func imageHeaders(id Identity, referer string) []Header {
	return []Header{
		{"Connection", "keep-alive"},
		{"sec-ch-ua", id.SecChUa},
		{"sec-ch-ua-mobile", id.SecChUaMobile},
		{"sec-ch-ua-platform", id.SecChUaPlatform},
		{"User-Agent", id.UserAgent},
		{"Accept", or(id.ImageAccept, defaultImageAccept)},
		{"Sec-Fetch-Site", "cross-site"},
		{"Sec-Fetch-Mode", "no-cors"},
		{"Sec-Fetch-Dest", "image"},
		{"Sec-Fetch-Storage-Access", "none"},
		{"Referer", referer},
		{"Accept-Encoding", acceptEncoding},
		{"Accept-Language", id.acceptLanguage()},
	}
}

// captchaSubmitHeaders is the captcha page's XHR that submits the solution.
func captchaSubmitHeaders(id Identity, link string) []Header {
	return []Header{
		{"Connection", "keep-alive"},
		{"sec-ch-ua-platform", id.SecChUaPlatform},
		{"User-Agent", id.UserAgent},
		{"sec-ch-ua", id.SecChUa},
		{"sec-ch-ua-mobile", id.SecChUaMobile},
		{"Accept", "*/*"},
		{"Sec-Fetch-Site", "same-origin"},
		{"Sec-Fetch-Mode", "cors"},
		{"Sec-Fetch-Dest", "empty"},
		{"Sec-Fetch-Storage-Access", "none"},
		{"Referer", link},
		{"Accept-Encoding", acceptEncoding},
		{"Accept-Language", id.acceptLanguage()},
	}
}

func or(v, fallback string) string {
	if v != "" {
		return v
	}
	return fallback
}

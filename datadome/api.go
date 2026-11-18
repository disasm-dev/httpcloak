package datadome

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"time"
)

// DefaultServiceURL is the payload API a Config without a ServiceURL uses.
const DefaultServiceURL = "https://dd.antibotapi.com"

// APIError is a refusal from the payload API: a status other than 200, or a
// 200 whose body says success: false.
type APIError struct {
	Path       string
	StatusCode int
	Message    string
}

func (e *APIError) Error() string {
	msg := e.Message
	if msg == "" {
		msg = http.StatusText(e.StatusCode)
	}
	return fmt.Sprintf("payload API %s answered %d: %s", e.Path, e.StatusCode, msg)
}

type interstitialRequest struct {
	DeviceCheckLink   string `json:"device_check_link"`
	DeviceCheckPage   string `json:"device_check_page"`
	DeviceCheckScript string `json:"device_check_script,omitempty"`
	Language          string `json:"language"`
	UserAgent         string `json:"user_agent"`
	IPAddress         string `json:"ip_address"`
}

type captchaRequest struct {
	Type            string `json:"type"`
	CaptchaLink     string `json:"captcha_link"`
	HTML            string `json:"html"`
	CaptchaScript   string `json:"captcha_script,omitempty"`
	BackgroundImage string `json:"background_image,omitempty"`
	FragmentImage   string `json:"fragment_image,omitempty"`
	Language        string `json:"language"`
	UserAgent       string `json:"user_agent"`
	IPAddress       string `json:"ip_address"`
}

type payloadResponse struct {
	Success          *bool             `json:"success"`
	Error            string            `json:"error"`
	Payload          string            `json:"payload"`
	CaptchaSubmitURL string            `json:"captcha_submit_url"`
	Headers          map[string]string `json:"headers"`
}

// api is the disasm.dev DataDome payload API. Every call is one POST that
// answers synchronously with what to submit to DataDome.
type api struct {
	base      string
	key       string
	jwtSecret string
	client    *http.Client
}

func (a *api) interstitial(ctx context.Context, in interstitialRequest) (*payloadResponse, error) {
	out, err := a.post(ctx, "/interstitial", in)
	if err != nil {
		return nil, err
	}
	if out.Payload == "" {
		return nil, errors.New("payload API /interstitial answered without a payload")
	}
	return out, nil
}

func (a *api) captcha(ctx context.Context, in captchaRequest) (*payloadResponse, error) {
	out, err := a.post(ctx, "/captcha", in)
	if err != nil {
		return nil, err
	}
	if out.CaptchaSubmitURL == "" {
		return nil, errors.New("payload API /captcha answered without a captcha_submit_url")
	}
	return out, nil
}

func (a *api) post(ctx context.Context, path string, in any) (*payloadResponse, error) {
	body, err := json.Marshal(in)
	if err != nil {
		return nil, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, a.base+path, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	if a.key != "" {
		req.Header.Set("x-api-key", a.key)
	}
	if a.jwtSecret != "" {
		req.Header.Set("x-signature", signature(a.key, a.jwtSecret, time.Now()))
	}
	resp, err := a.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("payload API %s: %w", path, err)
	}
	defer resp.Body.Close()
	data, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return nil, fmt.Errorf("payload API %s: %w", path, err)
	}
	var out payloadResponse
	jsonErr := json.Unmarshal(data, &out)
	if resp.StatusCode != http.StatusOK {
		return nil, &APIError{Path: path, StatusCode: resp.StatusCode, Message: refusalMessage(out.Error, data)}
	}
	if jsonErr != nil {
		return nil, fmt.Errorf("payload API %s: %w", path, jsonErr)
	}
	if out.Success != nil && !*out.Success {
		return nil, &APIError{Path: path, StatusCode: resp.StatusCode, Message: refusalMessage(out.Error, data)}
	}
	return &out, nil
}

// refusalMessage is the API's own error text, else the start of the body.
func refusalMessage(msg string, body []byte) string {
	if msg != "" {
		return msg
	}
	if len(body) > 200 {
		return string(body[:200]) + "…"
	}
	return string(body)
}

// signature is the x-signature a key with signing on has to send: an HS256
// JWT, signed with the key's secret, whose x-api-key claim is the key. It
// lives a minute, which covers one call with room for clock skew.
func signature(key, secret string, now time.Time) string {
	enc := base64.RawURLEncoding
	header := enc.EncodeToString([]byte(`{"alg":"HS256","typ":"JWT"}`))
	claims, _ := json.Marshal(map[string]any{
		"x-api-key": key,
		"iat":       now.Unix(),
		"exp":       now.Add(time.Minute).Unix(),
	})
	payload := enc.EncodeToString(claims)
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte(header + "." + payload))
	return header + "." + payload + "." + enc.EncodeToString(mac.Sum(nil))
}

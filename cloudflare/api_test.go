package cloudflare

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"
	"time"
)

// The signature is checked the way disasm-shared/ginauth checks it: HS256 over
// header.payload with the key's JWT secret, the x-api-key claim the key sent,
// and an exp still ahead.
func TestSignatureIsTheJWTTheServiceVerifies(t *testing.T) {
	now := time.Unix(1_800_000_000, 0)
	token := signature("key-1", "secret", now)
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		t.Fatalf("token %q is not three parts", token)
	}
	enc := base64.RawURLEncoding

	var header struct{ Alg string }
	head, _ := enc.DecodeString(parts[0])
	if json.Unmarshal(head, &header) != nil || header.Alg != "HS256" {
		t.Errorf("header %s", head)
	}

	mac := hmac.New(sha256.New, []byte("secret"))
	mac.Write([]byte(parts[0] + "." + parts[1]))
	if got, _ := enc.DecodeString(parts[2]); !hmac.Equal(got, mac.Sum(nil)) {
		t.Error("signature does not verify with the secret")
	}

	var claims map[string]any
	payload, _ := enc.DecodeString(parts[1])
	if err := json.Unmarshal(payload, &claims); err != nil {
		t.Fatal(err)
	}
	if claims["x-api-key"] != "key-1" {
		t.Errorf("x-api-key claim %v", claims["x-api-key"])
	}
	if exp, _ := claims["exp"].(float64); int64(exp) <= now.Unix() {
		t.Errorf("exp %v is not after now", claims["exp"])
	}
}

func TestRefusalReadsBothErrorShapes(t *testing.T) {
	own := refusal(400, []byte(`{"error":"No device sends this User-Agent","user_agents":["ua-1","ua-2"]}`))
	if own.Message != "No device sends this User-Agent" || len(own.UserAgents) != 2 {
		t.Errorf("own refusal read as %+v", own)
	}

	key := refusal(401, []byte(`{"success":false,"error":{"type":"validation","message":"Invalid API key: not found"}}`))
	if key.Message != "Invalid API key: not found" {
		t.Errorf("key refusal read as %+v", key)
	}

	gone := refusal(404, nil)
	if !strings.Contains(gone.Error(), "not held") {
		t.Errorf("a bare 404 reads %q", gone.Error())
	}
}

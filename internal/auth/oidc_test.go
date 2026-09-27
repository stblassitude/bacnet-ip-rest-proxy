package auth

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"math/big"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

const testAudience = "bacnet-proxy"

var b64 = base64.RawURLEncoding.EncodeToString

// fakeIdP serves an OpenID Connect discovery document and a JWKS whose keys
// tests can swap, counting JWKS fetches.
type fakeIdP struct {
	srv        *httptest.Server
	mu         sync.Mutex
	jwks       []map[string]string
	issuerName string // issuer the discovery document claims; defaults to the URL
	fetches    atomic.Int32
}

func newFakeIdP(t *testing.T) *fakeIdP {
	idp := &fakeIdP{}
	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, r *http.Request) {
		idp.mu.Lock()
		name := idp.issuerName
		idp.mu.Unlock()
		if name == "" {
			name = idp.srv.URL
		}
		_ = json.NewEncoder(w).Encode(map[string]string{"issuer": name, "jwks_uri": idp.srv.URL + "/jwks"})
	})
	mux.HandleFunc("/jwks", func(w http.ResponseWriter, r *http.Request) {
		idp.fetches.Add(1)
		idp.mu.Lock()
		defer idp.mu.Unlock()
		_ = json.NewEncoder(w).Encode(map[string]any{"keys": idp.jwks})
	})
	idp.srv = httptest.NewServer(mux)
	t.Cleanup(idp.srv.Close)
	return idp
}

func (idp *fakeIdP) setKeys(jwks ...map[string]string) {
	idp.mu.Lock()
	defer idp.mu.Unlock()
	idp.jwks = jwks
}

func rsaJWK(kid string, k *rsa.PrivateKey) map[string]string {
	return map[string]string{"kty": "RSA", "kid": kid, "use": "sig", "n": b64(k.N.Bytes()), "e": b64(big.NewInt(int64(k.E)).Bytes())}
}

func ecJWK(kid string, k *ecdsa.PrivateKey) map[string]string {
	raw, _ := k.PublicKey.Bytes() // 0x04 || x || y
	size := (len(raw) - 1) / 2
	return map[string]string{"kty": "EC", "kid": kid, "crv": "P-256", "x": b64(raw[1 : 1+size]), "y": b64(raw[1+size:])}
}

func edJWK(kid string, k ed25519.PrivateKey) map[string]string {
	return map[string]string{"kty": "OKP", "kid": kid, "crv": "Ed25519", "x": b64(k.Public().(ed25519.PublicKey))}
}

func sign(t *testing.T, method jwt.SigningMethod, kid string, key crypto.PrivateKey, claims jwt.MapClaims) string {
	t.Helper()
	tok := jwt.NewWithClaims(method, claims)
	if kid != "" {
		tok.Header["kid"] = kid
	}
	s, err := tok.SignedString(key)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func validClaims(iss string) jwt.MapClaims {
	return jwt.MapClaims{
		"iss":   iss,
		"aud":   []string{"account", testAudience},
		"sub":   "sensor-dashboards",
		"group": "admins",
		"exp":   time.Now().Add(time.Hour).Unix(),
		"iat":   time.Now().Unix(),
	}
}

func newRSAKey(t *testing.T) *rsa.PrivateKey {
	k, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	return k
}

func newOIDCAuthenticator(idp *fakeIdP) *Authenticator {
	return NewAuthenticator(Options{Issuers: []Issuer{{URL: idp.srv.URL, Audience: testAudience}}})
}

func TestOIDCAcceptsValidAccessToken(t *testing.T) {
	idp := newFakeIdP(t)
	rsaKey := newRSAKey(t)
	ecKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	_, edKey, _ := ed25519.GenerateKey(rand.Reader)
	idp.setKeys(rsaJWK("rsa", rsaKey), ecJWK("ec", ecKey), edJWK("ed", edKey))
	a := newOIDCAuthenticator(idp)

	for name, token := range map[string]string{
		"RS256": sign(t, jwt.SigningMethodRS256, "rsa", rsaKey, validClaims(idp.srv.URL)),
		"PS256": sign(t, jwt.SigningMethodPS256, "rsa", rsaKey, validClaims(idp.srv.URL)),
		"ES256": sign(t, jwt.SigningMethodES256, "ec", ecKey, validClaims(idp.srv.URL)),
		"EdDSA": sign(t, jwt.SigningMethodEdDSA, "ed", edKey, validClaims(idp.srv.URL)),
	} {
		res := a.Authenticate(context.Background(), token)
		if res.Claims == nil || res.Claims["group"] != "admins" {
			t.Errorf("%s: got %+v, want the token's claims", name, res)
		}
	}
}

func TestOIDCRejectsInvalidTokens(t *testing.T) {
	idp := newFakeIdP(t)
	key := newRSAKey(t)
	idp.setKeys(rsaJWK("k1", key))
	a := newOIDCAuthenticator(idp)
	iss := idp.srv.URL

	with := func(change func(jwt.MapClaims)) jwt.MapClaims {
		c := validClaims(iss)
		change(c)
		return c
	}
	pubPEM := func() []byte {
		der, _ := x509.MarshalPKIXPublicKey(&key.PublicKey)
		return pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der})
	}()
	none, _ := jwt.NewWithClaims(jwt.SigningMethodNone, validClaims(iss)).SignedString(jwt.UnsafeAllowNoneSignatureType)

	cases := map[string]string{
		"wrong audience":      sign(t, jwt.SigningMethodRS256, "k1", key, with(func(c jwt.MapClaims) { c["aud"] = "other-app" })),
		"no audience":         sign(t, jwt.SigningMethodRS256, "k1", key, with(func(c jwt.MapClaims) { delete(c, "aud") })),
		"expired":             sign(t, jwt.SigningMethodRS256, "k1", key, with(func(c jwt.MapClaims) { c["exp"] = time.Now().Add(-2 * time.Minute).Unix() })),
		"no expiry":           sign(t, jwt.SigningMethodRS256, "k1", key, with(func(c jwt.MapClaims) { delete(c, "exp") })),
		"not yet valid":       sign(t, jwt.SigningMethodRS256, "k1", key, with(func(c jwt.MapClaims) { c["nbf"] = time.Now().Add(time.Hour).Unix() })),
		"unconfigured issuer": sign(t, jwt.SigningMethodRS256, "k1", key, with(func(c jwt.MapClaims) { c["iss"] = "https://evil.example.com" })),
		"signed by other key": sign(t, jwt.SigningMethodRS256, "k1", newRSAKey(t), validClaims(iss)),
		"alg none":            none,
		// Algorithm confusion: HMAC "signed" with the issuer's public key.
		"HS256 with public key": sign(t, jwt.SigningMethodHS256, "k1", pubPEM, validClaims(iss)),
	}
	for name, token := range cases {
		if res := a.Authenticate(context.Background(), token); res.Claims != nil {
			t.Errorf("%s: token was accepted: %+v", name, res.Claims)
		}
	}
}

func TestOIDCPicksUpRotatedKey(t *testing.T) {
	idp := newFakeIdP(t)
	oldKey, newKey := newRSAKey(t), newRSAKey(t)
	idp.setKeys(rsaJWK("old", oldKey))
	a := newOIDCAuthenticator(idp)
	a.issuers[idp.srv.URL].minRefresh = 0
	ctx := context.Background()

	if res := a.Authenticate(ctx, sign(t, jwt.SigningMethodRS256, "old", oldKey, validClaims(idp.srv.URL))); res.Claims == nil {
		t.Fatal("token signed with the original key was rejected")
	}
	idp.setKeys(rsaJWK("old", oldKey), rsaJWK("new", newKey))
	if res := a.Authenticate(ctx, sign(t, jwt.SigningMethodRS256, "new", newKey, validClaims(idp.srv.URL))); res.Claims == nil {
		t.Fatal("token signed with the rotated-in key was rejected")
	}
}

func TestOIDCRateLimitsFetchesForUnknownKeyIDs(t *testing.T) {
	idp := newFakeIdP(t)
	key := newRSAKey(t)
	idp.setKeys(rsaJWK("k1", key))
	a := newOIDCAuthenticator(idp)
	ctx := context.Background()
	if res := a.Authenticate(ctx, sign(t, jwt.SigningMethodRS256, "k1", key, validClaims(idp.srv.URL))); res.Claims == nil {
		t.Fatal("valid token was rejected")
	}
	before := idp.fetches.Load()

	for i := range 50 {
		token := sign(t, jwt.SigningMethodRS256, fmt.Sprintf("made-up-%d", i), key, validClaims(idp.srv.URL))
		if res := a.Authenticate(ctx, token); res.Claims != nil {
			t.Fatal("token with an unknown key ID was accepted")
		}
	}
	if extra := idp.fetches.Load() - before; extra > 0 {
		t.Errorf("unknown key IDs caused %d JWKS fetches within the rate limit, want 0", extra)
	}
}

func TestOIDCRejectsDiscoveryForAnotherIssuer(t *testing.T) {
	idp := newFakeIdP(t)
	key := newRSAKey(t)
	idp.setKeys(rsaJWK("k1", key))
	idp.issuerName = "https://someone-else.example.com"
	a := newOIDCAuthenticator(idp)
	if res := a.Authenticate(context.Background(), sign(t, jwt.SigningMethodRS256, "k1", key, validClaims(idp.srv.URL))); res.Claims != nil {
		t.Fatal("token was accepted although discovery named a different issuer")
	}
}

func TestParseJWKRejectsWeakOrInvalidKeys(t *testing.T) {
	small, _ := rsa.GenerateKey(rand.Reader, 1024)
	offCurve := map[string]string{"kty": "EC", "crv": "P-256", "x": b64(make([]byte, 32)), "y": b64(append(make([]byte, 31), 1))}
	for name, jwk := range map[string]map[string]string{
		"RSA 1024":        rsaJWK("small", small),
		"EC off curve":    offCurve,
		"encryption key":  {"kty": "RSA", "use": "enc", "n": b64(newRSAKey(t).N.Bytes()), "e": "AQAB"},
		"symmetric (oct)": {"kty": "oct", "k": b64([]byte("secret"))},
	} {
		raw, _ := json.Marshal(jwk)
		if _, _, err := parseJWK(raw); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

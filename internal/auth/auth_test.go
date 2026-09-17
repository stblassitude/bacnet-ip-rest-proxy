package auth

import (
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

func TestAuthenticateOpaqueToken(t *testing.T) {
	a := NewAuthenticator(Options{Tokens: []Token{{Name: "alice", Value: "s3cr3t"}}})

	result := a.Authenticate("s3cr3t")
	if result.TokenName != "alice" {
		t.Fatalf("got token name %q, want alice", result.TokenName)
	}
	if result.Claims != nil {
		t.Fatalf("opaque token match should not carry JWT claims, got %v", result.Claims)
	}
}

func TestAuthenticateUnknownBearer(t *testing.T) {
	a := NewAuthenticator(Options{Tokens: []Token{{Name: "alice", Value: "s3cr3t"}}})
	result := a.Authenticate("not-a-known-token")
	if result.TokenName != "" || result.Claims != nil {
		t.Fatalf("expected empty result for unrecognized bearer, got %+v", result)
	}
}

func TestAuthenticateEmptyBearer(t *testing.T) {
	a := NewAuthenticator(Options{})
	result := a.Authenticate("")
	if result.TokenName != "" || result.Claims != nil {
		t.Fatalf("expected empty result for empty bearer, got %+v", result)
	}
}

func signHS256(t *testing.T, secret string, claims jwt.MapClaims) string {
	t.Helper()
	tok := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	signed, err := tok.SignedString([]byte(secret))
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	return signed
}

func TestAuthenticateValidJWT(t *testing.T) {
	a := NewAuthenticator(Options{JWTSecret: "test-secret"})
	token := signHS256(t, "test-secret", jwt.MapClaims{
		"iss":   "id.example.com",
		"group": "admins",
		"exp":   time.Now().Add(time.Hour).Unix(),
	})

	result := a.Authenticate(token)
	if result.Claims == nil {
		t.Fatal("expected claims, got nil")
	}
	if result.Claims["iss"] != "id.example.com" {
		t.Errorf("got iss=%v", result.Claims["iss"])
	}
	if result.TokenName != "" {
		t.Errorf("JWT match should not set TokenName, got %q", result.TokenName)
	}
}

func TestAuthenticateExpiredJWT(t *testing.T) {
	a := NewAuthenticator(Options{JWTSecret: "test-secret"})
	token := signHS256(t, "test-secret", jwt.MapClaims{
		"iss": "id.example.com",
		"exp": time.Now().Add(-time.Hour).Unix(),
	})

	result := a.Authenticate(token)
	if result.Claims != nil {
		t.Fatalf("expired JWT should not validate, got claims %v", result.Claims)
	}
}

func TestAuthenticateWrongSignature(t *testing.T) {
	a := NewAuthenticator(Options{JWTSecret: "correct-secret"})
	token := signHS256(t, "wrong-secret", jwt.MapClaims{"iss": "id.example.com"})

	result := a.Authenticate(token)
	if result.Claims != nil {
		t.Fatalf("JWT with wrong signature should not validate, got claims %v", result.Claims)
	}
}

func TestAuthenticateJWTWithoutSecretConfigured(t *testing.T) {
	a := NewAuthenticator(Options{})
	token := signHS256(t, "whatever", jwt.MapClaims{"iss": "id.example.com"})

	result := a.Authenticate(token)
	if result.Claims != nil {
		t.Fatalf("JWT should not validate when no secret is configured, got claims %v", result.Claims)
	}
}

func TestAuthenticateOpaqueTokenTakesPrecedenceOverJWTShape(t *testing.T) {
	// An opaque token that happens to look like a JWT-shaped string should
	// still be recognized by exact value match.
	a := NewAuthenticator(Options{
		Tokens:    []Token{{Name: "alice", Value: "a.b.c"}},
		JWTSecret: "test-secret",
	})
	result := a.Authenticate("a.b.c")
	if result.TokenName != "alice" {
		t.Fatalf("got %+v, want opaque token match", result)
	}
}

func TestAuthenticateRejectsNoneAlgorithm(t *testing.T) {
	a := NewAuthenticator(Options{JWTSecret: "test-secret"})
	// alg=none tokens must never be accepted regardless of secret configuration.
	tok := jwt.NewWithClaims(jwt.SigningMethodNone, jwt.MapClaims{"iss": "id.example.com"})
	unsigned, err := tok.SignedString(jwt.UnsafeAllowNoneSignatureType)
	if err != nil {
		t.Fatalf("sign none: %v", err)
	}
	result := a.Authenticate(unsigned)
	if result.Claims != nil {
		t.Fatalf("alg=none token must not validate, got claims %v", result.Claims)
	}
}

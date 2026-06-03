package main

import (
	"bytes"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"testing"
	"time"
)

// makeKey returns a deterministic-length 32-byte slice for tests.
func makeKey(t *testing.T) []byte {
	t.Helper()
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		t.Fatalf("rand.Read failed: %v", err)
	}
	return key
}

// (a) base64-encoded 32-byte value is decoded to the exact bytes.
func TestLoadSessionSecret_Base64(t *testing.T) {
	key := makeKey(t)
	t.Setenv("DOCK_SESSION_SECRET", base64.StdEncoding.EncodeToString(key))

	got := loadSessionSecret()
	if !bytes.Equal(got, key) {
		t.Fatalf("base64 secret mismatch: got %x want %x", got, key)
	}
}

// (b) hex-encoded 32-byte value is decoded to the exact bytes. A 64-char hex
// string is decoded by the hex-first branch (it would be mis-read by base64).
func TestLoadSessionSecret_Hex(t *testing.T) {
	key := makeKey(t)
	t.Setenv("DOCK_SESSION_SECRET", hex.EncodeToString(key))

	got := loadSessionSecret()
	if !bytes.Equal(got, key) {
		t.Fatalf("hex secret mismatch: got %x want %x", got, key)
	}
}

// (c) unset env yields a generated 32-byte fallback secret.
func TestLoadSessionSecret_FallbackLength(t *testing.T) {
	t.Setenv("DOCK_SESSION_SECRET", "")
	got := loadSessionSecret()
	if len(got) != 32 {
		t.Fatalf("fallback secret length = %d, want 32", len(got))
	}
}

// (d) RESTART-STABILITY regression: two independent loads of the SAME fixed
// env value yield key material that interoperates for token sign/verify. This
// is the exact property that was broken (ephemeral secret rotated each start).
func TestLoadSessionSecret_RestartStability(t *testing.T) {
	key := makeKey(t)
	envVal := base64.StdEncoding.EncodeToString(key)

	// First "process start" — sign a token.
	t.Setenv("DOCK_SESSION_SECRET", envVal)
	secretA := loadSessionSecret()
	token := createSessionToken("micah", secretA)

	// Second "process start" — independent load from the same env value.
	secretB := loadSessionSecret()
	if !bytes.Equal(secretA, secretB) {
		t.Fatalf("two loads of the same env value differ: %x vs %x", secretA, secretB)
	}

	user, ok := extractSessionUser(token, secretB, time.Hour)
	if !ok {
		t.Fatal("token signed with secretA failed validation under secretB (restart instability)")
	}
	if user != "micah" {
		t.Fatalf("extracted user = %q, want %q", user, "micah")
	}
}

// Sanity: with an ephemeral (generated) secret, a token signed by one secret
// does NOT validate under a freshly generated one — documents the old bug.
func TestEphemeralSecret_InvalidatesTokens(t *testing.T) {
	secret1 := generateSessionSecret()
	secret2 := generateSessionSecret()
	token := createSessionToken("micah", secret1)
	if _, ok := extractSessionUser(token, secret2, time.Hour); ok {
		t.Fatal("token unexpectedly validated under a different ephemeral secret")
	}
}

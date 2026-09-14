package envelope

import (
	"crypto/ed25519"
	"errors"
	"testing"
)

func TestVerifyRequest(t *testing.T) {
	e, pub, priv, now := fixture(t)
	signed, err := Sign(e, "key-1", priv)
	if err != nil {
		t.Fatal(err)
	}
	keys := StaticKeyring{"key-1": pub}

	t.Run("accepts exact request", func(t *testing.T) {
		err := VerifyRequest(signed, keys, now, []byte("canonical manifests"), e.Operations[0])
		if err != nil {
			t.Fatalf("VerifyRequest() error = %v", err)
		}
	})

	t.Run("rejects unknown key", func(t *testing.T) {
		err := VerifyRequest(signed, StaticKeyring{}, now, []byte("canonical manifests"), e.Operations[0])
		if !errors.Is(err, ErrUnknownSigningKey) {
			t.Fatalf("VerifyRequest() error = %v, want ErrUnknownSigningKey", err)
		}
	})

	t.Run("rejects nil resolver", func(t *testing.T) {
		err := VerifyRequest(signed, nil, now, []byte("canonical manifests"), e.Operations[0])
		if !errors.Is(err, ErrUnknownSigningKey) {
			t.Fatalf("VerifyRequest() error = %v, want ErrUnknownSigningKey", err)
		}
	})

	t.Run("rejects manifest mismatch", func(t *testing.T) {
		err := VerifyRequest(signed, keys, now, []byte("changed manifests"), e.Operations[0])
		if !errors.Is(err, ErrManifestMismatch) {
			t.Fatalf("VerifyRequest() error = %v, want ErrManifestMismatch", err)
		}
	})

	t.Run("rejects unlisted operation", func(t *testing.T) {
		unlisted := Operation{
			Verb:      "delete",
			APIGroup:  "apps",
			Resource:  "deployments",
			Namespace: "payments",
			Name:      "api",
		}
		err := VerifyRequest(signed, keys, now, []byte("canonical manifests"), unlisted)
		if !errors.Is(err, ErrOperationDenied) {
			t.Fatalf("VerifyRequest() error = %v, want ErrOperationDenied", err)
		}
	})

	t.Run("rejects wrong public key", func(t *testing.T) {
		otherPublic, _, err := ed25519.GenerateKey(nil)
		if err != nil {
			t.Fatal(err)
		}
		err = VerifyRequest(signed, StaticKeyring{"key-1": otherPublic}, now, []byte("canonical manifests"), e.Operations[0])
		if err == nil {
			t.Fatal("VerifyRequest() error = nil, want signature failure")
		}
	})

	t.Run("rejects expired envelope", func(t *testing.T) {
		err := VerifyRequest(signed, keys, e.ExpiresAt, []byte("canonical manifests"), e.Operations[0])
		if err == nil {
			t.Fatal("VerifyRequest() error = nil, want expiry failure")
		}
	})
}

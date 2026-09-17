package envelope

import (
	"crypto/ed25519"
	"errors"
	"testing"
)

func TestVerifyRequest(t *testing.T) {
	e, pub, priv, now := fixture(t)
	canonicalManifests := fixtureManifests(t, fixtureImage)
	signed, err := Sign(e, "key-1", priv)
	if err != nil {
		t.Fatal(err)
	}
	keys := StaticKeyring{"key-1": pub}

	t.Run("accepts exact request", func(t *testing.T) {
		err := VerifyRequest(signed, keys, now, canonicalManifests, e.Operations[0])
		if err != nil {
			t.Fatalf("VerifyRequest() error = %v", err)
		}
	})

	t.Run("rejects unknown key", func(t *testing.T) {
		err := VerifyRequest(signed, StaticKeyring{}, now, canonicalManifests, e.Operations[0])
		if !errors.Is(err, ErrUnknownSigningKey) {
			t.Fatalf("VerifyRequest() error = %v, want ErrUnknownSigningKey", err)
		}
	})

	t.Run("rejects nil resolver", func(t *testing.T) {
		err := VerifyRequest(signed, nil, now, canonicalManifests, e.Operations[0])
		if !errors.Is(err, ErrUnknownSigningKey) {
			t.Fatalf("VerifyRequest() error = %v, want ErrUnknownSigningKey", err)
		}
	})

	t.Run("rejects non-canonical manifest bytes", func(t *testing.T) {
		nonCanonical := append([]byte(" "), canonicalManifests...)
		modified := signed
		modified.Envelope.ManifestSetDigest = ManifestSetDigest(nonCanonical)
		modified, err = Sign(modified.Envelope, "key-1", priv)
		if err != nil {
			t.Fatal(err)
		}
		err := VerifyRequest(modified, keys, now, nonCanonical, e.Operations[0])
		if !errors.Is(err, ErrArtifactInspection) {
			t.Fatalf("VerifyRequest() error = %v, want ErrArtifactInspection", err)
		}
	})

	t.Run("rejects artifact binding mismatch", func(t *testing.T) {
		modifiedEnvelope := e
		modifiedEnvelope.Artifacts = []string{"registry.example.com/payments/api@sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"}
		modified, err := Sign(modifiedEnvelope, "key-1", priv)
		if err != nil {
			t.Fatal(err)
		}
		err = VerifyRequest(modified, keys, now, canonicalManifests, e.Operations[0])
		if !errors.Is(err, ErrArtifactMismatch) {
			t.Fatalf("VerifyRequest() error = %v, want ErrArtifactMismatch", err)
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
		err := VerifyRequest(signed, keys, now, canonicalManifests, unlisted)
		if !errors.Is(err, ErrOperationDenied) {
			t.Fatalf("VerifyRequest() error = %v, want ErrOperationDenied", err)
		}
	})

	t.Run("rejects wrong public key", func(t *testing.T) {
		otherPublic, _, err := ed25519.GenerateKey(nil)
		if err != nil {
			t.Fatal(err)
		}
		err = VerifyRequest(signed, StaticKeyring{"key-1": otherPublic}, now, canonicalManifests, e.Operations[0])
		if err == nil {
			t.Fatal("VerifyRequest() error = nil, want signature failure")
		}
	})

	t.Run("rejects expired envelope", func(t *testing.T) {
		err := VerifyRequest(signed, keys, e.ExpiresAt, canonicalManifests, e.Operations[0])
		if err == nil {
			t.Fatal("VerifyRequest() error = nil, want expiry failure")
		}
	})
}

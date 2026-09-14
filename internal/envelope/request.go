package envelope

import (
	"crypto/ed25519"
	"errors"
	"time"
)

var (
	ErrUnknownSigningKey = errors.New("unknown signing key")
	ErrManifestMismatch  = errors.New("manifest-set digest does not match envelope")
	ErrOperationDenied   = errors.New("operation is not authorized by envelope")
)

// KeyResolver is verifier-owned trust configuration. Implementations must not
// resolve keys from untrusted fields inside an envelope.
type KeyResolver interface {
	Resolve(keyID string) (ed25519.PublicKey, bool)
}

// VerifyRequest makes one fail-closed authorization decision. It verifies the
// trusted signing key, signature, validity window, manifest set, and exact
// Kubernetes operation in that order.
func VerifyRequest(
	signed SignedEnvelope,
	keys KeyResolver,
	now time.Time,
	canonicalManifests []byte,
	operation Operation,
) error {
	if keys == nil {
		return ErrUnknownSigningKey
	}

	publicKey, ok := keys.Resolve(signed.KeyID)
	if !ok {
		return ErrUnknownSigningKey
	}
	if err := Verify(signed, publicKey, now); err != nil {
		return err
	}
	if !signed.Envelope.MatchesManifestSet(canonicalManifests) {
		return ErrManifestMismatch
	}
	if !signed.Envelope.Authorizes(operation) {
		return ErrOperationDenied
	}
	return nil
}

// StaticKeyring is intended for tests and small deployments. Callers must build
// it from trusted configuration, not envelope content.
type StaticKeyring map[string]ed25519.PublicKey

func (k StaticKeyring) Resolve(keyID string) (ed25519.PublicKey, bool) {
	key, ok := k[keyID]
	return key, ok
}

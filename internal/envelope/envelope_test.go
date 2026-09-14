package envelope

import (
	"crypto/ed25519"
	"crypto/rand"
	"strings"
	"testing"
	"time"
)

func fixture(t *testing.T) (Envelope, ed25519.PublicKey, ed25519.PrivateKey, time.Time) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 9, 12, 12, 0, 0, 0, time.UTC)
	e := Envelope{
		Version: VersionV0Alpha1, DeploymentID: "deploy-01",
		Identity: Identity{Issuer: "https://token.actions.githubusercontent.com", Audience: "release-envelope", RepositoryID: "123456", WorkflowRef: "acme/app/.github/workflows/deploy.yml@refs/heads/main"},
		Target: Target{ClusterID: "cluster-prod-1", Namespace: "payments"},
		SourceRevision: "0123456789abcdef", ManifestSetDigest: ManifestSetDigest([]byte("canonical manifests")),
		NotBefore: now.Add(-time.Minute), ExpiresAt: now.Add(5 * time.Minute),
		Operations: []Operation{
			{Verb: "update", APIGroup: "apps", Resource: "deployments", Namespace: "payments", Name: "api"},
			{Verb: "create", APIGroup: "", Resource: "services", Namespace: "payments", Name: "api"},
		},
	}
	return e, pub, priv, now
}

func TestSignVerifyAndCanonicalOperationOrder(t *testing.T) {
	e, pub, priv, now := fixture(t)
	a, err := e.CanonicalBytes()
	if err != nil {
		t.Fatal(err)
	}
	e.Operations[0], e.Operations[1] = e.Operations[1], e.Operations[0]
	b, err := e.CanonicalBytes()
	if err != nil {
		t.Fatal(err)
	}
	if string(a) != string(b) {
		t.Fatal("operation order changed canonical payload")
	}
	signed, err := Sign(e, "signing-key-1", priv)
	if err != nil {
		t.Fatal(err)
	}
	if err := Verify(signed, pub, now); err != nil {
		t.Fatalf("verify: %v", err)
	}
}

func TestVerifyRejectsTamperingAndExpiry(t *testing.T) {
	e, pub, priv, now := fixture(t)
	signed, err := Sign(e, "signing-key-1", priv)
	if err != nil {
		t.Fatal(err)
	}
	t.Run("manifest digest changed", func(t *testing.T) {
		tampered := signed
		tampered.Envelope.ManifestSetDigest = ManifestSetDigest([]byte("different"))
		if err := Verify(tampered, pub, now); err == nil || !strings.Contains(err.Error(), "signature") {
			t.Fatalf("got %v", err)
		}
	})
	t.Run("extra resource", func(t *testing.T) {
		tampered := signed
		tampered.Envelope.Operations = append(append([]Operation(nil), signed.Envelope.Operations...), Operation{Verb: "delete", Resource: "secrets", Namespace: "payments", Name: "credentials"})
		if err := Verify(tampered, pub, now); err == nil || !strings.Contains(err.Error(), "signature") {
			t.Fatalf("got %v", err)
		}
	})
	t.Run("expired", func(t *testing.T) {
		if err := Verify(signed, pub, e.ExpiresAt); err == nil || !strings.Contains(err.Error(), "expired") {
			t.Fatalf("got %v", err)
		}
	})
}

func TestExactAuthorizationAndManifestBinding(t *testing.T) {
	e, _, _, _ := fixture(t)
	if !e.Authorizes(e.Operations[0]) {
		t.Fatal("expected listed operation to be authorized")
	}
	forbiddenDelete := Operation{Verb: "delete", APIGroup: "apps", Resource: "deployments", Namespace: "payments", Name: "api"}
	if e.Authorizes(forbiddenDelete) {
		t.Fatal("delete must not inherit authorization from update")
	}
	extraResource := Operation{Verb: "create", Resource: "configmaps", Namespace: "payments", Name: "extra"}
	if e.Authorizes(extraResource) {
		t.Fatal("unlisted resource must not be authorized")
	}
	if !e.MatchesManifestSet([]byte("canonical manifests")) || e.MatchesManifestSet([]byte("changed manifests")) {
		t.Fatal("manifest-set binding failed")
	}
}

func TestValidationRejectsDuplicateAndForbiddenVerb(t *testing.T) {
	e, _, _, _ := fixture(t)
	e.Operations = append(e.Operations, e.Operations[0])
	if err := e.Validate(); err == nil || !strings.Contains(err.Error(), "duplicate") {
		t.Fatalf("got %v", err)
	}
	e, _, _, _ = fixture(t)
	e.Operations[0].Verb = "impersonate"
	if err := e.Validate(); err == nil || !strings.Contains(err.Error(), "unsupported verb") {
		t.Fatalf("got %v", err)
	}
}

func TestDecodeRejectsUnknownFields(t *testing.T) {
	_, err := Decode([]byte(`{"envelope":{},"keyId":"k","signature":"00","surprise":true}`))
	if err == nil {
		t.Fatal("expected unknown field rejection")
	}
}

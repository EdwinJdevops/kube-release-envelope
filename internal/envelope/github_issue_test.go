package envelope

import (
	"crypto"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"testing"
	"time"

	"github.com/EdwinJdevops/kube-release-envelope/internal/githuboidc"
)

type memoryTokenConsumer struct {
	used  map[string]struct{}
	calls int
}

func (c *memoryTokenConsumer) Consume(issuer, jti string, _ time.Time) bool {
	c.calls++
	key := issuer + "\x00" + jti
	if _, exists := c.used[key]; exists {
		return false
	}
	c.used[key] = struct{}{}
	return true
}

func verifiedGitHubPrincipal(t *testing.T, now time.Time) githuboidc.Principal {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	sourceSHA := "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	subject := "repo:acme@100/app@123456:environment:production"
	workflowRef := "acme/app/.github/workflows/deploy.yml@refs/heads/main"
	claims := map[string]any{
		"iss": githuboidc.Issuer, "aud": "release-envelope", "sub": subject,
		"repository": "acme/app", "repository_id": "123456", "repository_owner_id": "100",
		"sha": sourceSHA, "ref": "refs/heads/main", "workflow_ref": workflowRef, "workflow_sha": sourceSHA,
		"environment": "production", "event_name": "workflow_dispatch", "runner_environment": "github-hosted",
		"actor_id": "200", "run_id": "300", "run_attempt": "1", "jti": "github-token-01",
		"iat": now.Add(-time.Minute).Unix(), "nbf": now.Add(-time.Minute).Unix(), "exp": now.Add(4 * time.Minute).Unix(),
	}
	headerJSON, err := json.Marshal(map[string]any{"alg": "RS256", "kid": "github-key", "typ": "JWT"})
	if err != nil {
		t.Fatal(err)
	}
	claimsJSON, err := json.Marshal(claims)
	if err != nil {
		t.Fatal(err)
	}
	header := base64.RawURLEncoding.EncodeToString(headerJSON)
	payload := base64.RawURLEncoding.EncodeToString(claimsJSON)
	digest := sha256.Sum256([]byte(header + "." + payload))
	signature, err := rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA256, digest[:])
	if err != nil {
		t.Fatal(err)
	}
	token := header + "." + payload + "." + base64.RawURLEncoding.EncodeToString(signature)
	environment := "production"
	principal, err := githuboidc.Verify(token, githuboidc.StaticKeyring{"github-key": &key.PublicKey}, githuboidc.Policy{
		Audience: "release-envelope", Subject: subject,
		RepositoryID: "123456", RepositoryOwnerID: "100", SourceSHA: sourceSHA,
		Ref: "refs/heads/main", Workflow: githuboidc.WorkflowIdentity{Ref: workflowRef, SHA: sourceSHA},
		ExpectedEnvironment: &environment, EventName: "workflow_dispatch", RunnerEnvironment: "github-hosted",
		MaxTokenAge: 5 * time.Minute, ClockSkew: 10 * time.Second,
	}, now)
	if err != nil {
		t.Fatal(err)
	}
	return principal
}

func TestIssueGitHubBindsVerifiedIdentityAndConsumesToken(t *testing.T) {
	e, publicKey, privateKey, now := fixture(t)
	e.SourceRevision = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	e.NotBefore = now
	e.ExpiresAt = now.Add(3 * time.Minute)
	principal := verifiedGitHubPrincipal(t, now)
	consumer := &memoryTokenConsumer{used: make(map[string]struct{})}

	signed, err := IssueGitHub(e, principal, consumer, "envelope-key", privateKey)
	if err != nil {
		t.Fatal(err)
	}
	if signed.Envelope.Identity.RepositoryID != "123456" || signed.Envelope.Identity.TokenID != "github-token-01" {
		t.Fatalf("unexpected identity: %#v", signed.Envelope.Identity)
	}
	if err := Verify(signed, publicKey, now); err != nil {
		t.Fatalf("Verify() error = %v", err)
	}
	if _, err := IssueGitHub(e, principal, consumer, "envelope-key", privateKey); !errors.Is(err, ErrTokenReplay) {
		t.Fatalf("second IssueGitHub() error = %v, want ErrTokenReplay", err)
	}
}

func TestIssueGitHubRejectsBeforeTokenConsumption(t *testing.T) {
	e, _, privateKey, now := fixture(t)
	e.SourceRevision = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	e.NotBefore = now
	e.ExpiresAt = now.Add(3 * time.Minute)
	principal := verifiedGitHubPrincipal(t, now)

	tests := []struct {
		name      string
		principal githuboidc.Principal
		mutate    func(*Envelope)
		key       ed25519.PrivateKey
		want      error
	}{
		{"unverified principal", githuboidc.Principal{}, func(*Envelope) {}, privateKey, ErrUnverifiedGitHubIdentity},
		{"source mismatch", principal, func(e *Envelope) { e.SourceRevision = "different" }, privateKey, ErrSourceRevisionMismatch},
		{"window exceeds token", principal, func(e *Envelope) { e.ExpiresAt = now.Add(10 * time.Minute) }, privateKey, ErrIdentityWindowMismatch},
		{"invalid signing key", principal, func(*Envelope) {}, ed25519.PrivateKey("short"), errors.New("invalid Ed25519 private key")},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			candidate := e
			test.mutate(&candidate)
			consumer := &memoryTokenConsumer{used: make(map[string]struct{})}
			_, err := IssueGitHub(candidate, test.principal, consumer, "envelope-key", test.key)
			if err == nil || (test.want != nil && !errors.Is(err, test.want) && err.Error() != test.want.Error()) {
				t.Fatalf("IssueGitHub() error = %v, want %v", err, test.want)
			}
			if consumer.calls != 0 {
				t.Fatalf("token consumed before validation failure; calls = %d", consumer.calls)
			}
		})
	}
}

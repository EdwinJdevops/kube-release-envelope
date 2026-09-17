package githuboidc

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"
)

const testKeyID = "github-key-1"

var (
	testKeyOnce sync.Once
	testKey     *rsa.PrivateKey
	testKeyErr  error
)

func signingKey(t *testing.T) *rsa.PrivateKey {
	t.Helper()
	testKeyOnce.Do(func() {
		testKey, testKeyErr = rsa.GenerateKey(rand.Reader, 2048)
	})
	if testKeyErr != nil {
		t.Fatal(testKeyErr)
	}
	return testKey
}

func environment(value string) *string { return &value }

func fixture(t *testing.T) (map[string]any, Policy, time.Time, StaticKeyring) {
	t.Helper()
	now := time.Date(2026, 9, 17, 12, 0, 0, 0, time.UTC)
	subject := "repo:EdwinJdevops@262093906/kube-release-envelope@1369974887:environment:production"
	workflowRef := "EdwinJdevops/kube-release-envelope/.github/workflows/release.yml@refs/heads/main"
	workflowSHA := "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	claims := map[string]any{
		"iss": Issuer, "aud": "release-envelope", "sub": subject,
		"repository": "EdwinJdevops/kube-release-envelope", "repository_id": "1369974887",
		"repository_owner_id": "262093906", "sha": workflowSHA, "ref": "refs/heads/main",
		"workflow_ref": workflowRef, "workflow_sha": workflowSHA, "environment": "production",
		"event_name": "workflow_dispatch", "runner_environment": "github-hosted",
		"actor_id": "262093906", "run_id": "35190000000", "run_attempt": "1", "jti": "token-unique-id",
		"iat": now.Add(-time.Minute).Unix(), "nbf": now.Add(-time.Minute).Unix(), "exp": now.Add(4 * time.Minute).Unix(),
	}
	policy := Policy{
		Audience: "release-envelope", Subject: subject,
		RepositoryID: "1369974887", RepositoryOwnerID: "262093906",
		SourceSHA: workflowSHA, Ref: "refs/heads/main",
		Workflow:            WorkflowIdentity{Ref: workflowRef, SHA: workflowSHA},
		ExpectedEnvironment: environment("production"), EventName: "workflow_dispatch",
		RunnerEnvironment: "github-hosted", MaxTokenAge: 5 * time.Minute, ClockSkew: 10 * time.Second,
	}
	key := signingKey(t)
	return claims, policy, now, StaticKeyring{testKeyID: &key.PublicKey}
}

func signClaims(t *testing.T, claims map[string]any) string {
	t.Helper()
	header, err := json.Marshal(map[string]any{"alg": "RS256", "kid": testKeyID, "typ": "JWT"})
	if err != nil {
		t.Fatal(err)
	}
	payload, err := json.Marshal(claims)
	if err != nil {
		t.Fatal(err)
	}
	return signRaw(t, header, payload)
}

func signRaw(t *testing.T, header, payload []byte) string {
	t.Helper()
	encodedHeader := base64.RawURLEncoding.EncodeToString(header)
	encodedPayload := base64.RawURLEncoding.EncodeToString(payload)
	digest := sha256.Sum256([]byte(encodedHeader + "." + encodedPayload))
	signature, err := rsa.SignPKCS1v15(rand.Reader, signingKey(t), crypto.SHA256, digest[:])
	if err != nil {
		t.Fatal(err)
	}
	return encodedHeader + "." + encodedPayload + "." + base64.RawURLEncoding.EncodeToString(signature)
}

func cloneClaims(t *testing.T, original map[string]any) map[string]any {
	t.Helper()
	encoded, err := json.Marshal(original)
	if err != nil {
		t.Fatal(err)
	}
	var clone map[string]any
	if err := json.Unmarshal(encoded, &clone); err != nil {
		t.Fatal(err)
	}
	return clone
}

func TestVerifyExactDirectWorkflowIdentity(t *testing.T) {
	claims, policy, now, keys := fixture(t)
	principal, err := Verify(signClaims(t, claims), keys, policy, now)
	if err != nil {
		t.Fatal(err)
	}
	verified := principal.Claims()
	if !principal.Verified() || verified.RepositoryID != policy.RepositoryID || verified.WorkflowSHA != policy.Workflow.SHA || verified.JTI != "token-unique-id" {
		t.Fatalf("unexpected verified claims: %#v", verified)
	}
}

func TestVerifyAcceptsAudienceArray(t *testing.T) {
	claims, policy, now, keys := fixture(t)
	claims["aud"] = []string{"another-audience", policy.Audience}
	if _, err := Verify(signClaims(t, claims), keys, policy, now); err != nil {
		t.Fatal(err)
	}
}

func TestVerifyRejectsClaimMismatch(t *testing.T) {
	claims, policy, now, keys := fixture(t)
	tests := []struct {
		name, claim string
		value       any
	}{
		{"issuer", "iss", "https://attacker.example"},
		{"audience", "aud", "wrong-audience"},
		{"subject", "sub", "repo:attacker/repo:ref:refs/heads/main"},
		{"repository ID", "repository_id", "999"},
		{"owner ID", "repository_owner_id", "999"},
		{"source SHA", "sha", "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"},
		{"ref", "ref", "refs/heads/untrusted"},
		{"workflow ref", "workflow_ref", "attacker/repo/.github/workflows/release.yml@refs/heads/main"},
		{"workflow SHA", "workflow_sha", "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"},
		{"environment", "environment", "staging"},
		{"event", "event_name", "pull_request"},
		{"runner", "runner_environment", "self-hosted"},
		{"invalid actor ID", "actor_id", "not-a-number"},
		{"zero run attempt", "run_attempt", "0"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			modified := cloneClaims(t, claims)
			modified[test.claim] = test.value
			_, err := Verify(signClaims(t, modified), keys, policy, now)
			if !errors.Is(err, ErrPolicyMismatch) {
				t.Fatalf("Verify() error = %v, want ErrPolicyMismatch", err)
			}
		})
	}
}

func TestVerifyReusableWorkflowPolicy(t *testing.T) {
	claims, policy, now, keys := fixture(t)
	reusable := WorkflowIdentity{
		Ref: "EdwinJdevops/platform/.github/workflows/release.yml@refs/heads/main",
		SHA: "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
	}
	claims["job_workflow_ref"] = reusable.Ref
	claims["job_workflow_sha"] = reusable.SHA

	t.Run("rejects unexpected reusable workflow", func(t *testing.T) {
		if _, err := Verify(signClaims(t, claims), keys, policy, now); !errors.Is(err, ErrPolicyMismatch) {
			t.Fatalf("Verify() error = %v", err)
		}
	})

	t.Run("accepts exact reusable workflow", func(t *testing.T) {
		policy.ReusableWorkflow = &reusable
		if _, err := Verify(signClaims(t, claims), keys, policy, now); err != nil {
			t.Fatal(err)
		}
	})

	t.Run("rejects changed reusable workflow commit", func(t *testing.T) {
		policy.ReusableWorkflow = &reusable
		modified := cloneClaims(t, claims)
		modified["job_workflow_sha"] = "cccccccccccccccccccccccccccccccccccccccc"
		if _, err := Verify(signClaims(t, modified), keys, policy, now); !errors.Is(err, ErrPolicyMismatch) {
			t.Fatalf("Verify() error = %v", err)
		}
	})
}

func TestVerifyRequiresEnvironmentPresencePolicy(t *testing.T) {
	claims, policy, now, keys := fixture(t)
	delete(claims, "environment")
	if _, err := Verify(signClaims(t, claims), keys, policy, now); !errors.Is(err, ErrPolicyMismatch) {
		t.Fatalf("Verify() error = %v", err)
	}

	policy.ExpectedEnvironment = nil
	if _, err := Verify(signClaims(t, claims), keys, policy, now); err != nil {
		t.Fatal(err)
	}
}

func TestVerifyRejectsSignatureAndHeaderAttacks(t *testing.T) {
	claims, policy, now, keys := fixture(t)
	valid := signClaims(t, claims)

	t.Run("tampered signature", func(t *testing.T) {
		parts := strings.Split(valid, ".")
		parts[2] = strings.Repeat("A", len(parts[2]))
		if _, err := Verify(strings.Join(parts, "."), keys, policy, now); !errors.Is(err, ErrInvalidSignature) {
			t.Fatalf("Verify() error = %v", err)
		}
	})

	t.Run("unknown key", func(t *testing.T) {
		if _, err := Verify(valid, StaticKeyring{}, policy, now); !errors.Is(err, ErrUnknownKey) {
			t.Fatalf("Verify() error = %v", err)
		}
	})

	payload, err := json.Marshal(claims)
	if err != nil {
		t.Fatal(err)
	}
	for name, header := range map[string]string{
		"none algorithm":   `{"alg":"none","kid":"github-key-1","typ":"JWT"}`,
		"unknown header":   `{"alg":"RS256","kid":"github-key-1","typ":"JWT","jwk":{}}`,
		"duplicate header": `{"alg":"RS256","alg":"none","kid":"github-key-1","typ":"JWT"}`,
	} {
		t.Run(name, func(t *testing.T) {
			_, err := Verify(signRaw(t, []byte(header), payload), keys, policy, now)
			if err == nil {
				t.Fatal("Verify() error = nil")
			}
		})
	}
}

func TestVerifyRejectsDuplicateClaims(t *testing.T) {
	_, policy, now, keys := fixture(t)
	header := []byte(`{"alg":"RS256","kid":"github-key-1","typ":"JWT"}`)
	payload := []byte(`{"iss":"` + Issuer + `","iss":"https://attacker.example"}`)
	_, err := Verify(signRaw(t, header, payload), keys, policy, now)
	if !errors.Is(err, ErrDuplicateField) {
		t.Fatalf("Verify() error = %v, want ErrDuplicateField", err)
	}
}

func TestVerifyRejectsInvalidTimes(t *testing.T) {
	claims, policy, now, keys := fixture(t)
	tests := []struct {
		name  string
		claim string
		value any
	}{
		{"expired", "exp", now.Add(-time.Minute).Unix()},
		{"not yet valid", "nbf", now.Add(time.Minute).Unix()},
		{"future issued-at", "iat", now.Add(time.Minute).Unix()},
		{"too old", "iat", now.Add(-10 * time.Minute).Unix()},
		{"fractional expiry", "exp", 1.5},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			modified := cloneClaims(t, claims)
			modified[test.claim] = test.value
			_, err := Verify(signClaims(t, modified), keys, policy, now)
			if !errors.Is(err, ErrInvalidTime) {
				t.Fatalf("Verify() error = %v, want ErrInvalidTime", err)
			}
		})
	}
}

func TestVerifyRejectsInvalidPolicy(t *testing.T) {
	claims, policy, now, keys := fixture(t)
	for name, mutate := range map[string]func(*Policy){
		"missing repository ID": func(p *Policy) { p.RepositoryID = "" },
		"excessive token age":   func(p *Policy) { p.MaxTokenAge = 2 * time.Hour },
		"excessive clock skew":  func(p *Policy) { p.ClockSkew = 6 * time.Minute },
	} {
		t.Run(name, func(t *testing.T) {
			candidate := policy
			mutate(&candidate)
			if _, err := Verify(signClaims(t, claims), keys, candidate, now); !errors.Is(err, ErrInvalidPolicy) {
				t.Fatalf("Verify() error = %v, want ErrInvalidPolicy", err)
			}
		})
	}
}

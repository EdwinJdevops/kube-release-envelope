package githubjwks

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/EdwinJdevops/kube-release-envelope/internal/githuboidc"
)

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(request *http.Request) (*http.Response, error) {
	return f(request)
}

type testClock struct {
	mu  sync.Mutex
	now time.Time
}

func (c *testClock) Time() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.now
}

func (c *testClock) Advance(duration time.Duration) {
	c.mu.Lock()
	c.now = c.now.Add(duration)
	c.mu.Unlock()
}

func testClient(transport http.RoundTripper) *http.Client {
	return &http.Client{Transport: transport, Timeout: 2 * time.Second}
}

func response(body string) *http.Response {
	return &http.Response{
		StatusCode: http.StatusOK,
		Header: http.Header{
			"Cache-Control": {"public, max-age=3600, must-revalidate"},
			"Content-Type":  {"application/json"},
		},
		Body: io.NopCloser(strings.NewReader(body)),
	}
}

func jwks(t *testing.T, keys map[string]*rsa.PublicKey) string {
	t.Helper()
	entries := make([]map[string]string, 0, len(keys))
	for kid, key := range keys {
		entries = append(entries, map[string]string{
			"kty": "RSA", "alg": "RS256", "use": "sig", "kid": kid,
			"n": base64.RawURLEncoding.EncodeToString(key.N.Bytes()),
			"e": base64.RawURLEncoding.EncodeToString(bigEndian(key.E)),
		})
	}
	encoded, err := json.Marshal(map[string]any{"keys": entries})
	if err != nil {
		t.Fatal(err)
	}
	return string(encoded)
}

func bigEndian(value int) []byte {
	bytes := make([]byte, 0, 4)
	for value > 0 {
		bytes = append([]byte{byte(value)}, bytes...)
		value >>= 8
	}
	return bytes
}

func generateKey(t *testing.T) *rsa.PrivateKey {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	return key
}

func TestNewRequiresBoundedHTTPClient(t *testing.T) {
	for name, client := range map[string]*http.Client{
		"nil": nil,
		"no timeout": {
			Timeout: 0,
		},
		"excessive timeout": {
			Timeout: 31 * time.Second,
		},
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := New(client); !errors.Is(err, ErrInvalidConfiguration) {
				t.Fatalf("New() error = %v, want ErrInvalidConfiguration", err)
			}
		})
	}
}

func TestLiveGitHubJWKSRefresh(t *testing.T) {
	if os.Getenv("KUBE_RELEASE_LIVE_GITHUB_JWKS") != "1" {
		t.Skip("set KUBE_RELEASE_LIVE_GITHUB_JWKS=1 to call GitHub")
	}
	cache, err := New(&http.Client{Timeout: 30 * time.Second})
	if err != nil {
		t.Fatal(err)
	}
	if err := cache.Refresh(context.Background()); err != nil {
		t.Fatal(err)
	}
	cache.mu.RLock()
	defer cache.mu.RUnlock()
	if len(cache.keys) == 0 || !time.Now().UTC().Before(cache.expiresAt) {
		t.Fatalf("unexpected live cache state: keys=%d, expiresAt=%s", len(cache.keys), cache.expiresAt)
	}
}

func TestRefreshResolvesFreshKeyAndReturnsCopy(t *testing.T) {
	key := generateKey(t)
	clock := &testClock{now: time.Date(2026, 9, 17, 15, 0, 0, 0, time.UTC)}
	requests := 0
	cache, err := newWithClock(testClient(roundTripFunc(func(request *http.Request) (*http.Response, error) {
		requests++
		if request.URL.String() != Endpoint || request.Header.Get("Accept") != "application/json" {
			t.Fatalf("unexpected request: %s, Accept=%q", request.URL, request.Header.Get("Accept"))
		}
		return response(jwks(t, map[string]*rsa.PublicKey{"key-1": &key.PublicKey})), nil
	})), clock.Time)
	if err != nil {
		t.Fatal(err)
	}
	if err := cache.Refresh(context.Background()); err != nil {
		t.Fatal(err)
	}
	resolved, ok := cache.Resolve("key-1")
	if !ok || resolved.N.Cmp(key.N) != 0 || requests != 1 {
		t.Fatalf("Resolve() = (%v, %v), requests = %d", resolved, ok, requests)
	}
	resolved.N.SetInt64(3)
	again, ok := cache.Resolve("key-1")
	if !ok || again.N.Cmp(key.N) != 0 {
		t.Fatal("caller mutation changed cached trust material")
	}
}

func TestVerifyRefreshesOnceForRotatedUnknownKey(t *testing.T) {
	first := generateKey(t)
	second := generateKey(t)
	clock := &testClock{now: time.Date(2026, 9, 17, 15, 0, 0, 0, time.UTC)}
	requests := 0
	cache, err := newWithClock(testClient(roundTripFunc(func(_ *http.Request) (*http.Response, error) {
		requests++
		if requests == 1 {
			return response(jwks(t, map[string]*rsa.PublicKey{"key-1": &first.PublicKey})), nil
		}
		return response(jwks(t, map[string]*rsa.PublicKey{"key-2": &second.PublicKey})), nil
	})), clock.Time)
	if err != nil {
		t.Fatal(err)
	}
	if err := cache.Refresh(context.Background()); err != nil {
		t.Fatal(err)
	}
	clock.Advance(unknownRefreshBackoff)

	claims, policy := tokenFixture(clock.Time())
	token := sign(t, "key-2", second, claims)
	principal, err := cache.Verify(context.Background(), token, policy, clock.Time())
	if err != nil {
		t.Fatal(err)
	}
	if !principal.Verified() || requests != 2 {
		t.Fatalf("Verified() = %v, requests = %d", principal.Verified(), requests)
	}
}

func TestConcurrentVerificationSharesInitialRefresh(t *testing.T) {
	key := generateKey(t)
	clock := &testClock{now: time.Date(2026, 9, 17, 15, 0, 0, 0, time.UTC)}
	var requests atomic.Int32
	cache, err := newWithClock(testClient(roundTripFunc(func(_ *http.Request) (*http.Response, error) {
		requests.Add(1)
		return response(jwks(t, map[string]*rsa.PublicKey{"trusted": &key.PublicKey})), nil
	})), clock.Time)
	if err != nil {
		t.Fatal(err)
	}
	claims, policy := tokenFixture(clock.Time())
	token := sign(t, "trusted", key, claims)

	const workers = 16
	errorsFound := make(chan error, workers)
	var group sync.WaitGroup
	for range workers {
		group.Add(1)
		go func() {
			defer group.Done()
			_, err := cache.Verify(context.Background(), token, policy, clock.Time())
			errorsFound <- err
		}()
	}
	group.Wait()
	close(errorsFound)
	for err := range errorsFound {
		if err != nil {
			t.Fatal(err)
		}
	}
	if requests.Load() != 1 {
		t.Fatalf("HTTP requests = %d, want 1", requests.Load())
	}
}

func TestUnknownKeyRefreshIsRateLimited(t *testing.T) {
	trusted := generateKey(t)
	untrusted := generateKey(t)
	clock := &testClock{now: time.Date(2026, 9, 17, 15, 0, 0, 0, time.UTC)}
	requests := 0
	cache, err := newWithClock(testClient(roundTripFunc(func(_ *http.Request) (*http.Response, error) {
		requests++
		return response(jwks(t, map[string]*rsa.PublicKey{"trusted": &trusted.PublicKey})), nil
	})), clock.Time)
	if err != nil {
		t.Fatal(err)
	}
	if err := cache.Refresh(context.Background()); err != nil {
		t.Fatal(err)
	}
	claims, policy := tokenFixture(clock.Time())
	token := sign(t, "attacker-kid", untrusted, claims)
	_, err = cache.Verify(context.Background(), token, policy, clock.Time())
	if !errors.Is(err, githuboidc.ErrUnknownKey) || requests != 2 {
		t.Fatalf("Verify() error = %v, requests = %d", err, requests)
	}
	_, err = cache.Verify(context.Background(), token, policy, clock.Time())
	if !errors.Is(err, githuboidc.ErrUnknownKey) || requests != 2 {
		t.Fatalf("second Verify() error = %v, requests = %d", err, requests)
	}
}

func TestExpiredCacheFailsClosedWhenRefreshFails(t *testing.T) {
	key := generateKey(t)
	clock := &testClock{now: time.Date(2026, 9, 17, 15, 0, 0, 0, time.UTC)}
	requests := 0
	cache, err := newWithClock(testClient(roundTripFunc(func(_ *http.Request) (*http.Response, error) {
		requests++
		if requests > 1 {
			return nil, errors.New("network unavailable")
		}
		result := response(jwks(t, map[string]*rsa.PublicKey{"trusted": &key.PublicKey}))
		result.Header.Set("Cache-Control", "public, max-age=60, must-revalidate")
		return result, nil
	})), clock.Time)
	if err != nil {
		t.Fatal(err)
	}
	if err := cache.Refresh(context.Background()); err != nil {
		t.Fatal(err)
	}
	clock.Advance(61 * time.Second)
	if _, ok := cache.Resolve("trusted"); ok {
		t.Fatal("Resolve() returned an expired key")
	}
	claims, policy := tokenFixture(clock.Time())
	_, err = cache.Verify(context.Background(), sign(t, "trusted", key, claims), policy, clock.Time())
	if !errors.Is(err, ErrFetch) {
		t.Fatalf("Verify() error = %v, want ErrFetch", err)
	}
}

func TestFailedRefreshDoesNotReplaceFreshCache(t *testing.T) {
	key := generateKey(t)
	requests := 0
	cache, err := New(testClient(roundTripFunc(func(_ *http.Request) (*http.Response, error) {
		requests++
		if requests == 1 {
			return response(jwks(t, map[string]*rsa.PublicKey{"trusted": &key.PublicKey})), nil
		}
		return &http.Response{
			StatusCode: http.StatusServiceUnavailable,
			Header:     http.Header{},
			Body:       io.NopCloser(strings.NewReader("unavailable")),
		}, nil
	})))
	if err != nil {
		t.Fatal(err)
	}
	if err := cache.Refresh(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err := cache.Refresh(context.Background()); !errors.Is(err, ErrFetch) {
		t.Fatalf("second Refresh() error = %v, want ErrFetch", err)
	}
	if _, ok := cache.Resolve("trusted"); !ok {
		t.Fatal("failed refresh replaced a still-fresh cache")
	}
}

func TestRefreshRejectsInvalidResponses(t *testing.T) {
	key := generateKey(t)
	valid := jwks(t, map[string]*rsa.PublicKey{"key-1": &key.PublicKey})
	tests := []struct {
		name     string
		response *http.Response
	}{
		{name: "redirect", response: &http.Response{StatusCode: http.StatusFound, Header: http.Header{}, Body: io.NopCloser(strings.NewReader(""))}},
		{name: "wrong content type", response: func() *http.Response {
			result := response(valid)
			result.Header.Set("Content-Type", "text/plain")
			return result
		}()},
		{name: "missing must-revalidate", response: func() *http.Response {
			result := response(valid)
			result.Header.Set("Cache-Control", "public, max-age=3600")
			return result
		}()},
		{name: "no-store", response: func() *http.Response {
			result := response(valid)
			result.Header.Set("Cache-Control", "max-age=3600, must-revalidate, no-store")
			return result
		}()},
		{name: "already stale", response: func() *http.Response {
			result := response(valid)
			result.Header.Set("Age", "3600")
			return result
		}()},
		{name: "oversized", response: response(strings.Repeat("x", maximumBodyBytes+1))},
		{name: "duplicate top-level field", response: response(`{"keys":[],"keys":[]}`)},
		{name: "empty keys", response: response(`{"keys":[]}`)},
		{name: "duplicate kid", response: response(duplicateKeySet(t, &key.PublicKey))},
		{name: "weak RSA key", response: response(`{"keys":[{"kty":"RSA","alg":"RS256","use":"sig","kid":"weak","n":"Aw","e":"Aw"}]}`)},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			cache, err := New(testClient(roundTripFunc(func(_ *http.Request) (*http.Response, error) {
				return test.response, nil
			})))
			if err != nil {
				t.Fatal(err)
			}
			if err := cache.Refresh(context.Background()); err == nil {
				t.Fatal("Refresh() error = nil")
			}
		})
	}
}

func duplicateKeySet(t *testing.T, key *rsa.PublicKey) string {
	t.Helper()
	entry := map[string]string{
		"kty": "RSA", "alg": "RS256", "use": "sig", "kid": "same",
		"n": base64.RawURLEncoding.EncodeToString(key.N.Bytes()),
		"e": base64.RawURLEncoding.EncodeToString(bigEndian(key.E)),
	}
	encoded, err := json.Marshal(map[string]any{"keys": []any{entry, entry}})
	if err != nil {
		t.Fatal(err)
	}
	return string(encoded)
}

func tokenFixture(now time.Time) (map[string]any, githuboidc.Policy) {
	subject := "repo:EdwinJdevops@262093906/kube-release-envelope@1369974887:environment:production"
	workflowRef := "EdwinJdevops/kube-release-envelope/.github/workflows/release.yml@refs/heads/main"
	sha := "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	claims := map[string]any{
		"iss": githuboidc.Issuer, "aud": "release-envelope", "sub": subject,
		"repository": "EdwinJdevops/kube-release-envelope", "repository_id": "1369974887",
		"repository_owner_id": "262093906", "sha": sha, "ref": "refs/heads/main",
		"workflow_ref": workflowRef, "workflow_sha": sha, "environment": "production",
		"event_name": "workflow_dispatch", "runner_environment": "github-hosted",
		"actor_id": "262093906", "run_id": "35190000000", "run_attempt": "1", "jti": "token-unique-id",
		"iat": now.Add(-time.Minute).Unix(), "nbf": now.Add(-time.Minute).Unix(), "exp": now.Add(4 * time.Minute).Unix(),
	}
	environment := "production"
	policy := githuboidc.Policy{
		Audience: "release-envelope", Subject: subject,
		RepositoryID: "1369974887", RepositoryOwnerID: "262093906",
		SourceSHA: sha, Ref: "refs/heads/main",
		Workflow:            githuboidc.WorkflowIdentity{Ref: workflowRef, SHA: sha},
		ExpectedEnvironment: &environment, EventName: "workflow_dispatch",
		RunnerEnvironment: "github-hosted", MaxTokenAge: 5 * time.Minute, ClockSkew: 10 * time.Second,
	}
	return claims, policy
}

func sign(t *testing.T, kid string, key *rsa.PrivateKey, claims map[string]any) string {
	t.Helper()
	headerJSON, err := json.Marshal(map[string]string{"alg": "RS256", "kid": kid, "typ": "JWT"})
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
	return fmt.Sprintf("%s.%s.%s", header, payload, base64.RawURLEncoding.EncodeToString(signature))
}

// Package githubjwks retrieves and caches GitHub Actions OIDC signing keys.
package githubjwks

import (
	"bytes"
	"context"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/big"
	"mime"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/EdwinJdevops/kube-release-envelope/internal/githuboidc"
)

const Endpoint = "https://token.actions.githubusercontent.com/.well-known/jwks"

const (
	maximumBodyBytes      = 64 << 10
	maximumKeyCount       = 32
	maximumKeyIDBytes     = 256
	maximumCacheLifetime  = time.Hour
	unknownRefreshBackoff = 30 * time.Second
	maximumHTTPTimeout    = 30 * time.Second
)

var (
	ErrInvalidConfiguration = errors.New("invalid GitHub JWKS configuration")
	ErrFetch                = errors.New("GitHub JWKS fetch failed")
	ErrInvalidSet           = errors.New("invalid GitHub JWKS")
)

// Cache is a concurrency-safe, fail-closed cache of GitHub Actions OIDC keys.
// It never returns keys after their HTTP freshness lifetime has expired.
type Cache struct {
	client http.Client
	now    func() time.Time

	mu                 sync.RWMutex
	keys               map[string]*rsa.PublicKey
	expiresAt          time.Time
	lastUnknownRefresh time.Time

	refreshMu sync.Mutex
}

// New creates a cache that retrieves keys only from Endpoint. The supplied
// client must have a finite timeout; redirects are disabled by the cache.
func New(client *http.Client) (*Cache, error) {
	return newWithClock(client, time.Now)
}

func newWithClock(client *http.Client, now func() time.Time) (*Cache, error) {
	if client == nil || now == nil || client.Timeout <= 0 || client.Timeout > maximumHTTPTimeout {
		return nil, ErrInvalidConfiguration
	}
	copy := *client
	copy.CheckRedirect = func(_ *http.Request, _ []*http.Request) error {
		return http.ErrUseLastResponse
	}
	return &Cache{client: copy, now: now, keys: make(map[string]*rsa.PublicKey)}, nil
}

// Resolve implements githuboidc.KeyResolver. A missing or stale key is never
// returned. Network refresh is explicit through Refresh or Verify.
func (c *Cache) Resolve(kid string) (*rsa.PublicKey, bool) {
	if c == nil || kid == "" {
		return nil, false
	}
	c.mu.RLock()
	defer c.mu.RUnlock()
	if !c.now().UTC().Before(c.expiresAt) {
		return nil, false
	}
	key, ok := c.keys[kid]
	if !ok {
		return nil, false
	}
	return cloneKey(key), true
}

// Refresh replaces the cached key set only after a complete, valid response is
// received from GitHub. A failed refresh preserves the prior cache, but stale
// keys remain unusable.
func (c *Cache) Refresh(ctx context.Context) error {
	if c == nil || ctx == nil {
		return ErrInvalidConfiguration
	}
	c.refreshMu.Lock()
	defer c.refreshMu.Unlock()
	return c.fetch(ctx)
}

// Verify refreshes an empty or stale cache, verifies the token, and performs at
// most one rotation refresh for an unknown kid. Unknown-kid refreshes are
// rate-limited because kid is attacker-controlled.
func (c *Cache) Verify(ctx context.Context, token string, policy githuboidc.Policy, now time.Time) (githuboidc.Principal, error) {
	if c == nil || ctx == nil {
		return githuboidc.Principal{}, ErrInvalidConfiguration
	}
	refreshed, err := c.ensureFresh(ctx)
	if err != nil {
		return githuboidc.Principal{}, err
	}
	principal, err := githuboidc.Verify(token, c, policy, now)
	if !errors.Is(err, githuboidc.ErrUnknownKey) || refreshed {
		return principal, err
	}

	rotated, err := c.refreshUnknown(ctx)
	if err != nil {
		return githuboidc.Principal{}, err
	}
	if !rotated {
		return githuboidc.Principal{}, githuboidc.ErrUnknownKey
	}
	return githuboidc.Verify(token, c, policy, now)
}

func (c *Cache) ensureFresh(ctx context.Context) (bool, error) {
	if c.fresh() {
		return false, nil
	}
	c.refreshMu.Lock()
	defer c.refreshMu.Unlock()
	if c.fresh() {
		return false, nil
	}
	if err := c.fetch(ctx); err != nil {
		return false, err
	}
	return true, nil
}

func (c *Cache) refreshUnknown(ctx context.Context) (bool, error) {
	c.refreshMu.Lock()
	defer c.refreshMu.Unlock()

	c.mu.RLock()
	lastRefresh := c.lastUnknownRefresh
	c.mu.RUnlock()
	now := c.now().UTC()
	if !lastRefresh.IsZero() && now.Sub(lastRefresh) < unknownRefreshBackoff {
		return false, nil
	}
	c.mu.Lock()
	c.lastUnknownRefresh = now
	c.mu.Unlock()
	if err := c.fetch(ctx); err != nil {
		return false, err
	}
	return true, nil
}

func (c *Cache) fresh() bool {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return len(c.keys) > 0 && c.now().UTC().Before(c.expiresAt)
}

func (c *Cache) fetch(ctx context.Context) error {
	requestedAt := c.now().UTC()
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, Endpoint, nil)
	if err != nil {
		return fmt.Errorf("%w: create request: %v", ErrFetch, err)
	}
	request.Header.Set("Accept", "application/json")
	request.Header.Set("User-Agent", "kube-release-envelope/github-jwks")

	response, err := c.client.Do(request)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrFetch, err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return fmt.Errorf("%w: unexpected HTTP status %d", ErrFetch, response.StatusCode)
	}
	mediaType, _, err := mime.ParseMediaType(response.Header.Get("Content-Type"))
	if err != nil || mediaType != "application/json" {
		return fmt.Errorf("%w: Content-Type must be application/json", ErrInvalidSet)
	}
	lifetime, err := freshnessLifetime(response.Header)
	if err != nil {
		return err
	}
	body, err := io.ReadAll(io.LimitReader(response.Body, maximumBodyBytes+1))
	if err != nil {
		return fmt.Errorf("%w: read response: %v", ErrFetch, err)
	}
	if len(body) > maximumBodyBytes {
		return fmt.Errorf("%w: response exceeds %d bytes", ErrInvalidSet, maximumBodyBytes)
	}
	keys, err := parse(body)
	if err != nil {
		return err
	}

	if !c.now().UTC().Before(requestedAt.Add(lifetime)) {
		return fmt.Errorf("%w: response became stale while being read", ErrInvalidSet)
	}
	c.mu.Lock()
	c.keys = keys
	c.expiresAt = requestedAt.Add(lifetime)
	c.mu.Unlock()
	return nil
}

func freshnessLifetime(header http.Header) (time.Duration, error) {
	var (
		maxAgeSeconds  uint64
		hasMaxAge      bool
		mustRevalidate bool
	)
	for _, field := range header.Values("Cache-Control") {
		for _, rawDirective := range strings.Split(field, ",") {
			directive := strings.TrimSpace(rawDirective)
			name, value, hasValue := strings.Cut(directive, "=")
			switch strings.ToLower(strings.TrimSpace(name)) {
			case "must-revalidate":
				if hasValue {
					return 0, fmt.Errorf("%w: invalid must-revalidate directive", ErrInvalidSet)
				}
				mustRevalidate = true
			case "no-cache", "no-store":
				return 0, fmt.Errorf("%w: cache reuse is prohibited", ErrInvalidSet)
			case "max-age":
				if !hasValue || hasMaxAge {
					return 0, fmt.Errorf("%w: invalid max-age directive", ErrInvalidSet)
				}
				parsed, err := strconv.ParseUint(strings.Trim(strings.TrimSpace(value), `"`), 10, 64)
				if err != nil || parsed == 0 {
					return 0, fmt.Errorf("%w: invalid max-age directive", ErrInvalidSet)
				}
				maxAgeSeconds, hasMaxAge = parsed, true
			}
		}
	}
	if !hasMaxAge || !mustRevalidate {
		return 0, fmt.Errorf("%w: Cache-Control requires max-age and must-revalidate", ErrInvalidSet)
	}
	if maxAgeSeconds > uint64(maximumCacheLifetime/time.Second) {
		maxAgeSeconds = uint64(maximumCacheLifetime / time.Second)
	}
	lifetime := time.Duration(maxAgeSeconds) * time.Second
	if rawAge := header.Get("Age"); rawAge != "" {
		ageSeconds, err := strconv.ParseUint(rawAge, 10, 64)
		if err != nil {
			return 0, fmt.Errorf("%w: invalid Age header", ErrInvalidSet)
		}
		if ageSeconds >= uint64(lifetime/time.Second) {
			return 0, fmt.Errorf("%w: response is already stale", ErrInvalidSet)
		}
		lifetime -= time.Duration(ageSeconds) * time.Second
	}
	return lifetime, nil
}

func parse(data []byte) (map[string]*rsa.PublicKey, error) {
	set, err := decodeObject(data)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrInvalidSet, err)
	}
	rawKeys, ok := set["keys"]
	if !ok {
		return nil, fmt.Errorf("%w: keys member is required", ErrInvalidSet)
	}
	var entries []json.RawMessage
	if err := json.Unmarshal(rawKeys, &entries); err != nil || len(entries) == 0 || len(entries) > maximumKeyCount {
		return nil, fmt.Errorf("%w: key count must be within [1, %d]", ErrInvalidSet, maximumKeyCount)
	}

	keys := make(map[string]*rsa.PublicKey, len(entries))
	for index, raw := range entries {
		jwk, err := decodeObject(raw)
		if err != nil {
			return nil, fmt.Errorf("%w: key %d: %v", ErrInvalidSet, index, err)
		}
		keyID := stringValue(jwk, "kid")
		if keyID == "" || len(keyID) > maximumKeyIDBytes {
			return nil, fmt.Errorf("%w: key %d has invalid kid", ErrInvalidSet, index)
		}
		if _, exists := keys[keyID]; exists {
			return nil, fmt.Errorf("%w: duplicate kid %q", ErrInvalidSet, keyID)
		}
		if stringValue(jwk, "kty") != "RSA" || stringValue(jwk, "alg") != "RS256" || stringValue(jwk, "use") != "sig" {
			return nil, fmt.Errorf("%w: key %q is not an RS256 signing key", ErrInvalidSet, keyID)
		}
		key, err := rsaKey(stringValue(jwk, "n"), stringValue(jwk, "e"))
		if err != nil {
			return nil, fmt.Errorf("%w: key %q: %v", ErrInvalidSet, keyID, err)
		}
		keys[keyID] = key
	}
	return keys, nil
}

func rsaKey(modulus, exponent string) (*rsa.PublicKey, error) {
	modulusBytes, err := decodeBase64URLUInt(modulus)
	if err != nil || modulusBytes[0] == 0 {
		return nil, errors.New("invalid RSA modulus")
	}
	exponentBytes, err := decodeBase64URLUInt(exponent)
	if err != nil || exponentBytes[0] == 0 {
		return nil, errors.New("invalid RSA exponent")
	}
	n := new(big.Int).SetBytes(modulusBytes)
	eBig := new(big.Int).SetBytes(exponentBytes)
	if n.BitLen() < 2048 || n.Bit(0) == 0 || !eBig.IsInt64() {
		return nil, errors.New("RSA key strength is insufficient")
	}
	e := eBig.Int64()
	if e < 3 || e > 1<<31-1 || e%2 == 0 {
		return nil, errors.New("invalid RSA exponent")
	}
	return &rsa.PublicKey{N: n, E: int(e)}, nil
}

func decodeBase64URLUInt(value string) ([]byte, error) {
	if value == "" || strings.Contains(value, "=") {
		return nil, errors.New("empty or padded base64url integer")
	}
	decoded, err := base64.RawURLEncoding.DecodeString(value)
	if err != nil || len(decoded) == 0 || base64.RawURLEncoding.EncodeToString(decoded) != value {
		return nil, errors.New("invalid base64url integer")
	}
	return decoded, nil
}

func decodeObject(data []byte) (map[string]json.RawMessage, error) {
	decoder := json.NewDecoder(bytes.NewReader(data))
	token, err := decoder.Token()
	if err != nil || token != json.Delim('{') {
		return nil, errors.New("expected JSON object")
	}
	object := make(map[string]json.RawMessage)
	for decoder.More() {
		keyToken, err := decoder.Token()
		if err != nil {
			return nil, err
		}
		key, ok := keyToken.(string)
		if !ok {
			return nil, errors.New("JSON object key is not a string")
		}
		if _, exists := object[key]; exists {
			return nil, fmt.Errorf("duplicate field %q", key)
		}
		var value json.RawMessage
		if err := decoder.Decode(&value); err != nil {
			return nil, err
		}
		object[key] = value
	}
	if _, err := decoder.Token(); err != nil {
		return nil, err
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return nil, errors.New("unexpected trailing JSON value")
	}
	return object, nil
}

func stringValue(object map[string]json.RawMessage, key string) string {
	var value string
	if raw, ok := object[key]; ok && json.Unmarshal(raw, &value) == nil {
		return value
	}
	return ""
}

func cloneKey(key *rsa.PublicKey) *rsa.PublicKey {
	return &rsa.PublicKey{N: new(big.Int).Set(key.N), E: key.E}
}

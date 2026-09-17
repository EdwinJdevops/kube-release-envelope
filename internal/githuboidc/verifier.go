// Package githuboidc verifies GitHub Actions OIDC tokens against exact,
// verifier-owned release policy.
package githuboidc

import (
	"bytes"
	"crypto"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strconv"
	"strings"
	"time"
)

const Issuer = "https://token.actions.githubusercontent.com"

const (
	maximumConfiguredTokenAge  = time.Hour
	maximumConfiguredClockSkew = 5 * time.Minute
)

var (
	ErrMalformedToken    = errors.New("malformed GitHub OIDC token")
	ErrUnsupportedHeader = errors.New("unsupported GitHub OIDC JOSE header")
	ErrUnknownKey        = errors.New("unknown GitHub OIDC signing key")
	ErrInvalidSignature  = errors.New("invalid GitHub OIDC signature")
	ErrInvalidTime       = errors.New("GitHub OIDC token is outside its valid time window")
	ErrPolicyMismatch    = errors.New("GitHub OIDC claims do not match release policy")
	ErrInvalidPolicy     = errors.New("invalid GitHub OIDC policy")
	ErrDuplicateField    = errors.New("duplicate JWT JSON field")
)

// KeyResolver returns public keys from verifier-owned, trusted GitHub JWKS
// state. The token's kid selects a key but never supplies trust material.
type KeyResolver interface {
	Resolve(kid string) (*rsa.PublicKey, bool)
}

type WorkflowIdentity struct {
	Ref string
	SHA string
}

// Policy contains exact values for one envelope issuance request. Empty values
// are invalid except ExpectedEnvironment and ReusableWorkflow, whose nil values
// require the corresponding claims to be absent.
type Policy struct {
	Audience            string
	Subject             string
	RepositoryID        string
	RepositoryOwnerID   string
	SourceSHA           string
	Ref                 string
	Workflow            WorkflowIdentity
	ExpectedEnvironment *string
	ReusableWorkflow    *WorkflowIdentity
	EventName           string
	RunnerEnvironment   string
	MaxTokenAge         time.Duration
	ClockSkew           time.Duration
}

// Claims is a copy of the verified GitHub identity and execution context.
type Claims struct {
	Issuer            string
	Audience          string
	Subject           string
	Repository        string
	RepositoryID      string
	RepositoryOwnerID string
	SourceSHA         string
	Ref               string
	WorkflowRef       string
	WorkflowSHA       string
	JobWorkflowRef    string
	JobWorkflowSHA    string
	Environment       string
	EventName         string
	RunnerEnvironment string
	ActorID           string
	RunID             string
	RunAttempt        string
	JTI               string
	IssuedAt          time.Time
	NotBefore         time.Time
	ExpiresAt         time.Time
}

// Principal is opaque proof that Claims passed signature, time, and policy
// verification. Its internal state cannot be modified by callers.
type Principal struct {
	claims   Claims
	verified bool
}

func (p Principal) Claims() Claims { return p.claims }

func (p Principal) Verified() bool { return p.verified }

type StaticKeyring map[string]*rsa.PublicKey

func (k StaticKeyring) Resolve(kid string) (*rsa.PublicKey, bool) {
	key, ok := k[kid]
	return key, ok
}

// Verify validates a compact JWT using RS256 and exact GitHub Actions claims.
// It performs no network access and does not accept keys embedded in the token.
func Verify(token string, keys KeyResolver, policy Policy, now time.Time) (Principal, error) {
	if err := policy.validate(); err != nil {
		return Principal{}, err
	}
	if keys == nil {
		return Principal{}, ErrUnknownKey
	}

	parts := strings.Split(token, ".")
	if len(parts) != 3 || parts[0] == "" || parts[1] == "" || parts[2] == "" {
		return Principal{}, ErrMalformedToken
	}
	headerJSON, err := decodeSegment(parts[0])
	if err != nil {
		return Principal{}, err
	}
	header, err := decodeObject(headerJSON)
	if err != nil {
		return Principal{}, errors.Join(ErrMalformedToken, err)
	}
	if len(header) != 3 || stringValue(header, "alg") != "RS256" || stringValue(header, "typ") != "JWT" {
		return Principal{}, ErrUnsupportedHeader
	}
	kid := stringValue(header, "kid")
	if kid == "" {
		return Principal{}, ErrUnsupportedHeader
	}

	key, ok := keys.Resolve(kid)
	if !ok || key == nil {
		return Principal{}, ErrUnknownKey
	}
	if key.N == nil || key.N.BitLen() < 2048 || key.E < 3 {
		return Principal{}, ErrUnknownKey
	}
	signature, err := decodeSegment(parts[2])
	if err != nil {
		return Principal{}, err
	}
	digest := sha256.Sum256([]byte(parts[0] + "." + parts[1]))
	if err := rsa.VerifyPKCS1v15(key, crypto.SHA256, digest[:], signature); err != nil {
		return Principal{}, ErrInvalidSignature
	}

	claimsJSON, err := decodeSegment(parts[1])
	if err != nil {
		return Principal{}, err
	}
	claims, err := decodeObject(claimsJSON)
	if err != nil {
		return Principal{}, errors.Join(ErrMalformedToken, err)
	}
	principal, err := claimsPrincipal(claims, policy, now.UTC())
	if err != nil {
		return Principal{}, err
	}
	return Principal{claims: principal, verified: true}, nil
}

func (p Policy) validate() error {
	for label, value := range map[string]string{
		"audience": p.Audience, "subject": p.Subject,
		"repository ID": p.RepositoryID, "repository owner ID": p.RepositoryOwnerID,
		"source SHA": p.SourceSHA, "ref": p.Ref,
		"workflow ref": p.Workflow.Ref, "workflow SHA": p.Workflow.SHA,
		"event name": p.EventName, "runner environment": p.RunnerEnvironment,
	} {
		if strings.TrimSpace(value) == "" {
			return fmt.Errorf("%w: %s is required", ErrInvalidPolicy, label)
		}
	}
	if p.ExpectedEnvironment != nil && strings.TrimSpace(*p.ExpectedEnvironment) == "" {
		return fmt.Errorf("%w: expected environment cannot be empty", ErrInvalidPolicy)
	}
	if p.ReusableWorkflow != nil && (strings.TrimSpace(p.ReusableWorkflow.Ref) == "" || strings.TrimSpace(p.ReusableWorkflow.SHA) == "") {
		return fmt.Errorf("%w: reusable workflow ref and SHA are required together", ErrInvalidPolicy)
	}
	if p.MaxTokenAge <= 0 || p.MaxTokenAge > maximumConfiguredTokenAge {
		return fmt.Errorf("%w: maximum token age must be within (0, 1h]", ErrInvalidPolicy)
	}
	if p.ClockSkew < 0 || p.ClockSkew > maximumConfiguredClockSkew {
		return fmt.Errorf("%w: clock skew must be within [0, 5m]", ErrInvalidPolicy)
	}
	return nil
}

func claimsPrincipal(claims map[string]json.RawMessage, policy Policy, now time.Time) (Claims, error) {
	audience, err := audienceValues(claims["aud"])
	if err != nil || !contains(audience, policy.Audience) {
		return Claims{}, mismatch("audience")
	}

	p := Claims{
		Issuer:            stringValue(claims, "iss"),
		Audience:          policy.Audience,
		Subject:           stringValue(claims, "sub"),
		Repository:        stringValue(claims, "repository"),
		RepositoryID:      stringValue(claims, "repository_id"),
		RepositoryOwnerID: stringValue(claims, "repository_owner_id"),
		SourceSHA:         stringValue(claims, "sha"),
		Ref:               stringValue(claims, "ref"),
		WorkflowRef:       stringValue(claims, "workflow_ref"),
		WorkflowSHA:       stringValue(claims, "workflow_sha"),
		JobWorkflowRef:    stringValue(claims, "job_workflow_ref"),
		JobWorkflowSHA:    stringValue(claims, "job_workflow_sha"),
		Environment:       stringValue(claims, "environment"),
		EventName:         stringValue(claims, "event_name"),
		RunnerEnvironment: stringValue(claims, "runner_environment"),
		ActorID:           stringValue(claims, "actor_id"),
		RunID:             stringValue(claims, "run_id"),
		RunAttempt:        stringValue(claims, "run_attempt"),
		JTI:               stringValue(claims, "jti"),
	}

	checks := []struct {
		label, got, want string
	}{
		{"issuer", p.Issuer, Issuer}, {"subject", p.Subject, policy.Subject},
		{"repository ID", p.RepositoryID, policy.RepositoryID},
		{"repository owner ID", p.RepositoryOwnerID, policy.RepositoryOwnerID},
		{"source SHA", p.SourceSHA, policy.SourceSHA}, {"ref", p.Ref, policy.Ref},
		{"workflow ref", p.WorkflowRef, policy.Workflow.Ref}, {"workflow SHA", p.WorkflowSHA, policy.Workflow.SHA},
		{"event name", p.EventName, policy.EventName}, {"runner environment", p.RunnerEnvironment, policy.RunnerEnvironment},
	}
	for _, check := range checks {
		if check.got != check.want {
			return Claims{}, mismatch(check.label)
		}
	}
	for label, value := range map[string]string{
		"repository": p.Repository, "actor ID": p.ActorID, "run ID": p.RunID,
		"run attempt": p.RunAttempt, "token ID": p.JTI,
	} {
		if strings.TrimSpace(value) == "" {
			return Claims{}, mismatch(label)
		}
	}
	if !positiveDecimal(p.RepositoryID) || !positiveDecimal(p.RepositoryOwnerID) || !positiveDecimal(p.ActorID) || !positiveDecimal(p.RunID) || !positiveDecimal(p.RunAttempt) {
		return Claims{}, mismatch("numeric identity")
	}
	if policy.ExpectedEnvironment == nil {
		if _, present := claims["environment"]; present {
			return Claims{}, mismatch("unexpected environment")
		}
	} else if p.Environment != *policy.ExpectedEnvironment {
		return Claims{}, mismatch("environment")
	}
	if policy.ReusableWorkflow == nil {
		if _, present := claims["job_workflow_ref"]; present {
			return Claims{}, mismatch("unexpected reusable workflow")
		}
		if _, present := claims["job_workflow_sha"]; present {
			return Claims{}, mismatch("unexpected reusable workflow SHA")
		}
	} else if p.JobWorkflowRef != policy.ReusableWorkflow.Ref || p.JobWorkflowSHA != policy.ReusableWorkflow.SHA {
		return Claims{}, mismatch("reusable workflow")
	}

	iat, err := numericDate(claims, "iat")
	if err != nil {
		return Claims{}, err
	}
	nbf, err := numericDate(claims, "nbf")
	if err != nil {
		return Claims{}, err
	}
	exp, err := numericDate(claims, "exp")
	if err != nil {
		return Claims{}, err
	}
	if !exp.After(iat) || !exp.After(nbf) || now.Add(policy.ClockSkew).Before(nbf) || !now.Add(-policy.ClockSkew).Before(exp) || iat.After(now.Add(policy.ClockSkew)) || now.Sub(iat) > policy.MaxTokenAge+policy.ClockSkew {
		return Claims{}, ErrInvalidTime
	}
	p.IssuedAt, p.NotBefore, p.ExpiresAt = iat, nbf, exp
	return p, nil
}

func decodeSegment(segment string) ([]byte, error) {
	decoded, err := base64.RawURLEncoding.DecodeString(segment)
	if err != nil || len(decoded) == 0 {
		return nil, ErrMalformedToken
	}
	return decoded, nil
}

func decodeObject(data []byte) (map[string]json.RawMessage, error) {
	decoder := json.NewDecoder(bytes.NewReader(data))
	token, err := decoder.Token()
	if err != nil || token != json.Delim('{') {
		return nil, ErrMalformedToken
	}
	object := make(map[string]json.RawMessage)
	for decoder.More() {
		keyToken, err := decoder.Token()
		if err != nil {
			return nil, err
		}
		key, ok := keyToken.(string)
		if !ok {
			return nil, ErrMalformedToken
		}
		if _, exists := object[key]; exists {
			return nil, fmt.Errorf("%w: %q", ErrDuplicateField, key)
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
		return nil, ErrMalformedToken
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

func audienceValues(raw json.RawMessage) ([]string, error) {
	var single string
	if json.Unmarshal(raw, &single) == nil && single != "" {
		return []string{single}, nil
	}
	var multiple []string
	if json.Unmarshal(raw, &multiple) != nil || len(multiple) == 0 {
		return nil, ErrMalformedToken
	}
	for _, value := range multiple {
		if value == "" {
			return nil, ErrMalformedToken
		}
	}
	return multiple, nil
}

func numericDate(claims map[string]json.RawMessage, key string) (time.Time, error) {
	raw, ok := claims[key]
	if !ok {
		return time.Time{}, ErrInvalidTime
	}
	text := string(raw)
	seconds, err := strconv.ParseInt(text, 10, 64)
	if err != nil || seconds <= 0 {
		return time.Time{}, ErrInvalidTime
	}
	return time.Unix(seconds, 0).UTC(), nil
}

func contains(values []string, wanted string) bool {
	for _, value := range values {
		if value == wanted {
			return true
		}
	}
	return false
}

func positiveDecimal(value string) bool {
	parsed, err := strconv.ParseUint(value, 10, 64)
	return err == nil && parsed > 0
}

func mismatch(field string) error {
	return fmt.Errorf("%w: %s", ErrPolicyMismatch, field)
}

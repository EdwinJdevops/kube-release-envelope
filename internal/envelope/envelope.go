package envelope

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/EdwinJdevops/kube-release-envelope/internal/artifact"
	"github.com/EdwinJdevops/kube-release-envelope/internal/githuboidc"
)

const VersionV0Alpha1 = "release-envelope.dev/v0alpha1"

type Envelope struct {
	Version           string      `json:"version"`
	DeploymentID      string      `json:"deploymentId"`
	Identity          Identity    `json:"identity"`
	Target            Target      `json:"target"`
	SourceRevision    string      `json:"sourceRevision"`
	ManifestSetDigest string      `json:"manifestSetDigest"`
	Artifacts         []string    `json:"artifacts"`
	NotBefore         time.Time   `json:"notBefore"`
	ExpiresAt         time.Time   `json:"expiresAt"`
	Operations        []Operation `json:"operations"`
}

type Identity struct {
	Issuer            string `json:"issuer"`
	Audience          string `json:"audience"`
	Subject           string `json:"subject"`
	Repository        string `json:"repository"`
	RepositoryID      string `json:"repositoryId"`
	RepositoryOwnerID string `json:"repositoryOwnerId"`
	ActorID           string `json:"actorId"`
	WorkflowRef       string `json:"workflowRef"`
	WorkflowSHA       string `json:"workflowSha"`
	JobWorkflowRef    string `json:"jobWorkflowRef"`
	JobWorkflowSHA    string `json:"jobWorkflowSha"`
	Ref               string `json:"ref"`
	Environment       string `json:"environment"`
	EventName         string `json:"eventName"`
	RunnerEnvironment string `json:"runnerEnvironment"`
	RunID             string `json:"runId"`
	RunAttempt        string `json:"runAttempt"`
	TokenID           string `json:"tokenId"`
}

type Target struct {
	ClusterID string `json:"clusterId"`
	Namespace string `json:"namespace"`
}

type Operation struct {
	Verb      string `json:"verb"`
	APIGroup  string `json:"apiGroup"`
	Resource  string `json:"resource"`
	Namespace string `json:"namespace"`
	Name      string `json:"name"`
}

type SignedEnvelope struct {
	Envelope  Envelope `json:"envelope"`
	KeyID     string   `json:"keyId"`
	Signature string   `json:"signature"`
}

func (e Envelope) Validate() error {
	var problems []string
	if e.Version != VersionV0Alpha1 {
		problems = append(problems, "unsupported version")
	}
	for label, value := range map[string]string{
		"deployment ID": e.DeploymentID, "issuer": e.Identity.Issuer,
		"audience": e.Identity.Audience, "subject": e.Identity.Subject,
		"repository": e.Identity.Repository, "repository ID": e.Identity.RepositoryID,
		"repository owner ID": e.Identity.RepositoryOwnerID, "actor ID": e.Identity.ActorID,
		"workflow ref": e.Identity.WorkflowRef, "workflow SHA": e.Identity.WorkflowSHA,
		"ref": e.Identity.Ref, "event name": e.Identity.EventName,
		"runner environment": e.Identity.RunnerEnvironment, "run ID": e.Identity.RunID,
		"run attempt": e.Identity.RunAttempt, "token ID": e.Identity.TokenID,
		"cluster ID":       e.Target.ClusterID,
		"target namespace": e.Target.Namespace, "source revision": e.SourceRevision,
	} {
		if strings.TrimSpace(value) == "" {
			problems = append(problems, label+" is required")
		}
	}
	if !positiveDecimal(e.Identity.RepositoryID) || !positiveDecimal(e.Identity.RepositoryOwnerID) || !positiveDecimal(e.Identity.ActorID) || !positiveDecimal(e.Identity.RunID) || !positiveDecimal(e.Identity.RunAttempt) {
		problems = append(problems, "GitHub numeric identity fields must be positive decimal integers")
	}
	if (e.Identity.JobWorkflowRef == "") != (e.Identity.JobWorkflowSHA == "") {
		problems = append(problems, "reusable workflow ref and SHA must be present together")
	}
	if !validSHA256(e.ManifestSetDigest) {
		problems = append(problems, "manifest-set digest must be lowercase sha256")
	}
	if e.Artifacts == nil {
		problems = append(problems, "artifacts must be an array")
	}
	seenArtifacts := make(map[string]struct{}, len(e.Artifacts))
	for i, reference := range e.Artifacts {
		if err := artifact.ValidatePinnedReference(reference); err != nil {
			problems = append(problems, fmt.Sprintf("artifact %d: %v", i, err))
		}
		if _, ok := seenArtifacts[reference]; ok {
			problems = append(problems, fmt.Sprintf("artifact %d: duplicate artifact", i))
		}
		seenArtifacts[reference] = struct{}{}
	}
	if e.NotBefore.IsZero() || e.ExpiresAt.IsZero() || !e.ExpiresAt.After(e.NotBefore) {
		problems = append(problems, "validity window must be non-zero and increasing")
	}
	if len(e.Operations) == 0 {
		problems = append(problems, "at least one operation is required")
	}
	seen := make(map[string]struct{}, len(e.Operations))
	for i, op := range e.Operations {
		if err := op.validate(e.Target.Namespace); err != nil {
			problems = append(problems, fmt.Sprintf("operation %d: %v", i, err))
		}
		key := operationKey(op)
		if _, ok := seen[key]; ok {
			problems = append(problems, fmt.Sprintf("operation %d: duplicate operation", i))
		}
		seen[key] = struct{}{}
	}
	if len(problems) > 0 {
		return errors.New(strings.Join(problems, "; "))
	}
	return nil
}

func (op Operation) validate(targetNamespace string) error {
	switch op.Verb {
	case "create", "update", "patch", "delete":
	default:
		return fmt.Errorf("unsupported verb %q", op.Verb)
	}
	if strings.TrimSpace(op.Resource) == "" || strings.TrimSpace(op.Name) == "" {
		return errors.New("resource and name are required")
	}
	if op.Namespace != targetNamespace {
		return errors.New("operation namespace differs from target namespace")
	}
	return nil
}

func (e Envelope) CanonicalBytes() ([]byte, error) {
	if err := e.Validate(); err != nil {
		return nil, err
	}
	c := e
	c.NotBefore = c.NotBefore.UTC().Truncate(0)
	c.ExpiresAt = c.ExpiresAt.UTC().Truncate(0)
	c.Artifacts = append([]string(nil), e.Artifacts...)
	sort.Strings(c.Artifacts)
	c.Operations = append([]Operation(nil), e.Operations...)
	sort.Slice(c.Operations, func(i, j int) bool { return operationKey(c.Operations[i]) < operationKey(c.Operations[j]) })
	return json.Marshal(c)
}

func sign(e Envelope, keyID string, privateKey ed25519.PrivateKey) (SignedEnvelope, error) {
	if strings.TrimSpace(keyID) == "" {
		return SignedEnvelope{}, errors.New("key ID is required")
	}
	if len(privateKey) != ed25519.PrivateKeySize {
		return SignedEnvelope{}, errors.New("invalid Ed25519 private key")
	}
	payload, err := e.CanonicalBytes()
	if err != nil {
		return SignedEnvelope{}, err
	}
	return SignedEnvelope{Envelope: e, KeyID: keyID, Signature: hex.EncodeToString(ed25519.Sign(privateKey, payload))}, nil
}

var (
	ErrUnverifiedGitHubIdentity = errors.New("GitHub OIDC identity is not verified")
	ErrSourceRevisionMismatch   = errors.New("source revision does not match GitHub OIDC token")
	ErrIdentityWindowMismatch   = errors.New("envelope validity exceeds GitHub OIDC token validity")
	ErrTokenConsumerRequired    = errors.New("GitHub OIDC token consumer is required")
	ErrTokenReplay              = errors.New("GitHub OIDC token has already been consumed")
	ErrTokenConsumption         = errors.New("GitHub OIDC token consumption failed")
)

// TokenConsumer atomically marks one issuer/JTI pair as consumed through its
// expiry. Implementations return consumed=false without an error for a replay;
// storage failures must return an error and fail issuance closed.
type TokenConsumer interface {
	Consume(issuer, jti string, expiresAt time.Time) (consumed bool, err error)
}

// IssueGitHub binds an envelope to an opaque, verified GitHub OIDC principal.
// It consumes the token only after all other envelope checks pass.
func IssueGitHub(e Envelope, principal githuboidc.Principal, consumed TokenConsumer, keyID string, privateKey ed25519.PrivateKey) (SignedEnvelope, error) {
	if !principal.Verified() {
		return SignedEnvelope{}, ErrUnverifiedGitHubIdentity
	}
	if consumed == nil {
		return SignedEnvelope{}, ErrTokenConsumerRequired
	}
	claims := principal.Claims()
	if e.SourceRevision != claims.SourceSHA {
		return SignedEnvelope{}, ErrSourceRevisionMismatch
	}
	if e.NotBefore.Before(claims.NotBefore) || e.ExpiresAt.After(claims.ExpiresAt) {
		return SignedEnvelope{}, ErrIdentityWindowMismatch
	}
	e.Identity = Identity{
		Issuer: claims.Issuer, Audience: claims.Audience, Subject: claims.Subject,
		Repository: claims.Repository, RepositoryID: claims.RepositoryID, RepositoryOwnerID: claims.RepositoryOwnerID,
		ActorID: claims.ActorID, WorkflowRef: claims.WorkflowRef, WorkflowSHA: claims.WorkflowSHA,
		JobWorkflowRef: claims.JobWorkflowRef, JobWorkflowSHA: claims.JobWorkflowSHA,
		Ref: claims.Ref, Environment: claims.Environment, EventName: claims.EventName,
		RunnerEnvironment: claims.RunnerEnvironment, RunID: claims.RunID, RunAttempt: claims.RunAttempt,
		TokenID: claims.JTI,
	}
	payload, err := e.CanonicalBytes()
	if err != nil {
		return SignedEnvelope{}, err
	}
	if strings.TrimSpace(keyID) == "" {
		return SignedEnvelope{}, errors.New("key ID is required")
	}
	if len(privateKey) != ed25519.PrivateKeySize {
		return SignedEnvelope{}, errors.New("invalid Ed25519 private key")
	}
	wasConsumed, err := consumed.Consume(claims.Issuer, claims.JTI, claims.ExpiresAt)
	if err != nil {
		return SignedEnvelope{}, errors.Join(ErrTokenConsumption, err)
	}
	if !wasConsumed {
		return SignedEnvelope{}, ErrTokenReplay
	}
	return SignedEnvelope{Envelope: e, KeyID: keyID, Signature: hex.EncodeToString(ed25519.Sign(privateKey, payload))}, nil
}

func Verify(s SignedEnvelope, publicKey ed25519.PublicKey, now time.Time) error {
	if strings.TrimSpace(s.KeyID) == "" {
		return errors.New("key ID is required")
	}
	if len(publicKey) != ed25519.PublicKeySize {
		return errors.New("invalid Ed25519 public key")
	}
	sig, err := hex.DecodeString(s.Signature)
	if err != nil || len(sig) != ed25519.SignatureSize {
		return errors.New("invalid signature encoding")
	}
	payload, err := s.Envelope.CanonicalBytes()
	if err != nil {
		return err
	}
	if !ed25519.Verify(publicKey, payload, sig) {
		return errors.New("signature verification failed")
	}
	now = now.UTC()
	if now.Before(s.Envelope.NotBefore) {
		return errors.New("envelope is not yet valid")
	}
	if !now.Before(s.Envelope.ExpiresAt) {
		return errors.New("envelope is expired")
	}
	return nil
}

// Authorizes reports whether the exact API operation is present in the envelope.
// It deliberately performs no wildcard matching.
func (e Envelope) Authorizes(request Operation) bool {
	if request.validate(e.Target.Namespace) != nil {
		return false
	}
	wanted := operationKey(request)
	for _, allowed := range e.Operations {
		if operationKey(allowed) == wanted {
			return true
		}
	}
	return false
}

func (e Envelope) MatchesManifestSet(canonicalManifests []byte) bool {
	return e.ManifestSetDigest == ManifestSetDigest(canonicalManifests)
}

func (e Envelope) MatchesArtifacts(references []string) bool {
	if len(e.Artifacts) != len(references) {
		return false
	}
	want := append([]string(nil), e.Artifacts...)
	got := append([]string(nil), references...)
	sort.Strings(want)
	sort.Strings(got)
	for i := range want {
		if want[i] != got[i] {
			return false
		}
	}
	return true
}

func ManifestSetDigest(canonicalManifests []byte) string {
	sum := sha256.Sum256(canonicalManifests)
	return "sha256:" + hex.EncodeToString(sum[:])
}

func Decode(data []byte) (SignedEnvelope, error) {
	var signed SignedEnvelope
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&signed); err != nil {
		return SignedEnvelope{}, err
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		if err == nil {
			return SignedEnvelope{}, errors.New("multiple JSON values")
		}
		return SignedEnvelope{}, err
	}
	return signed, nil
}

func validSHA256(value string) bool {
	if !strings.HasPrefix(value, "sha256:") || len(value) != len("sha256:")+64 {
		return false
	}
	decoded, err := hex.DecodeString(strings.TrimPrefix(value, "sha256:"))
	return err == nil && len(decoded) == sha256.Size && value == strings.ToLower(value)
}

func positiveDecimal(value string) bool {
	parsed, err := strconv.ParseUint(value, 10, 64)
	return err == nil && parsed > 0
}

func operationKey(op Operation) string {
	return strings.Join([]string{op.APIGroup, op.Resource, op.Namespace, op.Name, op.Verb}, "\x00")
}

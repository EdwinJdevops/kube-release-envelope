// Package artifact extracts immutable container image identities from the
// Kubernetes resource kinds explicitly supported by this protocol version.
package artifact

import (
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"sort"
	"strings"

	"github.com/EdwinJdevops/kube-release-envelope/internal/manifest"
)

var (
	ErrInvalidReference = errors.New("container image is not an explicit registry/repository@sha256 digest")
	ErrUnsupportedKind  = errors.New("resource kind is not covered by artifact inspection")
	ErrInvalidWorkload  = errors.New("workload pod specification is invalid")
)

var (
	registryPattern   = regexp.MustCompile(`^[a-z0-9.-]+(?::[0-9]+)?$`)
	repositoryPattern = regexp.MustCompile(`^[a-z0-9]+(?:[._-][a-z0-9]+)*$`)
)

type kindKey struct {
	apiVersion string
	kind       string
}

var podSpecPaths = map[kindKey][]string{
	{apiVersion: "v1", kind: "Pod"}:              {"spec"},
	{apiVersion: "apps/v1", kind: "Deployment"}:  {"spec", "template", "spec"},
	{apiVersion: "apps/v1", kind: "StatefulSet"}: {"spec", "template", "spec"},
	{apiVersion: "apps/v1", kind: "DaemonSet"}:   {"spec", "template", "spec"},
	{apiVersion: "apps/v1", kind: "ReplicaSet"}:  {"spec", "template", "spec"},
	{apiVersion: "batch/v1", kind: "Job"}:        {"spec", "template", "spec"},
	{apiVersion: "batch/v1", kind: "CronJob"}:    {"spec", "jobTemplate", "spec", "template", "spec"},
}

var imageFreeKinds = map[kindKey]struct{}{
	{apiVersion: "v1", kind: "ConfigMap"}: {}, {apiVersion: "v1", kind: "Secret"}: {},
	{apiVersion: "v1", kind: "Service"}: {}, {apiVersion: "v1", kind: "ServiceAccount"}: {},
	{apiVersion: "v1", kind: "PersistentVolumeClaim"}: {},
	{apiVersion: "networking.k8s.io/v1", kind: "Ingress"}: {},
	{apiVersion: "networking.k8s.io/v1", kind: "NetworkPolicy"}: {},
	{apiVersion: "policy/v1", kind: "PodDisruptionBudget"}: {},
	{apiVersion: "autoscaling/v2", kind: "HorizontalPodAutoscaler"}: {},
	{apiVersion: "rbac.authorization.k8s.io/v1", kind: "Role"}: {},
	{apiVersion: "rbac.authorization.k8s.io/v1", kind: "RoleBinding"}: {},
	{apiVersion: "rbac.authorization.k8s.io/v1", kind: "ClusterRole"}: {},
	{apiVersion: "rbac.authorization.k8s.io/v1", kind: "ClusterRoleBinding"}: {},
}

// ValidatePinnedReference accepts a deliberately narrow image-reference subset:
// a lowercase, explicit registry and repository followed by @sha256:<64 hex>.
// Tags, implicit registries, and alternative digest algorithms are rejected.
func ValidatePinnedReference(reference string) error {
	if reference != strings.TrimSpace(reference) || strings.Count(reference, "@") != 1 {
		return ErrInvalidReference
	}
	name, digest, _ := strings.Cut(reference, "@")
	if strings.ToLower(reference) != reference || !validSHA256(digest) {
		return ErrInvalidReference
	}
	parts := strings.Split(name, "/")
	if len(parts) < 2 || !registryPattern.MatchString(parts[0]) {
		return ErrInvalidReference
	}
	if parts[0] != "localhost" && !strings.ContainsAny(parts[0], ".:") {
		return ErrInvalidReference
	}
	for _, part := range parts[1:] {
		if !repositoryPattern.MatchString(part) {
			return ErrInvalidReference
		}
	}
	return nil
}

// ExtractPinnedReferences returns the unique, sorted image references from all
// container, initContainer, and ephemeralContainer entries. Unknown resource
// kinds fail closed rather than being misclassified as image-free.
func ExtractPinnedReferences(canonicalSet []byte) ([]string, error) {
	if err := manifest.ValidateCanonicalSet(canonicalSet); err != nil {
		return nil, err
	}

	var objects []map[string]any
	if err := json.Unmarshal(canonicalSet, &objects); err != nil {
		return nil, err
	}
	seen := make(map[string]struct{})
	for i, object := range objects {
		apiVersion, _ := object["apiVersion"].(string)
		kind, _ := object["kind"].(string)
		key := kindKey{apiVersion: apiVersion, kind: kind}
		path, workload := podSpecPaths[key]
		if !workload {
			if _, imageFree := imageFreeKinds[key]; imageFree {
				continue
			}
			return nil, fmt.Errorf("object %d %s/%s: %w", i, apiVersion, kind, ErrUnsupportedKind)
		}

		podSpec, err := nestedMap(object, path)
		if err != nil {
			return nil, fmt.Errorf("object %d %s/%s: %w", i, apiVersion, kind, err)
		}
		for _, field := range []string{"containers", "initContainers", "ephemeralContainers"} {
			if err := collectImages(podSpec, field, seen); err != nil {
				return nil, fmt.Errorf("object %d %s/%s: %s: %w", i, apiVersion, kind, field, err)
			}
		}
	}

	references := make([]string, 0, len(seen))
	for reference := range seen {
		references = append(references, reference)
	}
	sort.Strings(references)
	return references, nil
}

func nestedMap(root map[string]any, path []string) (map[string]any, error) {
	current := root
	for _, field := range path {
		next, ok := current[field].(map[string]any)
		if !ok {
			return nil, fmt.Errorf("%w: missing object field %q", ErrInvalidWorkload, field)
		}
		current = next
	}
	return current, nil
}

func collectImages(podSpec map[string]any, field string, seen map[string]struct{}) error {
	raw, present := podSpec[field]
	if !present {
		if field == "containers" {
			return fmt.Errorf("%w: required field is absent", ErrInvalidWorkload)
		}
		return nil
	}
	containers, ok := raw.([]any)
	if !ok || (field == "containers" && len(containers) == 0) {
		return fmt.Errorf("%w: expected non-empty array", ErrInvalidWorkload)
	}
	for i, rawContainer := range containers {
		container, ok := rawContainer.(map[string]any)
		if !ok {
			return fmt.Errorf("%w: entry %d is not an object", ErrInvalidWorkload, i)
		}
		reference, ok := container["image"].(string)
		if !ok || reference == "" {
			return fmt.Errorf("%w: entry %d has no image", ErrInvalidWorkload, i)
		}
		if err := ValidatePinnedReference(reference); err != nil {
			return fmt.Errorf("entry %d image %q: %w", i, reference, err)
		}
		seen[reference] = struct{}{}
	}
	return nil
}

func validSHA256(value string) bool {
	if !strings.HasPrefix(value, "sha256:") || len(value) != len("sha256:")+64 {
		return false
	}
	decoded, err := hex.DecodeString(strings.TrimPrefix(value, "sha256:"))
	return err == nil && len(decoded) == 32
}

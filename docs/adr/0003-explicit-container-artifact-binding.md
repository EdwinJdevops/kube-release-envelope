# ADR 0003: Bind explicit container artifacts

- Status: accepted
- Date: 2026-09-17

## Context

The manifest-set digest already detects any byte-level change to canonical
pre-admission intent. It does not expose the container artifacts as independent,
queryable claims, and it does not by itself reject mutable image tags.

Kubernetes accepts image names, tags, digests, and tag-plus-digest references.
Its documentation states that tags can move, digests are fixed, and when both a
tag and digest are supplied only the digest is used for pulling:
<https://kubernetes.io/docs/concepts/containers/images/#image-names>.

Kubernetes controllers create Pods from Pod templates embedded in workload
resources. The Kubernetes Pod documentation identifies that template as part of
the workload's desired state:
<https://kubernetes.io/docs/concepts/workloads/pods/#pod-templates>.

## Decision

The v0alpha1 signed envelope carries a sorted set of complete container image
references. Each reference must use this strict subset:

`explicit-registry/repository@sha256:<64 lowercase hexadecimal characters>`

Tags are rejected even when a digest is also present. Implicit registries and
non-SHA-256 digests are also rejected. This is intentionally narrower than the
Kubernetes image grammar; it avoids two textual identities for the same pull
decision and avoids environment-dependent default-registry expansion.

Artifact extraction covers these stable built-in APIs:

- `v1/Pod`
- `apps/v1/Deployment`, `StatefulSet`, `DaemonSet`, and `ReplicaSet`
- `batch/v1/Job` and `CronJob`

For each Pod specification it inspects `containers`, `initContainers`, and
`ephemeralContainers`. Duplicate references collapse into one signed artifact
identity; the manifest-set digest still binds every occurrence and location.

The verifier accepts a deliberately small allowlist of built-in, non-workload
resource kinds. Every other kind, including custom resources, fails closed until
its artifact semantics are implemented and tested. A caller cannot label an
unknown resource as image-free.

Artifact comparison occurs only after trusted-key selection, signature/time
verification, and exact manifest-digest comparison. A valid signature over an
artifact list that differs from the images extracted from the same canonical
manifest set is rejected.

## Consequences

- A changed image digest cannot be hidden behind an otherwise valid envelope.
- Sidecars and init containers cannot escape artifact inspection.
- Common shorthand such as `nginx`, mutable tags, and tag-plus-digest syntax is
  incompatible by design.
- Custom operators and less common built-in resources are unsupported, not
  silently accepted.
- This still binds pre-admission intent. A mutating admission webhook can change
  images after this check; post-admission evidence remains separate work.

## Rejected alternatives

### Rely only on the manifest-set digest

This detects tampering but does not enforce immutable artifact identity or make
the approved artifact set explicit for later evidence correlation.

### Accept tag-plus-digest references

Kubernetes pulls by digest in that form, but retaining a mutable tag creates an
extra, non-authoritative label in signed audit evidence. The narrower form is
unambiguous.

### Recursively search every field named `image`

Field-name search is not an API contract. It can miss custom encodings and can
misclassify unrelated fields. Coverage remains explicit per GroupVersionKind.

### Accept unknown kinds and inspect known paths when present

That would turn missing coverage into silent authorization. The protocol must
fail closed.

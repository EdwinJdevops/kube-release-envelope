# ADR 0002: Canonicalize pre-admission intent separately from observed state

Status: accepted

## Decision

`v0alpha1` canonicalizes a release as an ordered JSON array of strict JSON
Kubernetes objects. Object fields are emitted in deterministic JSON key order;
objects are sorted by `apiVersion`, `kind`, namespace, and name. Array order is
preserved. Duplicate JSON fields, duplicate object identities, trailing JSON
values, unnamed objects, and `generateName` are rejected.

The resulting digest is named the **manifest intent digest**. It describes the
client's pre-admission request only. It is not evidence of the object admitted,
stored, or made healthy by Kubernetes.

YAML input is not accepted by the protocol package in this phase. A later YAML
adapter must define duplicate-key, alias, scalar-type, and multi-document
semantics before its output can enter this canonicalizer.

## Why the stages must remain separate

Kubernetes admission can mutate an object before persistence, and admission
webhooks may be reinvoked when later mutations change the object. Kubernetes
Server-Side Apply records field-manager ownership and merges submitted intent
with existing/defaulted fields; it does not attest that a whole multi-object
release equals one signed input set.

Therefore one digest cannot honestly stand for all three states:

1. rendered client intent;
2. the admitted/persisted objects; and
3. runtime outcome.

Post-admission mutation capture and runtime verification will produce separate
evidence in later increments. Missing either record must remain indeterminate.

## Security consequences

- JSON duplicate fields fail closed instead of relying on last-key-wins parsing.
- Reordering documents or object keys cannot change the digest.
- Reordering arrays does change the digest because Kubernetes list semantics
  depend on schema and cannot be inferred safely by a generic canonicalizer.
- Unnamed or server-generated object identities cannot be authorized exactly,
  so they are rejected in this version.
- Number spellings are preserved by the JSON decoder. Numerically equivalent
  spellings such as `1` and `1.0` may produce different digests; this is a safe
  false-negative, not an authorization bypass.

## Primary references

- Kubernetes dynamic admission control:
  https://kubernetes.io/docs/reference/access-authn-authz/extensible-admission-controllers/
- Kubernetes Server-Side Apply and managed fields:
  https://kubernetes.io/docs/reference/using-api/server-side-apply/
- Kubernetes API strict field validation behavior:
  https://kubernetes.io/docs/reference/using-api/api-concepts/#field-validation

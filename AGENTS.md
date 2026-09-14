# Engineering Operating Contract

## Mission

Build and falsify one narrow primitive: a signed, immutable, time-bounded
Kubernetes release envelope that constrains and later evaluates the mutations
performed for one release.

## Non-goals

Do not expand this repository into a CI system, GitOps controller, portal,
secret manager, service catalog, generic PAM product, Terraform runner,
multi-cloud platform, or AI assistant. New scope requires evidence and an ADR.

## Invariants

1. Fail closed when identity, signature, digest, time, target, or operation scope
   cannot be verified.
2. Signed bytes must be canonical and independent of input ordering.
3. A signature never substitutes for semantic validation.
4. Keys and credentials must never be committed, logged, or returned to callers.
5. Repository names are not stable identity; bind GitHub trust to numeric IDs
   where the provider exposes them.
6. Mutable image tags are not accepted as artifact identity; use digests.
7. Admission success is not deployment success. Outcome evidence is separate.
8. Missing observation data produces `indeterminate`, never `conformant`.
9. Every security claim needs an executable test or a cited primary source.
10. Never describe this prototype as production-ready.

## Change protocol

- Add tests for every invariant and regression.
- Prefer the Go standard library until a dependency provides indispensable,
  reviewed value.
- Keep pure protocol logic separate from Kubernetes, GitHub, storage, and network
  adapters.
- Record material design decisions in `docs/adr`.
- Record unverified assumptions as unknowns, not facts.
- Run formatting, tests, and static analysis before merging.
- Keep commits narrow and reviewable; do not mix research, refactors, and features.

## Resource constraints

Development must remain usable on a 4 GB machine. Unit tests are the default;
cluster tests run in CI or in an explicitly started lightweight environment.

## Definition of done for Phase 1

GitHub OIDC identity is verified; a canonical manifest set is signed; a
deployment-specific Kubernetes identity is issued without returning permanent
cluster credentials; allowed updates succeed; extra resources, forbidden deletes,
expired envelopes, and changed image digests fail; mutations are independently
recorded; outcomes are classified; both direct CI and Argo CD paths are tested.

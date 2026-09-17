# Kubernetes Release Envelope

Research prototype for authorizing a Kubernetes release as a bounded set of
mutations rather than treating each API request as unrelated.

## Status

Pre-alpha. The repository currently defines and tests the signed envelope
primitive. It is not a production authorization service and makes no claim of
preventing all deployment or supply-chain attacks.

The current verifier additionally binds immutable container image references for
the built-in workload kinds listed in ADR 0003. Unknown kinds fail closed. This
is pre-admission intent enforcement; it does not yet prove which image an
admission webhook stored or which image a node ran.

## Problem boundary

Kubernetes RBAC authorizes API requests. It does not by itself bind a reviewed
release intent, CI identity, immutable manifest-set digest, exact resource set,
expiry, admitted API mutations, and observed rollout outcome into one object.
This project tests whether that missing binding is both technically feasible and
operationally valuable.

The initial proof must reject an expired envelope, a changed manifest digest, an
extra resource, and an unapproved delete. It must independently record admitted
mutations and distinguish conformant, non-conformant, partial, and indeterminate
outcomes.

## Scope

Phase 1 targets Kubernetes deployments initiated by GitHub Actions and Argo CD.
AWS provisioning, Terraform, multi-cloud, dashboards, Backstage, AI features,
and a general policy language are explicitly out of scope.

## Repository map

- `internal/envelope`: canonicalization, validation, signing, verification.
- `docs/spec`: protocol and invariant definitions.
- `docs/adr`: architectural decisions and rejected alternatives.
- `docs/research`: evidence, uncertainties, and validation gates.

## Verification

Run `make verify` with Go 1.27 or use the GitHub Actions workflow. The core has no
third-party dependencies.

# ADR 0001: Begin with a Kubernetes release envelope

- Status: accepted
- Date: 2026-09-12

## Context

The originating practitioner discussion compared direct CI deployment with a
persistent GitOps controller. Research found that OIDC, cloud IAM, Kubernetes
RBAC, admission policy, GitOps, provenance, and deployment-observability products
solve substantial parts of the lifecycle. The defensible technical gap is much
narrower than a new deployment platform.

## Decision

Build a research-grade Kubernetes release-envelope primitive first. It binds a
requesting workload identity, source revision, immutable manifest-set digest,
target, exact allowed operations, and validity window. The signed payload is
immutable. Admission and outcome evidence will be evaluated separately.

Go is selected because Kubernetes APIs and controllers are Go-native and the
cryptographic core can be implemented without third-party dependencies.

## Consequences

The first implementation proves protocol properties only. It does not yet prove
market demand, production safety, auditor acceptance, or Kubernetes admission
integration. Those remain explicit validation gates.

## Rejected starting points

- Broad deployment-authority SaaS: demand is not verified.
- Terraform/AWS first: incumbent policy and managed-runner coverage is stronger.
- Artifact evidence dashboard: established products already correlate much of
  this evidence.
- Full Kubernetes controller first: it would hide protocol errors behind
  infrastructure complexity and exceed the target development footprint.

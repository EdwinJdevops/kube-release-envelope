# Release Envelope v0alpha1

## Security objective

Authorize one named manifest set to perform only an enumerated set of Kubernetes
operations against one cluster and namespace during a bounded interval.

## Signed payload

The signature covers every field in `Envelope`: protocol version, deployment ID,
issuer, audience, GitHub repository ID, workflow reference, source revision,
cluster, namespace, manifest-set digest, validity window, and allowed operations.
The payload also carries the complete, de-duplicated set of container image
references extracted from supported workload manifests.

GitHub-issued envelopes additionally bind the exact OIDC subject, repository and
owner numeric IDs, actor ID, workflow ref and workflow commit SHA, optional
reusable-workflow ref and SHA, source ref, environment, event, runner type, run
ID, run attempt, and token ID. Caller-provided values cannot override verified
claims.

Operations are canonicalized by API group, resource, namespace, name, and verb.
Duplicate operations are invalid. Digests use lowercase `sha256:<64 hex>` form.
The source revision is an opaque non-empty identifier because this protocol must
not hard-code Git's current object format.

The manifest-set digest binds the pre-admission intent returned by
`manifest.CanonicalizeSet`. It does not claim that Kubernetes admitted, stored,
or made healthy those exact bytes. Those facts require separate evidence.

Each artifact uses an explicit registry and repository plus a lowercase SHA-256
digest. Mutable tags, tag-plus-digest references, implicit registries, unknown
resource kinds, and malformed Pod specifications are rejected. Artifact order is
canonicalized lexicographically. Duplicate artifact entries are invalid.

## Validation order

1. Decode with unknown fields rejected.
2. Resolve GitHub signing keys through the fixed JWKS endpoint. Cached keys must
   be within their HTTP freshness lifetime; an unknown key ID permits one
   bounded rotation refresh.
3. Before issuance, verify the GitHub JWT signature using the resolved key,
   validate its time window, and match exact identity/execution claims.
4. Atomically and durably consume the GitHub issuer/token-ID pair to reject
   replay. Storage uncertainty fails issuance closed.
5. Replace all envelope identity fields with verified claims and constrain the
   envelope source revision and validity window to those claims.
6. Validate protocol and all required semantic fields.
7. Canonicalize and reject duplicates.
8. Verify the envelope signature against a trusted key selected outside the
   envelope.
9. Check the envelope validity window against verifier time.
10. Compare the observed manifest digest to the envelope.
11. Extract immutable artifacts from the canonical manifest set and compare the
   exact set to the signed artifact claims.
12. Compare the requested mutation to the envelope.

An envelope carrying a public key does not make that key trusted. Key selection
and rotation belong to the verifier's trust configuration.

## Explicitly unresolved

- YAML-to-JSON conversion semantics.
- Post-admission/defaulted object capture.
- GenerateName and controller-created child resources.
- Subresources and CRDs.
- Image-bearing custom resources and built-in workload kinds not listed in ADR
  0003.
- Safe binding between an envelope and ephemeral ServiceAccount credentials.
- Linearizable multi-replica replay consumption; the current store is limited
  to a local filesystem on one node.
- Mutation capture when webhooks fail or audit delivery is delayed.
- Runtime health semantics and observation completeness.

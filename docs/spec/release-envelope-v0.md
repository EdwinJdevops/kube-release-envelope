# Release Envelope v0alpha1

## Security objective

Authorize one named manifest set to perform only an enumerated set of Kubernetes
operations against one cluster and namespace during a bounded interval.

## Signed payload

The signature covers every field in `Envelope`: protocol version, deployment ID,
issuer, audience, GitHub repository ID, workflow reference, source revision,
cluster, namespace, manifest-set digest, validity window, and allowed operations.

Operations are canonicalized by API group, resource, namespace, name, and verb.
Duplicate operations are invalid. Digests use lowercase `sha256:<64 hex>` form.
The source revision is an opaque non-empty identifier because this protocol must
not hard-code Git's current object format.

The manifest-set digest binds the pre-admission intent returned by
`manifest.CanonicalizeSet`. It does not claim that Kubernetes admitted, stored,
or made healthy those exact bytes. Those facts require separate evidence.

## Validation order

1. Decode with unknown fields rejected.
2. Validate protocol and all required semantic fields.
3. Canonicalize and reject duplicates.
4. Verify signature against a trusted key selected outside the envelope.
5. Check the validity window against verifier time.
6. Compare the observed manifest digest and requested mutation to the envelope.

An envelope carrying a public key does not make that key trusted. Key selection
and rotation belong to the verifier's trust configuration.

## Explicitly unresolved

- YAML-to-JSON conversion semantics.
- Post-admission/defaulted object capture.
- GenerateName and controller-created child resources.
- Subresources and CRDs.
- Safe binding between an envelope and ephemeral ServiceAccount credentials.
- Mutation capture when webhooks fail or audit delivery is delayed.
- Runtime health semantics and observation completeness.

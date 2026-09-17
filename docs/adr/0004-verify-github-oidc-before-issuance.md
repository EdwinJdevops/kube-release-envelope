# ADR 0004: Verify GitHub OIDC before envelope issuance

- Status: accepted
- Date: 2026-09-17

## Context

An envelope that merely copies workflow-provided identity fields does not prove
who requested a release. GitHub's OIDC provider publishes its issuer, signing
algorithm, key-set location, and supported claims through OpenID discovery. Its
current discovery document identifies:

- issuer `https://token.actions.githubusercontent.com`;
- JWKS URI `https://token.actions.githubusercontent.com/.well-known/jwks`;
- `RS256` as the supported ID-token signing algorithm; and
- numeric repository, owner, actor, run, workflow, reusable-workflow, ref,
  environment, time, and token-ID claims.

Primary source:
<https://token.actions.githubusercontent.com/.well-known/openid-configuration>

GitHub documents that OIDC subject formats can be customized. It also documents
that repositories created after July 15, 2026 use an immutable default subject
containing owner and repository IDs, while older repositories retain the legacy
format unless they opt in. Reconstructing `sub` from repository names is
therefore unsafe and incompatible across repositories.

Primary source:
<https://docs.github.com/en/actions/reference/security/oidc>

## Decision

Envelope issuance for GitHub Actions requires an opaque `githuboidc.Principal`
returned by successful token verification. Callers cannot construct or mutate a
verified principal. The lower-level envelope signing function is not exported.

The verifier:

1. accepts compact JWT input only;
2. rejects duplicate top-level JOSE header or claim fields;
3. accepts exactly the `alg`, `kid`, and `typ` headers;
4. requires `alg=RS256` and `typ=JWT`;
5. resolves `kid` through verifier-owned key state;
6. rejects token-supplied key material and RSA keys below 2048 bits;
7. verifies the RSASSA-PKCS1-v1_5 SHA-256 signature;
8. validates `iat`, `nbf`, and `exp` against explicit maximum token age,
   maximum token lifetime, and clock-skew policy;
9. matches an exact verifier-owned audience and subject;
10. independently matches numeric repository and owner IDs;
11. matches the source SHA, ref, workflow ref, immutable workflow SHA, event,
    runner type, and optional environment;
12. requires positive numeric actor, run, and run-attempt claims;
13. rejects reusable-workflow claims unless policy explicitly expects the exact
    `job_workflow_ref` and `job_workflow_sha`; and
14. returns the `jti` for atomic replay consumption.

No wildcard or prefix policy language is added. One policy describes one exact
issuance request.

`IssueGitHub` replaces every caller-supplied identity field with verified claims,
requires the envelope source revision to equal the token's `sha`, constrains the
envelope validity window to the token validity window, and atomically consumes
the issuer/JTI pair before signing. A missing replay consumer fails closed.

## Trust boundary

The token's `kid` is an untrusted selector. It does not make a key trusted. A
future network adapter must fetch and cache keys only from the fixed GitHub JWKS
endpoint discovered for the fixed issuer, enforce TLS, handle rotation, and
define stale-cache behavior. This change supplies only the pure cryptographic and
claim-policy core plus the key-resolver interface.

The replay-consumer interface requires atomic consume-once behavior through token
expiry. An in-memory map is used only in tests. Durable or distributed replay
storage is not implemented by this change.

## Consequences

- Repository names no longer serve as the stable authorization identity.
- A valid token for another repository, workflow commit, branch, environment,
  event, runner type, or reusable workflow cannot issue the envelope.
- A signed token cannot be replayed when the configured consumer implements the
  required atomic contract.
- Envelope lifetime cannot outlive the authenticating token in v0alpha1.
- Key discovery, rotation, cache-failure semantics, and durable replay storage
  remain required before this can operate as a service.

## Rejected alternatives

### Decode claims without verifying the JWT signature

This provides metadata, not identity proof.

### Trust only the default `sub` format

Subject formats vary by repository age, immutable-subject rollout, and custom
claim templates. Exact subject matching is retained, but numeric claims are
validated independently.

### Match repository and workflow names only

Names and refs can move. Numeric repository/owner IDs and workflow commit SHAs
are required.

### Permit any reusable workflow

That would move executable deployment authority without an explicit policy
decision. Direct and reusable execution paths are distinct.

### Implement JWKS network fetching inside the protocol package

Network caching, TLS, rotation, and outage behavior are adapter concerns. Mixing
them into the pure verifier would make security tests nondeterministic.

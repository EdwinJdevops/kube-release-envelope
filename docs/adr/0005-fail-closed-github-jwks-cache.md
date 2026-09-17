# ADR 0005: Retrieve GitHub JWKS through a bounded fail-closed cache

- Status: accepted
- Date: 2026-09-17

## Context

ADR 0004 left GitHub key retrieval outside the pure JWT verifier. The verifier's
`kid` is an untrusted selector; accepting key material from the token or from a
caller-selected URL would let input choose its own trust anchor.

GitHub's OpenID configuration currently declares one JWKS URI and `RS256` as the
only supported ID-token signing algorithm. The JWKS endpoint currently returns
`Cache-Control: public, max-age=3600, must-revalidate`. HTTP caching semantics
make a response stale after its freshness lifetime and prohibit stale reuse when
`must-revalidate` applies.

Primary sources:

- GitHub OpenID configuration:
  <https://token.actions.githubusercontent.com/.well-known/openid-configuration>
- GitHub JWKS:
  <https://token.actions.githubusercontent.com/.well-known/jwks>
- JSON Web Key format, RFC 7517:
  <https://www.rfc-editor.org/rfc/rfc7517>
- RSA JWK integer encoding, RFC 7518 section 6.3:
  <https://www.rfc-editor.org/rfc/rfc7518#section-6.3>
- HTTP freshness and `must-revalidate`, RFC 9111:
  <https://www.rfc-editor.org/rfc/rfc9111>

The response headers are an observation from 2026-09-17, not a permanent GitHub
contract. The adapter therefore validates the headers on every successful
refresh rather than assuming they will remain unchanged.

## Decision

`internal/githubjwks.Cache` is the only network adapter added in this increment.
It implements the existing `githuboidc.KeyResolver` interface while keeping
network access out of the protocol verifier.

The adapter:

1. retrieves only the compile-time HTTPS endpoint
   `https://token.actions.githubusercontent.com/.well-known/jwks`;
2. requires a caller-supplied HTTP client with a timeout in `(0, 30s]`;
3. disables redirects so GitHub cannot redirect trust retrieval to another
   origin without a reviewed code change;
4. accepts only HTTP 200 and `application/json` responses;
5. limits the body to 64 KiB, the set to 32 keys, and each `kid` to 256 bytes;
6. rejects duplicate JSON object fields and duplicate key IDs;
7. accepts only `kty=RSA`, `alg=RS256`, `use=sig` entries;
8. requires canonical unpadded base64url RSA integers, a modulus of at least
   2048 bits, and a positive odd exponent within 31 bits;
9. requires `max-age` and `must-revalidate`, caps freshness at one hour, and
   subtracts any response `Age`;
10. never resolves a key at or after cache expiry;
11. replaces cached trust material only after the whole response validates;
12. refreshes an empty or stale cache before verification;
13. permits one additional refresh when a fresh set does not contain the
    token's `kid`, to cover normal signing-key rotation; and
14. rate-limits attacker-triggered unknown-key refreshes to one per 30 seconds.

`Resolve` returns a copy of the RSA public key so caller mutation cannot alter
cached trust material. A refresh failure preserves the previous set for its
remaining freshness period, but it never extends that period. Once stale, an
outage fails verification closed.

## Why discovery is not fetched at runtime

Runtime discovery adds another network response and another URL-bearing document
to the trust bootstrap. The issuer and current JWKS URI are already fixed by the
protocol boundary. A GitHub endpoint change should therefore require a reviewed
code and ADR change rather than being followed dynamically.

## Rotation and denial-of-service trade-off

An unknown `kid` can be legitimate rotation or attacker-controlled input. Never
refreshing a fresh cache would reject a newly introduced key for up to one hour.
Refreshing for every unknown ID would turn arbitrary JWT headers into an
unbounded network trigger.

The chosen bound performs one immediate rotation refresh when the current
verification did not already refresh the cache, then suppresses further
unknown-key refreshes for 30 seconds. A just-rotated legitimate key can therefore
experience a bounded transient failure after another unknown-key refresh. This
is an explicit availability trade-off; it does not cause an untrusted key to be
accepted.

## Rejected alternatives

### Serve stale keys during a GitHub outage

This would contradict the observed `must-revalidate` directive and could keep a
removed signing key trusted beyond GitHub's declared freshness window.

### Use the token's `jku`, `x5u`, or embedded `jwk`

These fields would allow untrusted input to select or supply trust material. The
pure verifier already rejects headers beyond `alg`, `kid`, and `typ`.

### Trust `x5c` instead of the JWK RSA parameters

The HTTPS response from the fixed issuer endpoint is the trust distribution
channel. Certificate-chain processing inside individual JWK entries would add a
second, unnecessary PKI validation path. The adapter verifies signatures using
the JWK `n` and `e` values.

### Add a third-party OIDC/JWT library

The required surface is small and already covered by the pure verifier. This
increment adds bounded retrieval and parsing without expanding the dependency or
supply-chain boundary.

## Consequences and remaining limits

- GitHub signing-key rotation no longer requires a process restart.
- Stale trust material is not silently extended during an outage.
- Network behavior is tested with deterministic transports; an opt-in live test
  checks GitHub's current response without making CI depend on its availability.
- Proxy policy, egress allow-listing, TLS root management, metrics, and service
  deployment configuration remain operator responsibilities.
- Durable replay consumption, Kubernetes credential issuance, mutation capture,
  and outcome verification remain unresolved and are not implied by this cache.

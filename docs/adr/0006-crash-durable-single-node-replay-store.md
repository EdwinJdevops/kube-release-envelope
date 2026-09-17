# ADR 0006: Use immutable local markers for crash-durable replay rejection

- Status: accepted
- Date: 2026-09-17

## Context

GitHub OIDC tokens carry a unique `jti`. ADR 0004 requires the issuer/`jti` pair
to be consumed before an envelope is signed, but its boolean consumer interface
could not distinguish a replay from storage failure and the only implementation
was an in-memory test double. A process restart could therefore forget every
consumed token.

The phase-one prototype needs a real failure boundary before it can safely issue
any deployment-scoped authority. It does not yet need a distributed database or
multi-region service.

Go 1.27 provides `os.Root`, which anchors file operations beneath an opened
directory. `O_CREATE|O_EXCL` requires that a new file not already exist. On
Linux, making a new directory entry durable requires synchronizing both the file
and its containing directory.

Primary references:

- Go 1.27 `os.Root`, `OpenFile`, and file synchronization:
  <https://pkg.go.dev/os#Root>
- Go file-open flags, including `O_CREATE` and `O_EXCL`:
  <https://pkg.go.dev/os#pkg-constants>
- Linux `fsync(2)` durability semantics:
  <https://man7.org/linux/man-pages/man2/fsync.2.html>

## Decision

`internal/replaystore.Store` implements a narrow, crash-durable replay consumer
for a single node using an owner-only local directory.

For each verified issuer/`jti` pair, it:

1. requires an absolute non-root storage path;
2. creates the directory with mode `0700` and rejects existing directories with
   broader or different permissions;
3. rejects a configured path whose final component is a symbolic link;
4. opens the directory through `os.Root` so marker operations remain confined
   to the anchored directory;
5. derives the marker name from SHA-256 over length-prefixed issuer and `jti`
   bytes, so raw token identifiers are not written to names or contents;
6. creates a `0600` marker with `O_CREATE|O_EXCL`;
7. treats an existing marker as a replay without rewriting or trusting its
   contents;
8. writes only the record version and token expiry;
9. synchronizes the marker file, closes it, then synchronizes the containing
   directory before returning success; and
10. leaves a marker in place after any uncertain post-create failure, producing
    a safe false replay instead of permitting duplicate issuance.

Markers are not deleted in v0, even after token expiry. Retention beyond expiry
is safe for replay rejection because GitHub `jti` values are unique. It trades
bounded disk growth for simpler semantics and eliminates cleanup races that
could re-enable a consumed identifier.

The `TokenConsumer` contract now returns `(consumed bool, err error)`:

- `true, nil`: the identity was durably consumed;
- `false, nil`: a marker already existed, so issuance returns
  `ErrTokenReplay`;
- any error: storage is uncertain or unavailable, so issuance returns
  `ErrTokenConsumption` and does not sign.

## Failure semantics

A crash after the durable marker is created but before envelope signing means a
retry is rejected. This is an availability loss, not an authorization bypass.
Exactly-once completion would require a transaction spanning replay state and
signature delivery, which does not exist here and is not claimed.

A crash before file and directory synchronization cannot produce a successful
return to the caller. If a marker survives an uncertain failure, later attempts
still treat it as consumed.

## Scope limit

This adapter is suitable only when all issuers that share a replay domain use
the same local filesystem on one node and that filesystem provides the expected
exclusive-create and synchronization semantics. It is not a distributed lock,
does not claim correctness on NFS or object storage, and must not be used by
independent replicas with separate volumes.

The configured directory must also live beneath a parent path controlled by the
service operator. `os.Root` anchors access after open, but this adapter does not
prove parent-directory ownership or prevent an actor with permission to replace
the whole directory between process restarts from removing replay history.

A production multi-replica service needs a linearizable conditional insert keyed
by issuer/`jti`, durable acknowledgement, and an explicit retention policy. That
is still unresolved.

## Rejected alternatives

### Keep the in-memory map

It loses all consumed identities on restart and therefore does not close the
replay gap.

### Delete markers immediately after token expiry

Cleanup introduces coordination and crash races without helping phase-one
correctness. Garbage collection can be designed after real storage-volume data
exists.

### Add SQLite or a remote database now

A database is not required to falsify single-node durability, and adding one
would expand dependencies and operational scope before the deployment service
exists. This decision does not argue that files are sufficient for a replicated
production service.

### Return one boolean for replay and storage failure

Both outcomes must fail closed, but operators and callers need to distinguish a
normal replay rejection from degraded storage. Collapsing them prevents correct
alerting and recovery behavior.

## Consequences

- Replay state survives process restart on the same persistent local volume.
- Concurrent consumers on the same local filesystem have one winner.
- Raw issuer and token identifiers are not stored.
- Storage errors cannot be mistaken for successful consumption or ordinary
  replay.
- Markers grow monotonically until a separately reviewed retention mechanism is
  introduced.
- Distributed replay protection, deployment credential issuance, mutation
  capture, and runtime outcome verification remain unresolved.

# Cathedral CLI launch PRD and technical specification

Status: controlling execution specification  
Date: 2026-07-31  
Revision: 5, four independent false-PASS audits incorporated  
Owner: Cathedral  
Implementer: Fable  
Independent reviewer: Codex  
Current verdict: FAIL, Gate 0 open

This document is the single controlling plan for the Cathedral CLI launch.
It replaces ad hoc implementation prompts as the source of execution order.
The launch review packet remains supporting evidence:
`CODEX-LAUNCH-REVIEW-20260731.md`.

If code, an older report, or a prior instruction conflicts with this
specification, stop and record the conflict. Do not silently narrow the goal.

## 1. Product requirement

One `cathedral` CLI must let:

1. A CPU miner install, configure, start, stop, update, recover, and prove real
   Intel TDX work.
2. A CyberGym miner install, authenticate, receive an immutable vulnerability
   challenge, execute it, submit a result, and retain a verifiable receipt.
3. A validator install, verify both lanes, survive restart, compose the owner
   policy, and prepare one exact weight vector.
4. An operator inspect status, logs, evidence, receipts, and failures without
   using repository-specific commands.
5. Cathedral issue signed updates and force a controlled restart without
   changing the owner's burn, allocation, secrets, ledgers, receipts, or
   pending transaction state.

Launch promise:

> Exact 45% CPU, 45% CyberGym, 10% burn, or no write.

The first launch lane called "Distill" in product language is the vulnerability
solving lane with canonical ID `cathedral_cybergym`. The separate
`cathedral_distill` model-training lane is outside this first vector.

## 2. Completion definition

The work is complete only when current evidence proves all of the following:

- The CLI is installable from one signed whole-node release.
- CPU and CyberGym miners use the CLI only for their supported workflow.
- The validator uses the CLI only for its supported workflow.
- One real Intel TDX CPU workload passes end to end.
- One real immutable CyberGym workload passes end to end.
- Miner and validator interaction is authenticated and replay protected.
- Receipts bind identity, workload, result, execution evidence, release, and
  epoch.
- Three fresh epochs independently produce exactly 0.45 CPU, 0.45 CyberGym,
  and 0.10 burn.
- Three consecutive finalized submissions on a non-paying safe network use
  that exact vector and reconcile without duplicate or ambiguous writes.
- Missing lanes move only their own allocation to burn.
- Missing or changed rewarded hotkey mappings hold the entire write.
- One and only one publisher exists.
- Signed update, restart, recovery, and byte-exact rollback preserve all
  durable state and the exact vector.
- Independent security and launch review has no unresolved FAIL or NOT PROVEN
  launch blocker.
- A clean host with no repository checkout completes every supported operator
  workflow using only the published signed release and the `cathedral` binary.
- A mainnet write occurs only after a separate explicit owner approval.

Local tests, fixture runs, CI, live reads, and dry-runs do not by themselves
prove the real miner, hardware, publisher, or chain requirements.

### 2.1 One release candidate and evidence invalidation

All launch evidence must bind to one release-candidate identity:

```text
release_manifest_sha256
cathedral_node_commit
cathedral_compute_commit
cathedral_distill_commit
cathedral_validator_commit
artifact_sha256s
lock_digest
protocol_versions
configuration_schema_versions
owner_policy_digest
authority_manifest_digest
```

Every Gate 1 through Gate 6 evidence bundle must contain this exact tuple.
Evidence from a source checkout, commit, artifact, protocol, policy verifier,
or configuration schema outside the tuple is not launch evidence.

Any executable, dependency, protocol, policy-verifier, authority, or release
change invalidates every affected downstream gate. Gate 4 creates a higher
candidate, so fresh Gates 1, 2, and 3 must pass on that exact higher candidate.
Gate 5 must install the final candidate from its signed HTTPS artifact on a
clean host. Gate 6 must execute the same manifest digest.

A change to `cathedral-node`, the release manifest, artifact set, wheel
closure, entrypoint, launch mode, protocol declaration, or readiness contract
always invalidates Gate 0.

The release-candidate tuple is immutable once Gate 5 begins. A change creates
a new candidate and restarts the affected gates.

## 3. Users and jobs

### CPU miner

- Install one supported release.
- Store the hotkey and worker credential without exposing either.
- Run a measured TDX worker.
- Receive a workload.
- Return fresh hardware evidence, result, and lifecycle evidence.
- See whether the validator admitted or rejected the receipt and why.

### CyberGym miner

- Install one supported release.
- Request or receive an admission credential through the CLI without exposing
  it.
- Receive a signed immutable task.
- Pull exact vulnerable and fixed artifacts by OCI content digest.
- Run the challenge.
- Submit a hotkey-bound result.
- Retain a receipt and see the validator verdict.

### Validator operator

- Install one supported release.
- Select the owner-signed policy authority.
- Start one canonical validator.
- Inspect miner evidence and errors.
- Stop, restart, update, recover, and roll back safely.
- Preview the exact vector.
- Broadcast only with a separate bounded approval.

### Cathedral release operator

- Build one signed three-role release.
- Publish inert release bytes over HTTPS.
- Issue a separately signed, scoped update directive.
- Observe acknowledgement, controlled restart, health, and rollback.
- Preserve owner-controlled policy and every durable ledger.
- Prove or roll back the update.

### Cathedral admission operator

- Choose selected or open admission through owner-controlled policy.
- Issue a single-use, expiring, hotkey-bound credential in selected mode.
- Inspect, list, and revoke credentials through the CLI.
- Never copy a bearer secret through chat, argv, logs, or source files.

## 4. Repository and authority boundaries

### `cathedral-node`, the unified CLI

Owns:

- User command surface.
- Signed whole-node release installation.
- Role isolation.
- Configuration and secret entry.
- Process lifecycle.
- Status, logs, evidence lookup, update, recovery, and rollback.

Does not own:

- CPU evidence semantics.
- CyberGym scoring semantics.
- Validator allocation policy.
- Bittensor keys.

### `cathedralai/cathedral-compute`

Owns:

- Intel TDX worker.
- Enrollment protocol.
- Work dispatch and result receipt.
- TDX verifier contract.
- CPU score and evidence semantics.

### `cathedralai/cathedral-distill`

Owns:

- CyberGym task manifest.
- Immutable vulnerable and fixed artifact references.
- Miner authentication.
- Challenge dispatch, solve submission, anti-replay, anti-gaming, scoring,
  persistence, epoch closure, and completeness proof.

### `cathedralai/cathedral-validator`

Must become the validator launch authority.

Owns:

- CPU and CyberGym receipt verification.
- Epoch completeness verification.
- Owner-signed lane and burn policy.
- One finalized metagraph snapshot.
- Exact hotkey-to-UID mapping.
- One composed vector.
- One pending write journal.
- One publisher.

The launch authority is a signed manifest binding:

```text
schema
repository
commit
distribution
entrypoint
release_manifest_sha256
network
netuid
validator_hotkey
publisher_lease_authority
issued_at
expires_at
signer_key_id
```

The canonical publisher uses one remote linearizable signer and lease broker.
The lease key is `(network, netuid, validator_hotkey)`. The broker:

- Uses its own authoritative clock.
- Issues a monotonically increasing fencing token.
- Grants a 120-second lease.
- Requires renewal every 40 seconds.
- Serializes sign authority for the lease key.
- Rejects stale fencing tokens.

The validator records the fencing token in the pending-attempt journal and
includes it in every publication authorization request and evidence record.
Lease loss before signing or submission aborts the write. Authority outage,
renewal delay, partition, process restart, and host replacement fail closed.
A local process lock remains a secondary guard and is not authority.

The broker also owns one linearizable global attempt ledger with the primary
uniqueness key:

```text
network
netuid
validator_hotkey
epoch
```

Each epoch record stores the release digest, owner-policy digest, vector
digest, authorization nonce, fencing token, and signed extrinsic bytes as
immutable fields. A request with different release, policy, vector, or
authorization data for an existing epoch fails with a conflict. It never
creates a second epoch record.

Attempt states are `reserved`, `signed`, `submitted`, `finalized`, `reorged`,
and `abandoned`. The broker refuses a second signature for an unresolved
authorized epoch. A replacement host must reconcile the global attempt before
signing. A retry reuses the same signed extrinsic bytes when protocol rules
permit. A proven reorg permits only a linked attempt inside the same epoch
record under the same vector and authorization. A finalized epoch is
permanently consumed.

`abandoned` is reachable only after authoritative non-inclusion beyond the
protocol finality horizon and any required signed cancellation. Local timeout,
lost response, lease expiry, host replacement, or operator assertion is
insufficient.

Mandatory tests cover simultaneous acquisition, stale holder, partition,
broker outage, delayed renewal, process restart, host replacement, and lease
loss between signing and submission. One combined test covers ambiguous
submission, lease expiry, host replacement, a new fencing token,
query-before-sign, a new authorization nonce, a changed release or vector,
exactly one signature, and exactly one finalized transaction for the epoch.
The same global idempotency rule applies to safe-network and mainnet
publication. Every legacy publisher service and deployment must have explicit
retirement evidence.
Relevant finalized chain extrinsics must be observed for at least two lease
TTLs before Gate 3B and after the final Gate 3B submission, then reconciled to
the canonical authority.

Validator-owned behavior still present only in `cathedralai/cathedral` must be
ported or deliberately retained behind an explicit authority boundary before
Gate 3. The unified CLI must not ship a derived validator that declares itself
non-authoritative.

### `cathedralai/cathedral`

Legacy validator source during cutover only.

It is not installed by the final unified release. It remains a comparison
source until all validator-owned launch behavior is proven in
`cathedral-validator`.

## 5. Canonical CLI contract

The normal operator path uses only:

```text
cathedral doctor [role] --json
cathedral capabilities --json
cathedral setup [compute|distill|validator] --json
cathedral config show [role] --json
cathedral config set [role] <field> <value> --json
cathedral secret set <name> --stdin --json
cathedral enrollment request compute --json
cathedral enrollment status compute --json
cathedral enrollment revoke compute <hotkey> --json
cathedral admission mode [selected|open] --json
cathedral admission issue <hotkey> --expires <duration> --output <path> --json
cathedral admission inspect <credential-id> --json
cathedral admission revoke <credential-id> --json
cathedral admission list --json
cathedral test [compute|distill|validator] --json
cathedral start [compute|distill|validator] [--once] [--foreground] --json
cathedral stop [compute|distill|validator] --json
cathedral status [compute|distill|validator] --json
cathedral logs [compute|distill|validator] [--follow] --json
cathedral evidence <receipt-or-run-id> --json
cathedral epoch close --json
cathedral decision show [--epoch <epoch-id>] --json
cathedral publish preview [--epoch <epoch-id>] --json
cathedral update [--check] --json
cathedral recover --json
cathedral rollback --json
```

The only weight-writing form is:

```text
cathedral start validator --once --broadcast --yes --json
```

Finney use remains locked until Gate 6. Gate 3B permits this command only on
the named non-paying safe network after Gate 3A and only under one signed
safe-network authorization binding exactly three epochs. The CLI rejects a
missing authorization, Finney, a different network, a different netuid, an
epoch outside the authorization, and any fourth submission.

Every command returns one versioned machine envelope and a stable exit code.
Human output is rendered from that same envelope. No secret appears in argv,
stdout, stderr, logs, receipts, run state, URLs, or process metadata.

During launch acceptance, operators, miners, and validator operators invoke
only the `cathedral` binary. The signed CLI may invoke its pinned engines
internally. Operators must not use repository scripts, Python module
entrypoints, direct HTTP requests, direct database writes, or state-file edits.
Acceptance runs on clean hosts with no repository checkout or development
dependency. Process-level transcripts must cover setup, configuration, secret
entry, admission, start, status, logs, evidence, epoch close, decision,
preview, stop, update, recovery, and rollback.

## 6. System invariants

### Release invariants

- Exactly three roles: `compute`, `distill`, `validator`.
- One canonical signed manifest.
- Pinned signer identity: `release@cathedral.computer`.
- Exact artifact hashes and complete wheel closure.
- No network dependency resolution during install.
- No untrusted code runs before artifact and signature verification.
- Signed-bundle expiry is an installation and update window, not a runtime
  kill switch. A release installed before expiry remains eligible to run or
  roll back after expiry only while its signature, retained authorization,
  replay floor, filesystem, and revocation state still verify. Revocation
  requires an authenticated policy action or a newer signed release.
- Active state is reverified against retained signed authorization before
  start, test, state, restart, no-op update, recovery, or rollback.
- A missing or corrupt replay floor fails closed.
- A prior group is restored only after independent full verification.
- The highest externally accepted release version never decreases.
- Offline rollback activates only the exact prior release digest recorded
  transactionally before the update. It never admits an unseen lower release.
- The retained rollback authorization ledger is separate from the external
  release floor and appends an auditable rollback record.
- Offline rollback requires cached signed revocation state inside its freshness
  window. Outside that window it fails closed and does not claim current global
  revocation status.
- For the first launch, state-schema migration is prohibited. A higher release
  must read the existing schema without mutation. A future migration requires
  a separate versioned transactional migration specification and proof that
  the prior executable reads the resulting state.
- Signed release code is inside the trusted execution boundary. State
  preservation protects against transaction and operational failure, not a
  maliciously signed release.

### Work invariants

- CPU evidence is fresh, nonce-bound, hotkey-bound, channel-bound,
  workload-bound, result-bound, and policy-admitted.
- CyberGym dispatch and submission are authenticated, hotkey-bound,
  timestamped, expiring, nonce-bound, and replay protected.
- CyberGym tasks name immutable OCI content digests.
- CyberGym accepted solve state is restart persistent.
- Validator credits only receipts in the verified epoch completeness set.
- Selected admission credentials bind audience, miner hotkey, network, netuid,
  issue time, expiry, unique nonce, and credential identifier.
- Admission credentials are delivered once, stored with restrictive
  permissions, redacted everywhere, and rejected after use, expiry, replay, or
  revocation.
- Open admission still requires authenticated hotkey identity, rate limits,
  replay protection, and the owner-defined abuse policy.

### Vector invariants

- Valid CPU and CyberGym lanes: 0.45, 0.45, burn 0.10.
- Missing or invalid CyberGym: CPU 0.45, burn 0.55.
- Missing or invalid CPU: CyberGym 0.45, burn 0.55.
- Both missing or invalid: burn 1.00.
- Never transfer one reward lane's missing share to another reward lane.
- Never renormalize after a positive hotkey mapping disappears.
- Every positive hotkey maps at one finalized block and block hash.
- Any mapping mismatch holds the whole write.
- Vector sum is exactly 1.000000000 under canonical integer normalization.
- Publisher count is exactly one.
- First launch supports exactly one rewarded hotkey per lane per epoch. More
  than one eligible hotkey in a lane holds the write until an owner-approved
  deterministic within-lane scoring specification and its tests exist.
- A hotkey present in both reward lanes is rejected.
- The burn hotkey cannot equal a rewarded hotkey.
- Canonical internal units total `1_000_000_000`. CPU receives `450_000_000`,
  CyberGym receives `450_000_000`, and burn receives `100_000_000`.
- UID serialization is ordered by ascending UID. The protocol encoder is the
  exact `bittensor` package version pinned in the signed release lock and uses
  unsigned 16-bit weights from 0 through 65535. It uses largest-remainder
  allocation. Ties are resolved by ascending UID. Zero entries are removed
  only after encoding.
- The release contains golden input, ordered UID, encoded weight, and
  serialized-byte vectors for valid, missing-lane, duplicate, collision, and
  rounding cases.
- Evidence contains the lane vector, ordered hotkey vector, finalized
  hotkey-to-UID map, encoded UID vector, and exact bytes passed to the
  Bittensor submission interface.
- A fresh epoch binds one finalized block height and hash, one close boundary,
  one unique task set, and one receipt eligibility window.

### Update invariants

An update, restart, recovery, or rollback preserves:

- Owner lane allocation.
- Owner burn destination and share.
- Trusted policy keys.
- Secret references and secret bytes.
- CPU enrollment and evidence ledgers.
- CyberGym task, solve, score, replay, and completeness ledgers.
- Receipt bytes and receipt identifiers.
- Validator pending-attempt journal.
- Last safe vector and last finalized write record.

Updates are controlled by a signed directive separate from the release
manifest. The directive binds:

```text
schema
command_id
target_release_manifest_sha256
target_roles
network
netuid
monotonic_sequence
issued_at
expires_at
restart_mode
signer_key_id
```

The release key, update-directive key, owner-policy key, and launch-approval
key are separate authorities. Delivery is pull-based over authenticated HTTPS.
The node records receipt, acknowledgement, start, health, completion, failure,
and rollback. Duplicate, stale, future, expired, revoked, wrong-network, and
wrong-role directives fail closed. An update directive cannot modify owner
policy, wallet references, burn, allocation, pending vectors, or durable
ledgers.

The CLI-managed node supervisor polls the authenticated update channel every
60 seconds with up to 10 percent randomized jitter. It persists the last
verified directive sequence and acknowledgement cursor before acting. A
directive names its acknowledgement deadline and restart deadline. The
supervisor receives, verifies, acknowledges, downloads, installs, restarts,
health-checks, completes, or rolls back without a local operator invoking
`cathedral update`.

When offline, the node continues its already authorized release but performs
no update claim. A directive may explicitly permit one bounded maintenance
deferral. Otherwise there is no operator opt-out. Missed expiry, missed
acknowledgement, failed health, and lost channel are visible through
`cathedral status` and append-only update logs.

Owner policy is a signed versioned document binding:

```text
schema
network
netuid
burn_hotkey
lane_ids
lane_allocations
policy_version
previous_policy_digest
issued_at
expires_at
signer_key_id
```

Policy versions are monotonic and replay protected. Release installation,
restart, recovery, rollback, and update cannot replace owner policy.

A launch authorization is a separate single-use signed document binding:

```text
schema
release_manifest_sha256
owner_policy_digest
vector_digest
ordered_hotkey_vector_digest
encoded_uid_vector_digest
finalized_block_height
finalized_block_hash
validator_hotkey
network
netuid
single_use_nonce
transaction_ceiling
issued_at
expires_at
signer_key_id
```

Safe-network authorization is a signed document binding:

```text
schema
release_manifest_sha256
owner_policy_digest
network
netuid
validator_hotkey
first_epoch
last_epoch
maximum_transaction_count
issued_at
expires_at
authorization_nonce
signer_key_id
```

For Gate 3B, `maximum_transaction_count` is exactly three and the journal
consumes each authorized epoch transactionally.

Recurring mainnet operation uses a distinct signed authorization binding:

```text
schema
release_manifest_sha256
owner_policy_digest
network
netuid
validator_hotkey
start_epoch
end_epoch
maximum_transaction_count
not_before
expires_at
allowed_vector_rule_digest
per_epoch_nonce_domain
transaction_ceiling
stop_conditions_digest
authorization_nonce
signer_key_id
```

Consumed epochs are journaled transactionally. Expiry, count exhaustion,
replay, cancellation, release change, policy change, vector-rule change, and
reorg invalidation fail closed.

### Trust authority invariants

Protected configuration pins separate trust roots for:

- Release manifests.
- Update directives.
- Validator authority manifests.
- Owner policy.
- CPU enrollment.
- CyberGym admission credentials.
- Safe-network authorization.
- Single-use and recurring mainnet authorization.

An active pointer, release bundle, downloaded policy, admission response, or
operator-supplied file never selects its own trust root. Rotation uses a
separately signed, monotonic, digest-chained trust update under the existing
authority. Revocation state is signed, versioned, expiring, and freshness
checked.

Every signed document has an exact schema and rejects missing or unknown
fields. Mandatory negative tests cover changed fields, wrong signer,
cross-signed document, stale version, replay, expiry, wrong network, wrong
netuid, wrong hotkey, wrong release, and wrong previous digest. Gate 3 tests
authority, policy, enrollment, admission, and safe-network documents. Gate 6
tests single-use and recurring mainnet authorizations before any write.

The coldkey remains off the validator host. The validator uses only the
approved hotkey or external signing interface named by owner policy.

## 7. Architecture

```text
signed release channel
        |
        v
cathedral CLI release verifier
        |
        +--> isolated compute generation
        |       |
        |       +--> TDX worker --> CPU receipt
        |
        +--> isolated CyberGym generation
        |       |
        |       +--> immutable task --> solve --> CyberGym receipt
        |
        +--> isolated validator generation
                |
                +--> verify CPU receipt
                +--> verify CyberGym receipt and epoch completeness
                +--> apply owner-signed 45/45/10 policy
                +--> freeze one metagraph mapping
                +--> journal one pending vector
                +--> preview or publish through one publisher
```

All durable role state lives outside immutable release generations. The active
release pointer selects executable generations. It never selects policy,
wallets, secrets, ledgers, or receipts.

## 8. Gate 0: signed lifecycle security

Objective:

Prove setup, active-state verification, update, restart, recovery, and rollback
are one fail-closed signed transaction.

Required implementation:

```text
verify_active_group(lock, trusted_signers_path)
    -> VerifiedActiveGroup or fail closed
```

It must:

1. Strictly parse the active pointer with an exact key set.
2. Obtain the trust root from protected configuration, never the pointer.
3. Read the retained manifest and signature under the named release digest.
4. Reverify the signature using the pinned release identity.
5. Strictly parse the retained manifest.
6. Bind manifest and signature digests to the pointer.
7. Bind version and digest to the durable replay floor.
8. Require exactly the three canonical roles.
9. Reauthorize every signed role against the current local lock.
10. Fully verify every generation and receipt against the signed role,
    pointer, current lock, and filesystem.
11. Return a sealed verified group used by all execution paths.
12. Reverify no-op updates.
13. Reverify both pending and prior groups during recovery.

Non-skippable attack matrices:

- Pointer schema, state, roles, generation IDs, swaps, traversal, version,
  identity, release digest, signature digest, trust-path redirection,
  timestamp, and prior pointer.
- Missing, changed, cross-signed, or cross-digest retained release.
- Every required receipt field missing individually.
- Every receipt provenance field changed individually.
- Unknown receipt field.
- Cross-role, cross-release, mixed-generation, same-version-different-digest,
  forged signer, forged revision, active-pointer-after-install, and forged
  no-op attacks.
- Changed, deleted, extra, mode-changed, owner-changed, symlinked, interpreter
  swapped, bytecode-planted, or ancestor-symlinked managed files.
- Receipt write failure, pending pointer write failure, crash after pending,
  failed health rollback, forged prior, corrupt floor, and no-op revalidation.
- Role-specific readiness and liveness, including immediate clean exit,
  immediate nonzero exit, wrong endpoint, stale PID, readiness timeout,
  hanging server, and server exit after readiness.
- Minimal allowlisted environment for every signed engine check. Host
  `PYTHONPATH`, virtual environment selectors, preload variables, proxy
  variables, credential variables, and unapproved executable search paths
  must not cross the boundary.
- Applicable wheel markers, platform tags, Python versions, ABI compatibility,
  and every dependency version constraint.
- No network dependency resolution and no installed package outside the signed
  closure.
- Singleton ownership, process-group cleanup, concurrent update, lock
  ownership, stale-lock recovery, and idempotent stop and restart.

Gate 0 uses one checked-in test-to-requirement manifest containing every
required test node ID. The exact command is:

```text
python -m pytest -q tests/test_gate0.py tests/test_contract.py
```

Before execution, the gate harness must prove every manifest node ID collects.
A missing test, deselected test, skipped test, collection warning, or
collection error is a Gate 0 failure.

Gate 0 PASS evidence:

- One coherent commit.
- Zero failures.
- Zero skipped Gate 0 tests.
- Zero deselected or missing Gate 0 tests.
- Every role readiness and dependency-closure case passes.
- Every named mutation starts no process and reports no successful no-op.
- Independent Codex diff review.
- Independent Codex rerun of the exact gate command.

No CPU or CyberGym live work starts before Gate 0 PASS.

## 9. Gate 1: real Intel TDX CPU CLI loop

Objective:

Run one fresh TDX workload between distinct validator and CPU miner processes
installed from the same release candidate. Use only the `cathedral` CLI.

Required CLI behavior:

- Request, inspect, persist, revoke, and renew CPU enrollment through the CLI.
- Configure hotkey, public HTTPS endpoint, channel binding, approved
  measurement, policy release, verifier contract, evidence retention, receipt
  signing, and token references.
- Support customer SAT work explicitly.
- Obtain tokens only from the CLI secret store.
- Run a canary and an enrolled worker.
- Export and retrieve the receipt through `cathedral evidence`.
- Have the validator dispatch a fresh work unit through the canonical
  authenticated protocol.
- Have the miner execute the unit in TDX and return its result.
- Have the validator admit the exact returned receipt and attribute it to the
  authenticated hotkey.
- Prohibit file injection, database insertion, direct HTTP, and direct verifier
  calls during acceptance.
- Prohibit manual allowlist, registry, database, or token installation.

Required proof:

- Real Intel TDX quote.
- Intel verification and current collateral.
- TCB `UpToDate`.
- Debug disabled.
- Fresh nonce.
- Hotkey and TLS channel binding.
- Approved measurement.
- Workload and result binding.
- Attempt count one.
- Verified lifecycle and teardown.
- Receipt bytes reopen identically.
- Validator verdict and credited hotkey are visible through
  `cathedral evidence`.
- No publisher or chain write.

The CPU receipt binds:

```text
release_manifest_sha256
verifier_contract_digest
owner_policy_digest
epoch_identifier
finalized_block_height
finalized_block_hash
authenticated_miner_hotkey
session_identifier
work_unit_identifier
workload_digest
result_digest
TDX_evidence_digest
lifecycle_state
```

Each binding is mutated independently and rejected before credit. Enrollment
survives restart. Revoked enrollment fails. Re-enrollment creates a new
credential and invalidates the prior credential without changing the hotkey.

Required negative proofs:

- Wrong miner hotkey.
- Wrong endpoint or TLS channel.
- Changed workload.
- Changed result.
- Stale nonce.
- Replayed request or receipt.

Each negative proof must fail before credit and must not mutate the candidate
vector.

Gate 1 PASS evidence:

- Exact CLI transcript with secrets redacted.
- Live evidence bundle.
- Receipt ID and digest.
- Offline receipt verification.
- Spend ledger and teardown record.
- Independent review.

## 10. Gate 2: real CyberGym CLI loop

Objective:

Run one persistent, authenticated, immutable CyberGym task between a miner and
validator using only the `cathedral` CLI.

Required implementation:

- Production server constructor with finalized chain context.
- Persistent signing identity and durable task, score, solve, replay, and epoch
  state.
- Selected or open admission policy with authenticated caller identity.
- Timestamp, nonce, expiry, and replay protection.
- Signed epoch task manifest.
- Vulnerable and fixed artifacts resolved to OCI content digests.
- Verified miner pull and local differential execution.
- Credited first-launch execution inside Intel TDX with no production opt-out.
- Sandbox isolation, network policy, CPU and memory limits, timeout, output
  contract, and deterministic replay verdict.
- One admitted vulnerability report per miner per UTC day. The validator uses
  finalized chain time with the protocol-defined tolerance. Miner host time is
  not authoritative.
- Anti-gaming policy enforced before credit.
- Authenticated epoch closure and completeness proof.
- Validator CLI passes the durable CyberGym epoch-state path.

Gate 2 PASS evidence:

- `cathedral start distill --once --json` completes a production non-fixture
  task.
- Dispatch and submission identity match the credited hotkey.
- Task bytes match signed OCI digests.
- The submitted exploit succeeds against the vulnerable digest and fails
  against the fixed digest under independent validator replay.
- TDX quote, approved measurement, freshness, current collateral, TCB,
  workload, and replay-result bindings pass.
- Receipt is byte-identical after validator stop and restart.
- Old nonce and old receipt replay both fail.
- A second credited report from the same miner inside the same UTC day fails.
- No publisher or chain write.

The CyberGym receipt binds:

```text
authenticated hotkey
admission credential identifier
session identifier
epoch identifier
signed task manifest digest
vulnerable OCI content digest
fixed OCI content digest
submitted exploit digest
independent replay result
TDX execution evidence
release manifest digest
finalized block height and hash
```

Each binding is mutated independently and rejected before credit. Selected
admission, open admission, revocation, expiry, restart persistence, and replay
protection each have an end-to-end CLI test.

## 11. Gate 3: exact repeated composition and safe-network publication

Objective:

Prove the canonical validator consumes both real lanes, produces one exact
stable vector, and publishes it repeatedly on a non-paying safe network.

### Gate 3A: three non-writing epochs

1. Start one validator.
2. Run one fresh accepted CPU job through the CLI.
3. Run one fresh accepted CyberGym job through the CLI.
4. Stop the validator before epoch close.
5. Restart it.
6. Run `cathedral epoch close --json`.
7. Retrieve both receipts with `cathedral evidence`.
8. Run `cathedral decision show --json`.
9. Run `cathedral publish preview --json`.
10. Verify the completeness proof, finalized block height and hash, unique
    task set, and receipt eligibility window.
11. Repeat for three fresh epochs.
12. Run all missing-lane, duplicate-hotkey, burn-collision, and mapping-change
    counterexamples.

Gate 3A PASS:

```text
CPU internal units           450000000
CyberGym internal units      450000000
burn internal units          100000000
sum                          1000000000
rewarded hotkeys             2
publisher authority count    1
chain writes                 0
```

Across three epochs:

- Receipt IDs, task IDs, finalized blocks, and nonces change.
- Policy and exact vector remain unchanged.
- Old receipt replay fails.
- Missing lane moves only its share to burn.
- Changed rewarded hotkey mapping holds the whole write.
- Lane vector, ordered hotkey vector, finalized UID mapping, encoded UID
  vector, and submission bytes are retained.

### Gate 3B: three finalized safe-network submissions

Gate 3B uses a registered non-paying test network and a signed test
authorization. Finney remains locked.

1. Start the same canonical validator release candidate.
2. Produce fresh CPU and CyberGym work for each epoch.
3. Close and preview each epoch through the CLI.
4. Publish exactly once for each of three consecutive finalized epochs through
   the CLI.
5. Reconcile the attempt journal, network response, finalized block, encoded
   UID vector, and exact submission bytes.
6. Restart once between epochs and continue from the durable journal.
7. Inject an ambiguous submission response and prove query-before-retry avoids
   a duplicate.
8. Inject a rate-limit response and prove bounded scheduling resumes safely.
9. Inject a pre-finality reorg or replacement and prove finality handling
   reconciles before the next epoch.
10. Observe the network over the defined interval and prove every relevant
    submission belongs to the signed canonical publisher authority.

Gate 3B PASS:

- Exactly three finalized submissions.
- Every finalized encoded vector matches the canonical 45/45/10 encoding.
- No duplicate submission.
- No unreconciled pending attempt.
- No competing configured or observed publisher.
- Publisher count is globally one, not merely one local process.
- Owner policy is unchanged.

Gate 3 does not pass until both Gate 3A and Gate 3B pass on the same release
candidate.

## 12. Gate 4: controlled update and rollback

Objective:

Prove release operations do not corrupt the live mechanism.

Procedure:

1. Name the proven and already running baseline candidate `R0`.
2. Snapshot semantic contents, hashes, row counts, and schema versions for
   every durable state store.
3. Build and identify the higher candidate `R1` as inert bytes in a clean
   staging environment.
4. Run the exact Gate 0 command and independent Gate 0 review against inert
   `R1`. Do not issue an update directive until `R1` Gate 0 is PASS.
5. Issue a valid signed update directive for the Gate 0-approved `R1`.
6. Invoke no local update command. Observe the running supervisor receive,
   verify, acknowledge, download, install, restart, health-check, and complete
   `R1` through the signed HTTPS channel.
7. Reverify the active `R1` signed group and every role health contract.
8. Generate a new real CPU workload and a new real CyberGym task.
9. Verify both receipts and the exact vector on `R1`.
10. Perform an offline byte-exact rollback to the exact transactionally
   authorized `R0` digest.
11. Restart the exact role set.
12. Generate another new real CPU workload and another new real CyberGym task.
13. Verify both receipts and the exact vector on `R0`.
14. Reinstall the already Gate 0-approved `R1`.
15. Rerun fresh Gate 0, Gate 1, Gate 2, Gate 3A, and Gate 3B on the exact `R1`
    identity.
16. End with `R1` active.

Pre-update tasks, nonces, receipts, and eligibility never count as post-update
or post-rollback proof.

PASS:

- No secret exposed.
- No state store lost or reset.
- No receipt changed.
- No replay accepted.
- Exact vector preserved.
- New work passes after update and after rollback.
- Prior executable bytes match their original hashes.
- Prior executable reads every retained state store after rollback.
- Higher candidate `R1` ends active with fresh Gates 0 through 3 PASS.
- Failed update and failed health counterexamples restore only a reverified
  prior release.
- Duplicate, stale, future, expired, revoked, wrong-network, wrong-role, and
  replayed update directives fail.
- No update or rollback changes owner policy, authority, wallet reference,
  secrets, allocation, burn, pending vector, or attempt journal.

## 13. Gate 5: independent launch review

Required independent passes:

- Release and supply-chain security.
- Runtime and process lifecycle.
- CPU evidence and receipt semantics.
- CyberGym authentication, immutability, persistence, and anti-gaming.
- Validator composition, mapping, journaling, and single-publisher behavior.
- First-time miner and validator CLI usability.
- Cross-repository pin and protocol compatibility.
- Failure recovery and observability.
- Clean-host install from the final signed HTTPS artifact with no source
  checkout or development dependency.
- Full command-contract matrix covering every command in Section 5.
- JSON schema versions, stable exit codes, and human rendering from the same
  machine envelope.
- Status transitions, stale and unhealthy process state, missing evidence,
  follow-log cancellation, and secret redaction.
- Exact final release-candidate identity and invalidation analysis.

PASS:

- No unresolved P0 or P1 launch defect.
- No unresolved FAIL or NOT PROVEN item required by this specification.
- All code under test is committed and identified.
- Remote PR and CI state match the reviewed commits.
- Every release-candidate commit exists on its protected canonical branch or
  an immutable signed release tag. An open or draft PR is not final launch
  provenance.
- Remote CI passes against those exact commits.
- The signed whole-node manifest records the canonical branch or immutable tag
  and commit for every repository.
- A fresh remote fetch and equality check passes immediately before Gate 5
  PASS and again during Gate 6 preflight.
- Published instructions take a first-time miner and validator from a clean
  host to the tested state using only the `cathedral` binary.
- No claim relies only on fixture, dry-run, or local tests where live proof is
  required.

## 14. Gate 6: mainnet activation

### Gate 6A: bounded mainnet canary

Gate 6 requires a new explicit owner approval after Gates 0 through 5 pass.

Before approval:

- Read-only Finney preflight passes.
- Validator permit and UID mapping are current.
- No competing configured or observed publisher exists.
- The signed authority manifest and cross-host lease name the canonical
  publisher.
- One bounded signed launch authorization exists.
- The authorization binds the final release manifest digest, owner policy
  digest, vector digest, finalized block and hash, validator hotkey, network,
  netuid, single-use nonce, ceiling, and expiry.
- Exact UID vector matches the Gate 3 hotkey vector.
- Pending attempt journal is empty or reconciled.

Allowed action after approval:

- At most one validator weight transaction.

PASS:

- Exactly one transaction finalized.
- Finalized UID vector equals the approved vector.
- Local journal, public evidence, and chain state reconcile.
- No second submission.
- No competing configured or observed publisher appears before or after the
  transaction.

Gate 6A proves one bounded mainnet canary. It does not prove recurring mainnet
operation and does not satisfy the repeated-setting objective by itself.

### Gate 6B: bounded mainnet soak or recurring operation

Gate 6B requires a separate explicit owner authorization after Gate 6A.
Authorization must state either:

1. A bounded soak with an exact epoch count, time window, transaction ceiling,
   network, netuid, release digest, owner policy digest, and stop conditions.
2. Recurring operation under the signed recurring-authorization schema in
   Section 6, a versioned owner policy, and an explicit publisher operations
   runbook.

A runbook is not authorization. Every recurring transaction must consume one
authorized epoch under the recurring document. Expiry, cancellation, count
exhaustion, release change, policy change, replay, and reorg are enforced
before signing.

The launch objective is mainnet-operational only after the approved mode
produces at least three consecutive finalized scheduled epochs with:

- Fresh CPU and CyberGym work.
- Exact canonical encoding.
- No duplicate or ambiguous write.
- Finality and journal reconciliation.
- One global publisher.
- No owner-policy drift.

Without Gate 6B approval, the correct status after Gate 6A is:

```text
Mainnet canary PASS
Recurring mainnet operation NOT AUTHORIZED
```

## 15. Execution protocol

Fable is the implementer. Codex is the independent reviewer.

For each gate:

1. Record the current commit and dirty state.
2. Compute and record the release-candidate identity.
3. State the exact gate and acceptance command.
4. Implement only work needed for that gate.
5. Run the gate tests.
6. Write a short decision log.
7. Create one coherent local commit.
8. Recompute the release-candidate identity and list every invalidated gate.
9. Stop.
10. Codex inspects the diff and reruns the gate independently.
11. Advance only after Codex records PASS.

No later patch inherits an earlier PASS without an explicit invalidation
analysis.

Prohibited drift:

- No polishing unrelated UI or fixture workflows.
- No broad docs rewrite during a security gate.
- No live hardware work before Gate 0.
- No mainnet work before Gate 6.
- No new reward lane.
- No second publisher.
- No silent goal reduction.
- No skipped gate test.
- No claim of "live" from local, fixture, CI, or read-only evidence.

Status format:

```text
Gate:
State: PASS | FAIL | NOT PROVEN
Commit:
Release candidate:
Changed:
Exact tests:
Evidence:
Invalidated gates:
Remaining blocker:
External mutation:
Spend:
Next allowed action:
```

## 16. Historical state at specification freeze

This section is a historical snapshot. It is not acceptance evidence.
Current gate state must be recorded in an append-only gate journal keyed by
release-candidate identity. A later status update never rewrites prior
evidence.

- Gate 0: FAIL.
- Fable worktree: dirty and uncommitted after `91c41a1`.
- Latest focused fixture result: 155 passed, 3 failed, 5 real-engine tests
  deselected. One presentation failure has since been fixed. Two tests depend
  on low host disk and need deterministic healthy-disk fixtures.
- Active signed-release revalidation: not implemented.
- Full receipt cross-binding: not implemented.
- Complete tamper matrices: not implemented.
- Gate 1 live CPU: not started.
- Gate 2 live CyberGym: not started.
- Gate 3 exact repeated vector: not started.
- Gate 4 update and rollback proof: not started.
- Gate 5 independent launch review: not started.
- Gate 6 mainnet write: not authorized and not attempted.
- External spend: zero in the current run.
- Deployment, wallet mutation, registration, reward activation, and chain
  write: none in the current run.

Next allowed action:

Implement `verify_active_group`, the full receipt and pointer cross-bindings,
and the non-skippable Gate 0 attack matrices. Then produce one coherent local
commit for independent review.

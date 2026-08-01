# Cathedral CLI Gate 0 independent review

Date: 2026-07-31

PRD: `CATHEDRAL-CLI-LAUNCH-PRD-TECH-SPEC-20260731.md`

PRD revision: 5

PRD SHA-256:
`c1d6f1be5a44dd1c773089d6d4214290a72774f619336590cc17869608fff2d1`

Implementation worktree:
`/private/tmp/cathedral-unified-node-fable-20260730/node/.claude/worktrees/unified-node`

Reviewed implementation base:
`91c41a1f75ed483418ad9f5996883ed3a8ab426a`

Review mode: merge-readiness review of the uncommitted Gate 0 candidate.

Review question: Does the current Gate 0 candidate prove the complete
fail-closed signed release lifecycle required by Revision 5?

Out of scope: Gate 1 and later live work, deployment, infrastructure, wallets,
spend, rewards, and chain writes.

Verdict: FAIL

The implementation is still uncommitted and the worktree is dirty. The
candidate has useful security work and substantial passing test coverage, but
it still contains false-PASS paths and does not satisfy the required Gate 0
test contract.

## Test evidence

The PRD command does not execute on this host because `python` is not installed:

```text
python -m pytest -q tests/test_gate0.py tests/test_contract.py
zsh: command not found: python
```

The equivalent command with the available Python 3.14.3 interpreter was run
inside the restricted environment:

```text
python3 -m pytest -q tests/test_gate0.py tests/test_contract.py
```

Result:

```text
3 failed, 163 passed, 5 skipped, 1 warning
```

The three failures were caused by restricted loopback binding and access to the
default local runtime directory. The same command was rerun outside those
restrictions.

Result:

```text
166 passed, 5 skipped, 1 warning in 305.08s
```

This is not Gate 0 PASS. Revision 5 requires zero skipped, zero deselected,
zero warnings, a checked-in requirement manifest, one coherent commit, and an
independent exact-command rerun.

The candidate `run-gate0.sh` is not the PRD command. It adds:

```text
-m "not real_engine"
```

and deliberately deselects five tests. Its reported `166 passed, 5 deselected`
result is therefore not acceptable Gate 0 evidence.

## Confirmed launch blockers

### P0: no checked-in test-to-requirement manifest

Revision 5 requires every Gate 0 requirement and named attack case to map to a
collected pytest node ID. No such manifest exists in the candidate.

User-visible result: a missing or uncollected security case can disappear while
the gate still reports green.

### P0: filtered runner creates a false PASS

`run-gate0.sh` deliberately deselects five `real_engine` tests.
`tests/conftest.py` rejects skips only when the optional
`CATHEDRAL_NO_SKIP=1` environment variable is set. The exact PRD command does
not set it.

User-visible result: the release can be described as Gate 0 green with required
cases absent.

### P0: verified state is not sealed through execution

`cathedral_node/commands/run.py` verifies installation state and then loads the
engine. `cathedral_node/engines/base.py` resolves executable paths through
`cathedral_node/paths.py`, which rereads the mutable active pointer.

Concrete failure: the active pointer can change after verification and before
process launch. The process can then execute a generation that was not the
verified generation.

Required result: every execution consumer must receive executable paths from a
sealed `VerifiedActiveGroup`. It must never resolve them again from mutable
state.

### P0: active verification cache omits certified state

`_verify_active_group_cached` keys its result only on the active pointer,
replay floor, trust file, and lockfile metadata. It omits the retained
manifest, signature, receipts, interpreter, and managed filesystem tree.

Concrete failure: same-process tampering after one successful verification can
remain trusted. Tests that call `_ACTIVE_CACHE.clear()` hide this path.

Required result: remove the cache from security decisions or bind it to a
race-safe immutable snapshot of every certified input. A same-process tamper
test must pass without manually clearing the cache.

### P0: forged prior recovery can select executable generations

`_read_pointer_strict` only checks that `prior` is a dictionary. `_recover`
fully verifies the pending group, but on failure passes the unverified prior to
`_rollback_group`. `_rollback_group` writes the prior and can restart the
generation IDs it names.

Concrete failure: a forged prior pointer can become active executable state
during recovery.

Required result: recursively and independently verify the exact prior group
before restoring or starting it. A forged prior must start no process and
must not change the active pointer.

### P0: installed releases become runtime kill switches

`verify_active_group` calls the install-time manifest verifier using the
current time. The verifier rejects the retained manifest after
`expires_at`.

Revision 5 defines manifest expiry as an installation and update window, not a
runtime kill switch.

Concrete failure: every installed node becomes invalid on a timer even when
its retained signature, filesystem, replay floor, and cached revocation state
remain valid.

Required tests:

1. Install immediately before expiry.
2. Verify and start immediately after expiry while cached revocation state is
   fresh. This must pass.
3. Attempt a new install or update from the expired bundle. This must fail.
4. Verify with stale, missing, corrupt, or revoked cached revocation state.
   This must fail closed.

### P0: replay floor accepts semantic corruption

`_floor_state` checks only that `release_version` is an integer. It accepts
negative values, malformed or missing digests, and unknown fields.
`_raise_floor` can overwrite a floor after `_floor_state` reports invalid.

Concrete failure: syntactically valid corrupt state can weaken replay
protection or be overwritten without preserving evidence.

Required result: exact schema and key set, positive bounded version, exact
lowercase SHA-256 digest, aware timestamp, symlink refusal, monotonic
compare-and-write under the transaction lock, and no repair-by-overwrite.

### P1: receipt provenance is only partially verified

`_verify_generation` checks the top-level receipt key set, but does not bind
all recorded provenance values. `parent_base_executable`, textual
`venv_python`, `installed_at`, the exact nested `venv_python_stat` key set, and
recorded size are not fully validated.

Concrete failure: receipt fields that downstream readers can treat as
provenance can be changed while the generation remains trusted.

Required result: bind or remove every receipt field. Test every required field
missing individually, every provenance field changed individually, every
nested extra or missing key, and an unknown top-level field.

### P1: named attack matrices are incomplete

The current suite has useful examples, but does not manifest and prove every
required pointer, retained release, receipt, filesystem, crash, readiness,
environment, dependency, concurrency, cleanup, restart, and no-op case from
Revision 5.

Required result: a checked-in manifest names each case and its pytest node ID.
Every named node must collect, execute, and prove that no process starts and no
successful no-op is reported for rejected state.

### P1: rollback authorization and revocation freshness are missing

Revision 5 requires offline rollback to the exact transactionally recorded
prior digest, an append-only rollback authorization ledger, and cached signed
revocation state inside its freshness window. The candidate does not yet prove
these controls.

Concrete failure: rollback is either unavailable when needed or trusts
insufficiently authorized stale state.

## Counterexample pass

The most likely production failure is a verify-then-swap race:

1. `cathedral start validator` verifies the active group.
2. A concurrent update or attacker changes the active pointer.
3. The engine adapter resolves its executable path from the changed pointer.
4. The process launches bytes outside the verified group.

The current cache and tests do not disprove this sequence.

## Required evidence before Gate 0 PASS

1. One coherent local commit with a clean worktree.
2. Complete parent-to-commit diff review.
3. `git diff --check`.
4. Checked-in Gate 0 requirement manifest.
5. Exact collected node IDs equal the manifest.
6. Exact PRD command with zero failures, skips, deselections, warnings, and
   collection errors.
7. Supported interpreter matrix, or an honestly narrowed signed support
   contract.
8. Independent counterexamples for sealed verify-to-exec, same-process cache
   tampering, forged prior recovery, post-expiry runtime, corrupt replay floor,
   receipt fields, and all named mutation classes.
9. Supervisor and subprocess spies proving each rejected mutation starts no
   process.
10. Append-only Gate 0 journal entry with the reviewed commit and evidence.

No Gate 1 work is authorized by the PRD until this review records PASS.

# Gate 0 repair directive

Controlling specification:
`CATHEDRAL-CLI-LAUNCH-PRD-TECH-SPEC-20260731.md`

Revision: 5

Specification SHA-256:
`c1d6f1be5a44dd1c773089d6d4214290a72774f619336590cc17869608fff2d1`

Rejected candidate commit:
`8a9822f`

Independent review:
`GATE0-INDEPENDENT-REVIEW-20260731.md`

Gate status: FAIL

This directive narrows the next implementation turn. It does not replace or
weaken Revision 5. Complete every section in one coherent successor commit.
Do not begin Gate 1.

## 1. Make verified runtime state immutable and explicit

Add private-constructor immutable values:

```text
VerifiedRole
  role
  generation
  generation_dir
  source_dir
  venv_dir
  python
  receipt
  receipt_data
  entrypoints

VerifiedActiveGroup
  release_version
  lock_digest
  identity
  pointer_digest
  roles
```

Requirements:

1. Only the strict group verifier creates these values.
2. Use frozen, slotted values and immutable nested maps or tuples.
3. Remove the process-global active security-verdict cache.
4. Verify once per command and pass the verified group through every consumer.
5. Runtime execution never calls a helper that rereads
   `active-release.json`.
6. Engine executable, source, venv, receipt, and configuration paths come from
   the bound `VerifiedRole`.
7. `start`, `test`, status, doctor, capabilities, quickstart, update no-op,
   recovery, rollback, and automatic update consume the verified group.

Add a lifecycle guard:

```text
with verified_active_group(lock, trusted_signers) as group:
    ...
```

The guard:

1. Takes a shared lifecycle lock.
2. Strictly reads and verifies the group.
3. Holds the lock through process launch or the complete read operation.
4. Revalidates the exact pointer, floor, trust root, lock, receipts, and
   managed tree before the first child starts.

Install, update, recovery, and rollback use the exclusive form of the same
lock.

Do not claim protection from a hostile process with the same operating-system
identity unless a separate immutable filesystem or privilege boundary exists.

## 2. Use one verifier for active, pending, and prior groups

Factor:

```text
verify_group_pointer(pointer, expected_state, lock, trusted_signers)
    -> VerifiedActiveGroup or fail closed
```

It must verify:

1. Exact recursive pointer schema.
2. Retained manifest and signature.
3. Configured trust root.
4. Cached revocation state.
5. Replay-floor relationship.
6. Current lock authorization.
7. Every generation, receipt, interpreter, and managed file.

Installation captures `prior` only from an already verified group.

Recovery:

1. Verifies pending independently.
2. Verifies prior independently.
3. Never writes or starts an unverified prior.
4. Never mixes pending and prior generations.
5. Propagates supervisor stop, start, and readiness failures.
6. Reports rollback success only when the exact prior group is verified,
   restored, started where required, and ready.

`Supervisor.start` accepts a verified group plus selected roles. It must not
accept arbitrary generation identifiers.

## 3. Separate acquisition expiry from retained runtime authorization

Manifest validation needs explicit modes:

```text
CANDIDATE_ACQUISITION
RETAINED_RUNTIME
PENDING_RECOVERY
```

Rules:

1. Candidate install or update enforces
   `created_at <= now < expires_at`.
2. Retained runtime verification validates signature, canonical form,
   timestamp ordering and lifetime, ABI, platform, roles, digest, floor,
   revocation, receipts, and filesystem. It does not reject solely because
   the original acquisition window ended.
3. Pending recovery after the floor already equals the pending version and
   digest finishes the transaction without reapplying acquisition expiry.
4. A pending release not yet committed to the floor must remain inside its
   activation window. Otherwise only an independently verified prior is
   eligible for restoration.

## 4. Make the replay floor exact and monotonic

Use an exact document:

```text
schema
release_version
lock_digest
identity
committed_at
```

Requirements:

1. Exact key set and schema.
2. Positive bounded integer release version.
3. Lowercase 64-character hexadecimal digest.
4. Pinned release identity.
5. Aware UTC timestamp.
6. No-follow reads and restrictive owner and mode checks.
7. Same version and same digest is idempotent.
8. Same version and different digest is a hard refusal.
9. Lower version is a hard refusal.
10. Corrupt state is never repaired by overwrite.
11. Committed active pointer exactly equals the floor.
12. Floor absence means fresh only when pointer, retained releases,
    generations, activation journal, and activation marker are all absent.
13. Read, compare, and write remain inside the exclusive transaction lock.

If the floor already names pending, recovery must commit pending or stop for
operator repair. It must never roll back below the floor.

## 5. Add signed last-known-good revocation state

Use a separate offline revocation authority and monotonic sequence.

The signed snapshot binds:

```text
schema
sequence
issued_at
expires_at
revoked_release_digests
revoked_signer_fingerprints
signer_key_id
```

Requirements:

1. Fetch and verify before candidate acquisition.
2. Atomically retain only a newer valid snapshot.
3. Invalid, older, or unavailable network data never replaces the last known
   good snapshot.
4. Active verification consults the retained snapshot offline.
5. A revoked active digest blocks restart and weight broadcast.
6. Stale revocation knowledge is reported explicitly.
7. Network failure does not reinterpret release-manifest expiry.

## 6. Bind or remove every receipt field

The strict verifier receives the trusted base executable and its current
digest.

It must:

1. Hash `source/source.tar` against signed `source_sha256`.
2. Compare the current trusted base interpreter hash with
   `parent_base_sha256`.
3. Require exact canonical base and venv paths.
4. Require exact top-level and nested key sets.
5. Validate every field type.
6. Parse `installed_at` as aware UTC.
7. Validate recorded size as well as identity and mode.
8. Convert malformed nested data into a controlled refusal.
9. Write the receipt, freeze the complete generation including the receipt
   and root, then reverify it.
10. Remove an incomplete generation internally if any preparation or receipt
    step fails.

If a receipt field has no security or audit meaning, remove it from the
schema. Do not retain an unverified provenance claim.

## 7. Replace the false-PASS test harness

Add one checked-in Gate 0 requirement manifest. It maps every Revision 5
requirement and every named attack case to explicit pytest node IDs.

The harness must:

1. Collect the exact two PRD test files.
2. Compare collected node IDs with the manifest before execution.
3. Reject a missing, unknown, or duplicate node ID.
4. Reject a missing manifest requirement.
5. Run the exact PRD test set without a marker filter.
6. Reject every skip, deselection, warning, collection error, or failure.

Move true Gate 1 or Gate 2 live-engine tests out of the Gate 0 test files, or
replace their Gate 0 responsibility with deterministic signed-fixture tests.
Do not deselect them and call Gate 0 green.

The final exact acceptance command remains:

```text
python -m pytest -q tests/test_gate0.py tests/test_contract.py
```

The released development environment must provide the documented `python`
entrypoint, or the controlling specification and all release scripts must be
changed together before review.

## 8. Mandatory new falsification tests

### Verified runtime binding

1. `test_verified_group_is_private_frozen_and_role_map_is_immutable`
2. `test_generation_tamper_after_first_state_is_not_cached`
3. `test_retained_release_tamper_after_first_state_is_not_cached`
4. `test_stat_preserving_pointer_rewrite_is_not_cached`
5. `test_state_python_path_comes_from_verified_role_not_second_pointer_read`
6. `test_start_pointer_swap_after_verify_starts_no_process`
7. `test_start_generation_tamper_after_qualification_starts_no_process`
8. `test_test_pointer_swap_after_verify_runs_no_engine`
9. `test_test_generation_tamper_after_qualification_runs_no_engine`
10. `test_status_verifies_one_group_and_never_mixes_role_generations`
11. `test_shared_runtime_guard_blocks_concurrent_activation_until_process_exit`
12. `test_supervisor_receives_verified_group_not_generation_ids`

### Recovery and floor

13. `test_invalid_nested_prior_is_neither_written_nor_started`
14. `test_valid_prior_is_independently_verified_before_restart`
15. `test_recovery_pending_and_prior_cannot_mix_generations`
16. `test_floor_raised_pending_never_rolls_back_below_floor`
17. `test_supervisor_restart_failure_makes_recovery_fail`
18. `test_update_refuses_an_existing_unverified_active_group`
19. `test_floor_requires_exact_schema_types_and_hex_digest`
20. `test_same_version_different_digest_cannot_replace_floor`
21. `test_active_pointer_must_exactly_equal_floor`
22. `test_missing_pointer_and_floor_with_retained_state_is_not_fresh`
23. `test_crash_matrix_pending_floor_active_preserves_monotonicity`
24. `test_parallel_update_and_recover_leave_one_consistent_floor_and_pointer`

### Expiry and revocation

25. `test_expired_installed_release_remains_valid_but_cannot_be_newly_activated`
26. `test_floor_committed_pending_recovers_after_manifest_expiry`
27. `test_uncommitted_expired_pending_restores_only_verified_prior`
28. `test_install_requires_verified_cached_revocation_snapshot`
29. `test_invalid_or_older_revocation_snapshot_preserves_last_good_cache`
30. `test_revoked_active_digest_blocks_restart_offline`
31. `test_channel_outage_uses_last_good_revocation_cache`

### Receipt and cleanup

32. `test_regular_interpreter_replacement_with_forged_receipt_fails`
33. `test_changed_source_with_recomputed_local_manifest_fails_signed_source_hash`
34. `test_receipt_paths_types_and_timestamp_are_strict`
35. `test_malformed_venv_python_stat_refuses_without_exception`
36. `test_receipt_write_failure_leaves_no_generation_or_pointer`
37. `test_cached_success_does_not_survive_receipt_tree_or_signature_mutation`
38. `test_runtime_executes_only_paths_from_the_verified_group_snapshot`

Also manifest every Revision 5 pointer, retained-release, receipt,
filesystem, readiness, environment, dependency, concurrency, cleanup,
restart, crash, and no-op mutation.

For every rejection, assert:

1. No engine or installer subprocess starts.
2. No successful no-op is reported.
3. Active pointer and replay floor do not weaken.
4. Existing verified state remains byte-identical where rollback is allowed.

## 9. Required handoff

Before stopping:

1. Create one coherent local successor commit.
2. Leave a clean worktree.
3. Record parent and successor commit SHAs.
4. Record the Revision 5 hash.
5. Record the full file list and diff statistics.
6. Record collect-only manifest equality.
7. Record exact test commands, counts, skips, deselections, warnings, and
   interpreter versions.
8. Record every remaining FAIL or NOT PROVEN item.
9. Stop before Gate 1 for independent Codex review.

No push, merge, deployment, infrastructure, wallet, spend, reward, or chain
action belongs in this repair.

#!/usr/bin/env python3
"""Generate and check ``tests/gate0_manifest.json``.

The manifest is the checked-in map from every Revision 5 Gate 0 requirement and
every named attack case to the exact pytest node IDs that prove it. ``tests/
conftest.py`` refuses to let the Gate 0 command report green unless the collected
node IDs equal that map exactly.

The requirement table below is the reviewable artefact: each entry states the
requirement in Revision 5's own terms, cites where it comes from, and names the
tests by exact node ID or by test class. This script expands the classes against
a real pytest collection, so a manifest can never drift from what actually runs,
and it fails if any collected test is left unmapped — an unmapped test is a test
nobody has said what it proves.

    python scripts/gate0_manifest.py            # check (exit 1 on drift)
    python scripts/gate0_manifest.py --write    # regenerate
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import subprocess
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
MANIFEST = REPO / "tests" / "gate0_manifest.json"
GATE0_FILES = ("tests/test_gate0.py", "tests/test_contract.py")

# The controlling documents, pinned by hash. NOTHING here is emitted on trust:
# `read_controlling_documents()` opens each file, hashes the bytes, and refuses to
# generate a manifest it cannot verify. A hard-coded hash that is never checked
# against a file is a claim, not evidence, and a manifest built on one would keep
# asserting a specification revision that had already changed underneath it.
SPEC_DOCUMENT = "CATHEDRAL-CLI-LAUNCH-PRD-TECH-SPEC-20260731.md"
REVIEW_DOCUMENT = "GATE0-INDEPENDENT-REVIEW-20260731.md"
DIRECTIVE_DOCUMENT = "GATE0-FABLE-REPAIR-DIRECTIVE-20260731.md"
SPEC_REVISION = 5
PINNED_HASHES = {
    SPEC_DOCUMENT: "c1d6f1be5a44dd1c773089d6d4214290a72774f619336590cc17869608fff2d1",
    REVIEW_DOCUMENT: "0a9f4f1ad0d0853d0a67cb7678e635f126c20564e51c1a3d2a64996673928c31",
    DIRECTIVE_DOCUMENT: "e92760de335c92527cb414bde4334e741c04ef1741a8fcb29345dc904bd39d1f",
}
SPEC_DIR_ENV = "CATHEDRAL_SPEC_DIR"
SPEC_DIR_DEFAULTS = (
    str(REPO / "docs" / "gate0-spec"),
    "~/Documents/PROJECTS/cathedral-unified-cli-launch",
)


def locate_documents() -> Path:
    candidates = []
    override = os.environ.get(SPEC_DIR_ENV)
    if override:
        candidates.append(Path(override).expanduser())
    candidates.extend(Path(p).expanduser() for p in SPEC_DIR_DEFAULTS)
    for candidate in candidates:
        if all((candidate / name).is_file() for name in PINNED_HASHES):
            return candidate
    raise SystemExit(
        "the controlling documents were not found. The manifest records their hashes, "
        "so it may only be generated where they can actually be read.\n"
        f"Set ${SPEC_DIR_ENV} to the directory holding:\n  - "
        + "\n  - ".join(PINNED_HASHES))


def read_controlling_documents() -> dict[str, str]:
    """Hash the real documents and refuse anything that is not the pinned revision."""
    directory = locate_documents()
    actual = {}
    for name in PINNED_HASHES:
        digest = hashlib.sha256((directory / name).read_bytes()).hexdigest()
        actual[name] = digest
    drift = {n: (a, PINNED_HASHES[n]) for n, a in actual.items() if a != PINNED_HASHES[n]}
    if drift:
        lines = [f"{n}: on disk {a}, pinned {p}" for n, (a, p) in sorted(drift.items())]
        raise SystemExit(
            "a controlling document has changed. Gate 0 is defined by these exact bytes, "
            "so the manifest will not be regenerated until the change is reviewed and the "
            "pinned hashes are updated deliberately:\n  - " + "\n  - ".join(lines))
    print(f"controlling documents verified in {directory}")
    return actual


def specification_block(hashes: dict[str, str]) -> dict:
    return {
        "document": SPEC_DOCUMENT, "revision": SPEC_REVISION, "sha256": hashes[SPEC_DOCUMENT],
        "review": {"document": REVIEW_DOCUMENT, "sha256": hashes[REVIEW_DOCUMENT]},
        "repair_directive": {"document": DIRECTIVE_DOCUMENT,
                             "sha256": hashes[DIRECTIVE_DOCUMENT]},
    }


G0 = "tests/test_gate0.py"
CT = "tests/test_contract.py"


def n(class_name: str, test: str, file: str = G0) -> str:
    return f"{file}::{class_name}::{test}"


def cls(class_name: str, file: str = G0) -> str:
    """A whole test class, expanded against the real collection."""
    return f"@class:{file}::{class_name}"


# (id, source, statement, tests)
REQUIREMENTS: list[tuple[str, str, str, list[str]]] = [
    # --- PRD section 8: required implementation of verify_active_group -------
    ("G0-IMPL-01", "PRD 8.1", "Strictly parse the active pointer with an exact key set.",
     [n("TestActiveGroupTamper", "test_pointer_field_tampers"),
      n("TestActiveGroupTamper", "test_a_symlinked_pointer_is_refused")]),
    ("G0-IMPL-02", "PRD 8.2",
     "Obtain the trust root from protected configuration, never the pointer.",
     [n("TestActiveGroupTamper", "test_a_trust_root_that_does_not_authorize_the_release_identity_is_refused"),
      n("TestReleaseVerification", "test_a_world_writable_allowed_signers_is_refused"),
      n("TestReleaseVerification", "test_a_symlinked_allowed_signers_is_refused")]),
    ("G0-IMPL-03", "PRD 8.3-8.6",
     "Read the retained manifest and signature under the named release digest, reverify the "
     "signature with the pinned release identity, strictly parse it, and bind the manifest and "
     "signature digests to the pointer.",
     [n("TestActiveGroupTamper", "test_retained_manifest_and_signature_tampers")]),
    ("G0-IMPL-04", "PRD 8.7",
     "Bind version and digest to the durable replay floor.",
     [n("TestRecoveryAndFloor", "test_active_pointer_must_exactly_equal_floor"),
      n("TestActiveGroupTamper", "test_missing_or_corrupt_floor_fails_closed")]),
    ("G0-IMPL-05", "PRD 8.8", "Require exactly the three canonical roles.",
     [n("TestReleaseVerification", "test_a_release_missing_a_role_is_refused"),
      n("TestReleaseVerification", "test_an_unknown_role_is_refused"),
      n("TestInstallTransaction", "test_a_release_that_is_not_the_full_role_set_is_refused")]),
    ("G0-IMPL-06", "PRD 8.9", "Reauthorize every signed role against the current local lock.",
     [n("TestReleaseVerification", "test_a_forged_revision_is_not_authorized_by_the_local_lock")]),
    ("G0-IMPL-07", "PRD 8.10",
     "Fully verify every generation and receipt against the signed role, pointer, current lock "
     "and filesystem.",
     [n("TestActiveGroupTamper", "test_baseline_group_verifies"),
      n("TestReceiptBinding", "test_every_receipt_provenance_field_changed_individually_is_refused")]),
    ("G0-IMPL-08", "PRD 8.11",
     "Return a sealed verified group used by all execution paths.",
     [n("TestVerifiedRuntimeBinding", "test_verified_group_is_private_frozen_and_role_map_is_immutable"),
      n("TestVerifiedRuntimeBinding", "test_runtime_executes_only_paths_from_the_verified_group_snapshot")]),
    ("G0-IMPL-09", "PRD 8.12", "Reverify no-op updates.",
     [n("TestActiveGroupTamper", "test_a_no_op_reapply_over_a_tampered_generation_does_not_falsely_succeed"),
      n("TestActiveGroupTamper", "test_a_valid_no_op_reapply_is_idempotent_and_reverifies")]),
    ("G0-IMPL-10", "PRD 8.13", "Reverify both pending and prior groups during recovery.",
     [n("TestRecoveryAndFloor", "test_valid_prior_is_independently_verified_before_restart"),
      n("TestInstallTransaction", "test_recovery_commits_a_valid_pending_group")]),

    # --- PRD section 8: non-skippable attack matrices ------------------------
    ("G0-ATK-POINTER", "PRD 8 matrix 1",
     "Pointer schema, state, roles, generation IDs, swaps, traversal, version, identity, release "
     "digest, signature digest, trust-path redirection, timestamp and prior pointer.",
     [n("TestActiveGroupTamper", "test_prior_pointer_tampers"),
      n("TestVerifiedRuntimeBinding", "test_stat_preserving_pointer_rewrite_is_not_cached")]),
    ("G0-ATK-RETAINED", "PRD 8 matrix 2",
     "Missing, changed, cross-signed or cross-digest retained release.",
     [n("TestVerifiedRuntimeBinding", "test_retained_release_tamper_after_first_state_is_not_cached"),
      n("TestReleaseVerification", "test_a_forged_signer_is_refused")]),
    ("G0-ATK-RECEIPT-MISSING", "PRD 8 matrix 3",
     "Every required receipt field missing individually.",
     [n("TestReceiptBinding", "test_every_required_receipt_field_missing_individually_is_refused")]),
    ("G0-ATK-RECEIPT-CHANGED", "PRD 8 matrix 4",
     "Every receipt provenance field changed individually.",
     [n("TestReceiptBinding", "test_every_receipt_provenance_field_changed_individually_is_refused"),
      n("TestReceiptBinding", "test_receipt_paths_types_and_timestamp_are_strict")]),
    ("G0-ATK-RECEIPT-UNKNOWN", "PRD 8 matrix 5", "Unknown receipt field.",
     [n("TestReceiptBinding", "test_an_unknown_receipt_field_is_refused")]),
    ("G0-ATK-CROSS", "PRD 8 matrix 6",
     "Cross-role, cross-release, mixed-generation, same-version-different-digest, forged signer, "
     "forged revision, active-pointer-after-install and forged no-op attacks.",
     [n("TestActiveGroupTamper", "test_cross_role_receipt_swap"),
      n("TestActiveGroupTamper", "test_cross_release_generation_selection_is_refused"),
      n("TestReleaseVerification", "test_replay_semantics")]),
    ("G0-ATK-FS", "PRD 8 matrix 7",
     "Changed, deleted, extra, mode-changed, owner-changed, symlinked, interpreter-swapped, "
     "bytecode-planted or ancestor-symlinked managed files.",
     [n("TestActiveGroupTamper", "test_filesystem_mutation_matrix"),
      n("TestActiveGroupTamper", "test_a_group_writable_generation_or_receipt_is_refused"),
      n("TestInstallTransaction", "test_generations_are_frozen_read_only_including_the_receipt")]),
    ("G0-ATK-TXN", "PRD 8 matrix 8",
     "Receipt write failure, pending pointer write failure, crash after pending, failed health "
     "rollback, forged prior, corrupt floor and no-op revalidation.",
     [n("TestInstallTransaction", "test_receipt_write_failure_leaves_no_generation_or_pointer"),
      n("TestInstallTransaction", "test_pending_pointer_write_failure_leaves_no_committed_state"),
      n("TestInstallTransaction", "test_an_incomplete_generation_is_removed_when_preparation_fails"),
      n("TestInstallTransaction", "test_failed_activation_health_rolls_back_and_preserves_the_prior_group"),
      n("TestInstallTransaction", "test_read_only_state_reports_recovery_required_and_never_mutates")]),
    ("G0-ATK-READY", "PRD 8 matrix 9",
     "Role-specific readiness and liveness: immediate clean exit, immediate nonzero exit, wrong "
     "endpoint, stale PID, readiness timeout, hanging server and server exit after readiness.",
     [n("TestInstallTransaction", "test_role_readiness_and_liveness_matrix")]),
    ("G0-ATK-ENV", "PRD 8 matrix 10",
     "Minimal allowlisted environment for every signed engine check: no host PYTHONPATH, virtual "
     "environment selector, preload, proxy or credential variable crosses the boundary.",
     [n("TestInstallTransaction", "test_pip_runs_offline_and_hardened_with_a_minimal_environment")]),
    ("G0-ATK-WHEEL", "PRD 8 matrix 11",
     "Applicable wheel markers, platform tags, Python versions, ABI compatibility and every "
     "dependency version constraint.",
     [n("TestReleaseVerification", "test_a_foreign_abi_or_platform_is_refused"),
      n("TestReleaseVerification", "test_a_foreign_python_version_range_is_refused"),
      n("TestInstallTransaction", "test_a_wheel_whose_internal_metadata_disagrees_is_rejected"),
      n("TestInstallTransaction", "test_an_unsatisfiable_dependency_version_constraint_is_rejected")]),
    ("G0-ATK-CLOSURE", "PRD 8 matrix 12",
     "No network dependency resolution and no installed package outside the signed closure.",
     [n("TestInstallTransaction", "test_a_base_only_validator_closure_is_rejected"),
      n("TestInstallTransaction", "test_a_malicious_source_archive_is_never_built"),
      n("TestInstallTransaction", "test_no_install_subprocess_runs_when_the_signature_fails")]),
    ("G0-ATK-LIFECYCLE", "PRD 8 matrix 13",
     "Singleton ownership, process-group cleanup, concurrent update, lock ownership, stale-lock "
     "recovery, and idempotent stop and restart.",
     [n("TestInstallTransaction", "test_a_concurrent_transaction_is_refused_not_interleaved"),
      n("TestInstallTransaction", "test_a_stale_role_lock_is_reclaimed_and_stop_is_idempotent"),
      n("TestVerifiedRuntimeBinding",
        "test_shared_runtime_guard_blocks_concurrent_activation_until_process_exit")]),

    # --- PRD section 6: release invariants -----------------------------------
    ("G0-REL-SIGNED", "PRD 6 release invariants",
     "One canonical signed manifest, pinned signer identity, exact artifact hashes, complete wheel "
     "closure, and no untrusted code before verification.",
     [cls("TestReleaseVerification"), cls("TestAuthorizationImmutability")]),
    ("G0-REL-INSTALL", "PRD 6 release invariants",
     "A signed whole-node release installs exactly the three roles, offline, with no network "
     "dependency resolution, and persists provenance.",
     [n("TestInstallTransaction", "test_a_signed_release_installs_all_three_roles_and_persists_provenance"),
      cls("TestChannelDelivery")]),
    ("G0-REL-EXPIRY", "PRD 6 release invariants",
     "Signed-bundle expiry is an installation and update window, not a runtime kill switch: an "
     "installed release stays runnable while its signature, retained authorization, replay floor, "
     "filesystem and revocation state still verify.",
     [n("TestExpiryAndRevocation",
        "test_expired_installed_release_remains_valid_but_cannot_be_newly_activated"),
      n("TestReleaseVerification", "test_an_expired_release_still_verifies_for_retained_runtime"),
      n("TestReleaseVerification", "test_an_expired_release_is_refused_for_acquisition"),
      n("TestReleaseVerification", "test_an_unknown_validation_mode_is_refused")]),
    ("G0-REL-FLOOR", "PRD 6 release invariants",
     "A missing or corrupt replay floor fails closed, and the highest externally accepted release "
     "version never decreases.",
     [n("TestInstallTransaction", "test_the_durable_floor_survives_a_destroyed_pointer"),
      n("TestRecoveryAndFloor", "test_missing_pointer_and_floor_with_retained_state_is_not_fresh")]),
    ("G0-REL-ROLLBACK", "PRD 6 release invariants",
     "A prior group is restored only after independent full verification, and offline rollback "
     "requires cached signed revocation state inside its freshness window.",
     [n("TestRecoveryAndFloor", "test_invalid_nested_prior_is_neither_written_nor_started"),
      n("TestExpiryAndRevocation", "test_offline_rollback_refuses_stale_revocation_state")]),
    ("G0-REL-REVOCATION", "PRD 6 trust authority invariants",
     "Revocation state is signed, versioned, expiring and freshness checked, and a separate "
     "authority from the release signer.",
     [n("TestExpiryAndRevocation", "test_a_revoked_release_signer_blocks_restart_offline"),
      n("TestExpiryAndRevocation", "test_stale_revocation_knowledge_is_reported_explicitly")]),

    # --- repair directive section 1: verified runtime binding ----------------
    ("D-1.1", "Directive 8.1",
     "Verified runtime state is a private, frozen, slotted value with immutable nested maps.",
     [n("TestVerifiedRuntimeBinding", "test_verified_group_is_private_frozen_and_role_map_is_immutable")]),
    ("D-1.2", "Directive 8.2",
     "A generation tampered after a first successful read is not trusted by a cache.",
     [n("TestVerifiedRuntimeBinding", "test_generation_tamper_after_first_state_is_not_cached")]),
    ("D-1.3", "Directive 8.3",
     "A retained release tampered after a first successful read is not trusted by a cache.",
     [n("TestVerifiedRuntimeBinding", "test_retained_release_tamper_after_first_state_is_not_cached")]),
    ("D-1.4", "Directive 8.4",
     "A stat-preserving pointer rewrite is not trusted by a cache.",
     [n("TestVerifiedRuntimeBinding", "test_stat_preserving_pointer_rewrite_is_not_cached")]),
    ("D-1.5", "Directive 8.5",
     "State's interpreter path comes from the verified role, not a second pointer read.",
     [n("TestVerifiedRuntimeBinding",
        "test_state_python_path_comes_from_verified_role_not_second_pointer_read")]),
    ("D-1.6", "Directive 8.6",
     "A pointer swap after verification starts no process on `start`.",
     [n("TestVerifiedRuntimeBinding", "test_start_pointer_swap_after_verify_starts_no_process")]),
    ("D-1.7", "Directive 8.7",
     "A generation tampered after qualification starts no process on `start`.",
     [n("TestVerifiedRuntimeBinding",
        "test_start_generation_tamper_after_qualification_starts_no_process")]),
    ("D-1.8", "Directive 8.8", "A pointer swap after verification runs no engine on `test`.",
     [n("TestVerifiedRuntimeBinding", "test_test_pointer_swap_after_verify_runs_no_engine")]),
    ("D-1.9", "Directive 8.9",
     "A generation tampered after qualification runs no engine on `test`.",
     [n("TestVerifiedRuntimeBinding",
        "test_test_generation_tamper_after_qualification_runs_no_engine")]),
    ("D-1.10", "Directive 8.10",
     "Status verifies one group per command and never mixes role generations.",
     [n("TestVerifiedRuntimeBinding", "test_status_verifies_one_group_and_never_mixes_role_generations")]),
    ("D-1.11", "Directive 8.11",
     "The shared runtime guard blocks a concurrent activation until the operation exits.",
     [n("TestVerifiedRuntimeBinding",
        "test_shared_runtime_guard_blocks_concurrent_activation_until_process_exit")]),
    ("D-1.12", "Directive 8.12",
     "The supervisor receives a verified group, not arbitrary generation identifiers.",
     [n("TestVerifiedRuntimeBinding", "test_supervisor_receives_verified_group_not_generation_ids")]),

    # --- repair directive section 2/4: recovery and floor --------------------
    ("D-2.13", "Directive 8.13", "An invalid nested prior is neither written nor started.",
     [n("TestRecoveryAndFloor", "test_invalid_nested_prior_is_neither_written_nor_started")]),
    ("D-2.14", "Directive 8.14", "A valid prior is independently verified before restart.",
     [n("TestRecoveryAndFloor", "test_valid_prior_is_independently_verified_before_restart")]),
    ("D-2.15", "Directive 8.15", "Recovery never mixes pending and prior generations.",
     [n("TestRecoveryAndFloor", "test_recovery_pending_and_prior_cannot_mix_generations")]),
    ("D-2.16", "Directive 8.16",
     "A floor that already names pending never rolls back below the floor.",
     [n("TestRecoveryAndFloor", "test_floor_raised_pending_never_rolls_back_below_floor")]),
    ("G0-REL-LEDGER", "PRD 6 release invariants",
     "The retained rollback authorization ledger is separate from the external release floor and "
     "appends an auditable rollback record.",
     [n("TestRecoveryAndFloor", "test_offline_rollback_appends_an_auditable_authorization_record")]),
    ("D-2.17", "Directive 8.17", "A supervisor restart failure makes recovery fail.",
     [n("TestRecoveryAndFloor", "test_supervisor_restart_failure_makes_recovery_fail")]),
    ("D-2.18", "Directive 8.18", "Update refuses an existing unverified active group.",
     [n("TestRecoveryAndFloor", "test_update_refuses_an_existing_unverified_active_group")]),
    ("D-4.19", "Directive 8.19",
     "The floor requires an exact schema, exact types and a lowercase hex digest.",
     [n("TestRecoveryAndFloor", "test_floor_requires_exact_schema_types_and_hex_digest")]),
    ("D-4.20", "Directive 8.20",
     "Same version with a different digest cannot replace the floor, and corrupt state is never "
     "repaired by overwrite.",
     [n("TestRecoveryAndFloor", "test_same_version_different_digest_cannot_replace_floor")]),
    ("D-4.21", "Directive 8.21", "The committed active pointer exactly equals the floor.",
     [n("TestRecoveryAndFloor", "test_active_pointer_must_exactly_equal_floor")]),
    ("D-4.22", "Directive 8.22",
     "A missing pointer and floor with retained state is not fresh.",
     [n("TestRecoveryAndFloor", "test_missing_pointer_and_floor_with_retained_state_is_not_fresh")]),
    ("D-4.23", "Directive 8.23",
     "The pending/floor/active crash matrix preserves monotonicity.",
     [n("TestRecoveryAndFloor", "test_crash_matrix_pending_floor_active_preserves_monotonicity")]),
    ("D-4.24", "Directive 8.24",
     "A parallel update and recovery leave one consistent floor and pointer.",
     [n("TestRecoveryAndFloor", "test_parallel_update_and_recover_leave_one_consistent_floor_and_pointer")]),

    # --- repair directive section 3/5: expiry and revocation -----------------
    ("D-3.25", "Directive 8.25",
     "An expired installed release remains valid but cannot be newly activated.",
     [n("TestExpiryAndRevocation",
        "test_expired_installed_release_remains_valid_but_cannot_be_newly_activated")]),
    ("D-3.26", "Directive 8.26",
     "A floor-committed pending release recovers after manifest expiry.",
     [n("TestExpiryAndRevocation", "test_floor_committed_pending_recovers_after_manifest_expiry")]),
    ("D-3.27", "Directive 8.27",
     "An uncommitted expired pending release restores only a verified prior.",
     [n("TestExpiryAndRevocation", "test_uncommitted_expired_pending_restores_only_verified_prior")]),
    ("D-5.28", "Directive 8.28",
     "Install requires a verified cached revocation snapshot.",
     [n("TestExpiryAndRevocation", "test_install_requires_verified_cached_revocation_snapshot")]),
    ("D-5.29", "Directive 8.29",
     "An invalid or older revocation snapshot preserves the last known good cache.",
     [n("TestExpiryAndRevocation",
        "test_invalid_or_older_revocation_snapshot_preserves_last_good_cache")]),
    ("D-5.30", "Directive 8.30", "A revoked active digest blocks restart, offline.",
     [n("TestExpiryAndRevocation", "test_revoked_active_digest_blocks_restart_offline")]),
    ("D-5.31", "Directive 8.31", "A channel outage uses the last known good revocation cache.",
     [n("TestExpiryAndRevocation", "test_channel_outage_uses_last_good_revocation_cache")]),

    # --- repair directive section 6: receipt and cleanup ---------------------
    ("D-6.32", "Directive 8.32",
     "A regular-file interpreter replacement with a fully recomputed receipt still fails.",
     [n("TestReceiptBinding", "test_regular_interpreter_replacement_with_forged_receipt_fails")]),
    ("D-6.33", "Directive 8.33",
     "Changed source with a recomputed local manifest still fails the signed source hash.",
     [n("TestReceiptBinding",
        "test_changed_source_with_recomputed_local_manifest_fails_signed_source_hash")]),
    ("D-6.34", "Directive 8.34", "Receipt paths, types and timestamp are strict.",
     [n("TestReceiptBinding", "test_receipt_paths_types_and_timestamp_are_strict")]),
    ("D-6.35", "Directive 8.35",
     "Malformed nested venv_python_stat is a controlled refusal, not an exception.",
     [n("TestReceiptBinding", "test_malformed_venv_python_stat_refuses_without_exception")]),
    ("D-6.36", "Directive 8.36", "A receipt write failure leaves no generation or pointer.",
     [n("TestInstallTransaction", "test_receipt_write_failure_leaves_no_generation_or_pointer")]),
    ("D-6.37", "Directive 8.37",
     "A cached success does not survive receipt, tree or signature mutation.",
     [n("TestReceiptBinding", "test_cached_success_does_not_survive_receipt_tree_or_signature_mutation")]),
    ("D-6.38", "Directive 8.38",
     "The runtime executes only paths from the verified group snapshot.",
     [n("TestVerifiedRuntimeBinding",
        "test_runtime_executes_only_paths_from_the_verified_group_snapshot")]),

    ("G0-REAL-ADAPTER", "PRD 7 / Directive 1.6",
     "Engine executable, source, venv, receipt and configuration paths come from the bound "
     "VerifiedRole, proven against the repository's real adapters bound to a real verified "
     "generation, including that argv never carries a secret.",
     [cls("TestRealAdapterBinding")]),

    # --- runtime follow-up: the signed-child environment boundary ------------
    ("RT-1-ENV", "Runtime follow-up 1",
     "One central minimal signed-child environment builder, with inheritance an explicit "
     "choice for run, probe and stream. Hostile PYTHONPATH, preload, proxy, virtualenv, cloud "
     "credential and token variables cross no install, active-verification, local-test or "
     "long-running start path.",
     [cls("TestSignedChildEnvironment"), cls("TestInheritedEnvironmentAttack")]),

    # --- runtime follow-up: durable process-group ownership ------------------
    ("RT-2-OWNERSHIP", "Runtime follow-up 2",
     "Durable child ownership — child pid, process group, kernel start identity, effective uid "
     "and verified generation — is persisted before start is reported, validated before the "
     "stored process group is signalled, and stop waits until every group member is gone. Parent "
     "crash, orphan child, PID reuse, duplicate start and process-group cleanup are proven "
     "against production proc and state.",
     [cls("TestChildOwnership")]),

    # --- runtime follow-up: the validator configuration projection -----------
    ("RT-3-VALIDATOR-CONFIG", "Runtime follow-up 3",
     "cathedral config set validator holds a verified lease, binds the adapter to its verified "
     "role, renders and parses the complete result, verifies every required projected field, and "
     "commits both files atomically with no partial-success state.",
     [cls("TestValidatorConfigProjection")]),

    # --- runtime follow-up: the single publisher fence -----------------------
    ("RT-4-PUBLISHER-FENCE", "Runtime follow-up 4 / PRD 4",
     "The publisher fence is acquired before the validator child starts, keyed by network, netuid "
     "and validator hotkey, held until the owned process group is proven gone; two homes with the "
     "same publisher identity cannot run concurrently, and the broadcast refusal offers no escape "
     "around the node.",
     [cls("TestPublisherFence")]),

    # --- runtime follow-up: rollback witness truth ---------------------------
    ("RT-6-ROLLBACK-WITNESS", "Runtime follow-up 6",
     "A prior group that verifies but fails restart or readiness leaves the interrupted "
     "transaction recorded, so recovery is still required and no later run reports nothing to "
     "recover; the update command does not claim the prior release was kept.",
     [cls("TestRollbackWitness")]),

    # --- hardened locks and secure reads -------------------------------------
    ("RT-7-LOCKS", "Independent follow-up runtime 7",
     "The lifecycle lock and every durable security read refuse symlinks, wrong file types, "
     "foreign owners, unsafe modes, hard links and replacement during acquisition.",
     [cls("TestLifecycleLockHardening"), cls("TestSecureLockAndReadHardening")]),

    # --- signed revocation state ---------------------------------------------
    ("RT-REVOCATION", "Independent follow-up runtime 1-3",
     "The revocation cache is one atomically replaced container, a durable monotonic sequence "
     "floor refuses a restored older cache, the state and its lock refuse unsafe files, and a "
     "stale snapshot refuses acquisition and rollback while still serving retained runtime.",
     [cls("TestRevocationTransaction"), cls("TestRevocationCacheAndFloor"),
      cls("TestAcquisitionFreshness")]),

    # --- the lease boundary, uninstall and cleanup ---------------------------
    ("RT-LEASE", "Independent follow-up runtime 6",
     "Reporting commands hold the verified lifecycle lease while they run installed code; "
     "uninstall never authorizes deletion from a lenient pointer read, takes the lifecycle lock, "
     "and cleanup does not report success after uninstall refuses.",
     [cls("TestLeaseIsNotEscaped"), cls("TestFailureLeavesACleanRetry")]),

    # --- readiness, liveness and the signed update chain ---------------------
    ("RT-READINESS", "PRD 8 matrix 9 / Independent follow-up runtime 5",
     "Wrong endpoint, readiness timeout, hanging server, stale PID, process-group cleanup and "
     "idempotent restart, proven against processes that really run.",
     [cls("TestReadinessAndLiveness")]),
    ("RT-ROLLBACK-TERMINATION", "Independent follow-up runtime 4-5",
     "Rollback proves termination of the outgoing process group before publishing or clearing a "
     "pointer, returns a failed rollback to the caller, deletes nothing a process may still "
     "execute, and a failed retention leaves a fresh node that can retry.",
     [cls("TestRollbackTermination")]),
    ("RT-UPDATE-CHAIN", "Independent follow-up runtime 8",
     "Repeated signed v1 to v2 to v3 update with controlled restart, crash recovery and rollback, "
     "retaining exactly one prior generation per role throughout.",
     [cls("TestRepeatedUpdateCycle")]),

    # --- the harness itself ---------------------------------------------------
    ("RT-HARNESS", "Independent follow-up harness 1-6",
     "The acceptance harness refuses every narrowing option, every pytest environment mutation, "
     "an altered target set and direct node selection; it validates the manifest as a document; "
     "and the runner scripts show exactly what they run.",
     [cls("TestGateHarnessCannotBeNarrowed", CT), cls("TestGateManifestSemantics", CT)]),

    # --- atomicity counterexample 1 ------------------------------------------
    ("CE-1-REVOCATION-PARTIAL-COMMIT", "Atomicity counterexamples 1",
     "A crash between the revocation cache write and the floor write leaves the cache ahead of "
     "the floor. An identical retry of the higher sequence heals the floor rather than being "
     "rejected as a digest conflict against the lower one; a different digest at that sequence "
     "stays rejected; a restored older cache is never readmitted; and all of it holds across "
     "fresh interpreters.",
     [cls("TestRevocationPartialCommitRecovery")]),

    # --- atomicity counterexample 2 ------------------------------------------
    ("CE-2-ORPHANED-PROCESS-GROUP", "Atomicity counterexamples 2",
     "A launcher dies while a descendant of the recorded group leader survives. Ownership is the "
     "process group, so install pruning and uninstall both refuse to delete the generation until "
     "the whole owned group is proven stopped; an ownership publication failure after spawn "
     "terminates the group before returning; a malformed record fails closed; and a boot identity "
     "stops a pre-reboot record from authorising signalling or deletion.",
     [cls("TestOrphanedProcessGroupBlocksDeletion")]),

    # --- PRD section 5: the canonical CLI contract ---------------------------
    ("G0-CLI-ENVELOPE", "PRD 5",
     "Every command returns one versioned machine envelope with a stable exit code, and human "
     "output is rendered from that same envelope.",
     [cls("TestEnvelopeShape", CT), cls("TestErrorContract", CT), cls("TestProtocolVersioning", CT),
      cls("TestExitCodeDocumentation", CT), cls("TestEarlyFailures", CT)]),
    ("G0-CLI-SECRETS", "PRD 5",
     "No secret appears in argv, stdout, stderr, logs, receipts, run state, URLs or process "
     "metadata.",
     [cls("TestSecretHandling", CT), cls("TestSecretsNeverInHumanOutput", CT)]),
    ("G0-CLI-IDEMPOTENT", "PRD 5",
     "Commands are idempotent and non-interactive, and a required confirmation is reported rather "
     "than prompted.",
     [cls("TestIdempotency", CT), cls("TestNonInteractive", CT)]),
    ("G0-CLI-ENGINES", "PRD 4",
     "Every role resolves to an engine adapter with a complete, honest capability contract, and "
     "the legacy validator is never pinned.",
     [cls("TestEngineContract", CT), cls("TestGeneratedBrief", CT), cls("TestNoRendererFallsBack", CT)]),
    ("G0-CLI-CONFIG", "PRD 6",
     "Owner-controlled configuration cannot be set by an operator, and a configuration value never "
     "becomes configuration structure.",
     [cls("TestConfigSafety", CT), cls("TestConfigInjection", CT)]),
    ("G0-CLI-STATE", "PRD 5",
     "Run state, ordering, locks and damaged state produce a diagnosis, never a crash or a lie.",
     [cls("TestRunOrdering", CT), cls("TestLockRecovery", CT), cls("TestFailureRecovery", CT),
      cls("TestProcRobustness", CT)]),
    ("G0-CLI-PRESENTATION", "PRD 5",
     "Human rendering is derived from the machine envelope, never crashes, and never claims more "
     "than was proven.",
     [cls("TestPresentation", CT), cls("TestAsciiStreamDetection", CT),
      cls("TestRenderingNeverCrashes", CT), cls("TestHonestyOnThePath", CT),
      cls("TestRemediationIsActionable", CT)]),
    ("G0-CLI-UPDATE", "PRD 6",
     "Updates come only from a signed release; an unsigned lockfile update is refused.",
     [cls("TestUpdateSource", CT)]),

    # --- independent review: the revocation transaction across every boundary ---
    ("G0-REV-HEAL", "PRD 8.7 / review",
     "A revocation floor that cannot be advanced is a refusal: an unfloored snapshot is never "
     "exported, and the older snapshot is never re-admitted.",
     [cls("TestRevocationHealFailsClosed"), cls("TestRevocationFloorAheadOfCache")]),
    ("G0-REV-PROVISION", "PRD 8.7 / review",
     "Provisioning is the same verified transaction as retention: unverified bytes never become "
     "the last known good snapshot, a different digest at the floor sequence is refused, and "
     "concurrent provisioning never lowers the floor.",
     [cls("TestRevocationProvisioningTransaction")]),
    ("G0-REV-OUTAGE", "PRD 8.7 / review",
     "A channel outage degrades to the cache only when the durable floor covers it, and a "
     "concurrent floor advance never yields a snapshot below the final floor.",
     [cls("TestRevocationOutageAndConcurrency")]),
    ("G0-REV-ANCESTOR", "PRD 8.2 / review",
     "Security files are refused through a redirected ancestor directory, not only a redirected "
     "final component.",
     [cls("TestRevocationDirectoryRedirection")]),

    # --- independent review: durable ownership of running processes -------------
    ("G0-LOCK-IDENTITY", "PRD 8.2 / review",
     "A lock file replaced at its name is refused: mutual exclusion may never silently become "
     "two holders on two inodes.",
     [n("TestLifecycleLockHardening", "test_replacing_the_lock_file_during_the_wait_is_detected")]),
    ("G0-OWN-OBSOLETE", "PRD 8.9 / review",
     "An ownership record in a shape this node cannot parse is unverifiable, never silently "
     "reclaimed, and blocks deletion.",
     [n("TestInstallTransaction", "test_an_obsolete_ownership_record_is_not_silently_reclaimed")]),
    ("G0-OWN-PROBE", "PRD 8.9 / review",
     "A failed process probe is never read as termination: it blocks prune and uninstall and "
     "never reports a completed stop.",
     [cls("TestOwnershipProbeFailure")]),
    ("G0-OWN-BOOT", "PRD 8.9 / review",
     "An unknown boot identity is unverifiable rather than stale, and a known previous boot is "
     "cleared without signalling reused ids.",
     [cls("TestOwnershipBootIdentity")]),
    ("G0-OWN-REUSE", "PRD 8.9 / review",
     "A pid or process group we cannot prove is ours never authorizes a signal or a deletion, "
     "including same-second reuse.",
     [cls("TestOwnershipPidReuse")]),
    ("G0-OWN-LEDGER", "PRD 8.9 / review",
     "An append-only launch ledger — not a command-line scan — proves that a launch was opened "
     "and never closed, through a deleted record, an exec'd descendant, and a spawn crash.",
     [cls("TestLaunchLedgerBlocksDeletion"), cls("TestLedgerIsADurableWitness")]),
    ("G0-OWN-ESCAPE", "PRD 8.9 / review",
     "A descendant that leaves its process group leaves an unfinished lease, and only a recorded "
     "ending closes one.",
     [cls("TestLeaseEscapesTheProcessGroup")]),
    ("G0-OWN-EXCLUSIVE", "PRD 8.9 / review",
     "A launch that cannot be durably claimed starts no process, and an open or unreadable lease "
     "prevents a second owner.",
     [cls("TestLeaseOwnershipIsExclusive")]),
    ("G0-OWN-IDENTITY", "PRD 8.9 / review",
     "Process identity is kernel-grade; leases from a known previous boot retire without "
     "signalling, and an unknown boot still fails closed.",
     [cls("TestLeaseIdentityAndBoots")]),
    ("G0-OWN-PUBLIC-STOP", "PRD 8.9 / review",
     "The public stop finds the child the ledger names when the role record is missing, and the "
     "post-loop exit closes the lease instead of raising.",
     [cls("TestPublicStopFindsTheLease")]),
    ("G0-OWN-PUBLIC-CRASH", "PRD 8.9 / review",
     "A crash of the public start command blocks public prune and uninstall, records the exact "
     "interrupted state, and recovers deterministically.",
     [cls("TestPublicStartLauncherCrash")]),
    ("G0-ACT-WITNESS", "PRD 8.7 / review",
     "The installer reports what actually happened at each commit boundary, and a retry heals "
     "activation witnesses rather than no-opping.",
     [cls("TestActivationWitnessReporting")]),

    # --- independent launch-lease review ----------------------------------------
    ("G0-OWN-DETACHED", "PRD 8.9 / review",
     "A descendant that leaves its process group keeps its lease open through the public start, "
     "stop and second-start cycle, and a lease that cannot prove its identity or owner is never "
     "signalled.",
     [cls("TestDetachedDescendantThroughPublicCommands")]),
    ("G0-OWN-INTENT", "PRD 8.9 / review",
     "A spawn that was never confirmed is never closed by inference, with or without a role "
     "record.",
     [cls("TestUnconfirmedSpawnIsNeverClosed")]),
    ("G0-OWN-LEDGER-LOCK", "PRD 8.9 / review",
     "One lock covers appends and compaction, so a concurrent append is never durably written "
     "into an unlinked inode.",
     [cls("TestLedgerLockIsSingle")]),

    # --- independent revocation and safe-I/O review ------------------------------
    ("G0-REV-CHANNEL", "PRD 8.7 / review",
     "No channel outcome — invalid, older, equal-conflict, expired or malformed — exports a "
     "cache ahead of the durable floor or lets the older snapshot back in.",
     [cls("TestRevocationChannelOutcomes")]),
    ("G0-IO-ANCESTOR-RACE", "PRD 8.2 / review",
     "A directory replaced while a security file is being locked or written is a refusal, not a "
     "lock on a detached inode or a write reported as published.",
     [cls("TestAncestorReplacementDuringIO")]),

    # --- independent installer review --------------------------------------------
    ("G0-EXEC-BINDING", "PRD 8.9 / review",
     "Execution is bound to the exact verified inode: a program replaced after revalidation and "
     "before exec is detected before start is reported, and nothing from it survives.",
     [cls("TestVerifyToExecBinding")]),
    ("G0-COMMIT-TRUTH", "PRD 8.7 / review",
     "Outcomes are classified by the durable state on disk, not by which exception was raised: "
     "post-publish failures report committed, healing is release-bound, a rollback that could "
     "not clear the pointer is not a rollback, and the transaction records are hardened.",
     [cls("TestCommittedStateIsReportedNotGuessed")]),
]


def collect() -> list[str]:
    result = subprocess.run(  # noqa: S603
        [sys.executable, "-m", "pytest", "--collect-only", "-q", "-p", "no:cacheprovider",
         *GATE0_FILES],
        cwd=REPO, capture_output=True, text=True)
    if result.returncode != 0:
        sys.stderr.write(result.stdout + result.stderr)
        raise SystemExit("collection failed")
    node_ids = []
    for line in result.stdout.splitlines():
        line = line.strip()
        if line.startswith(GATE0_FILES) and "::" in line:
            node_ids.append(line)
    if not node_ids:
        raise SystemExit("no node IDs collected")
    return node_ids


def build(collected: list[str]) -> dict:
    by_class: dict[str, list[str]] = {}
    for node_id in collected:
        parts = node_id.split("::")
        if len(parts) >= 3:
            by_class.setdefault(f"{parts[0]}::{parts[1]}", []).append(node_id)

    requirements = []
    covered: set[str] = set()
    problems: list[str] = []
    for req_id, source, statement, entries in REQUIREMENTS:
        tests: list[str] = []
        for entry in entries:
            if entry.startswith("@class:"):
                key = entry[len("@class:"):]
                members = by_class.get(key)
                if not members:
                    problems.append(f"{req_id}: class {key} collected no tests")
                    continue
                tests.extend(members)
            else:
                if entry not in collected:
                    problems.append(f"{req_id}: node ID does not collect: {entry}")
                    continue
                tests.append(entry)
        # A test may prove more than one requirement, but must not be listed twice
        # inside the same requirement.
        unique = sorted(set(tests))
        covered.update(unique)
        requirements.append({"id": req_id, "source": source, "statement": statement,
                             "tests": unique})

    unmapped = sorted(set(collected) - covered)
    if unmapped:
        problems.append(f"{len(unmapped)} collected test(s) map to no requirement: {unmapped[:8]}")
    empty = [r["id"] for r in requirements if not r["tests"]]
    if empty:
        problems.append(f"requirements with no remaining unique proof: {empty}")
    if problems:
        raise SystemExit("manifest generation failed:\n  - " + "\n  - ".join(problems))

    return {
        "schema": "cathedral.gate0.requirement_manifest.v1",
        "specification": specification_block(read_controlling_documents()),
        "command": "python -m pytest -q tests/test_gate0.py tests/test_contract.py",
        "files": list(GATE0_FILES),
        "node_id_count": len(covered),
        "requirements": requirements,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--write", action="store_true", help="regenerate the manifest")
    args = parser.parse_args()
    manifest = build(collect())
    serialized = json.dumps(manifest, indent=2, sort_keys=False) + "\n"
    if args.write:
        MANIFEST.write_text(serialized)
        print(f"wrote {MANIFEST} — {manifest['node_id_count']} node IDs across "
              f"{len(manifest['requirements'])} requirements")
        return 0
    current = MANIFEST.read_text() if MANIFEST.exists() else ""
    if current != serialized:
        print("tests/gate0_manifest.json is out of date; run with --write")
        return 1
    print(f"manifest is current: {manifest['node_id_count']} node IDs across "
          f"{len(manifest['requirements'])} requirements")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

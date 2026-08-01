# The agent contract

Everything a program needs to drive a Cathedral node without a human present.

This contract is the product's primary interface. The terminal presentation is a
rendering of the same objects; it cannot show you something the contract does
not contain, and it cannot hide something the contract does.

## Versioning

`cathedral capabilities --json` reports `protocol_version`, currently **1.0.0**.

| Change | Bump | Your agent |
|---|---|---|
| Wording, added optional `data` fields | PATCH | keeps working |
| New commands, new optional envelope fields, new warnings | MINOR | keeps working |
| Removed field, changed type, changed exit code, renamed command | MAJOR | must be updated |

Pin the MAJOR. Pass `--protocol 1.0.0` to any command and it exits `32`
(`INCOMPATIBLE`) rather than running, if the node has moved on.

## The envelope

Every command writes exactly one JSON document to **stdout** under `--json`.

```json
{
  "schema": "cathedral.node.result.v1",
  "protocol_version": "1.0.0",
  "command": "test",
  "status": "ok",
  "exit_code": 0,
  "dry_run": false,
  "run_id": "test-20260730-235143-1a725b",
  "started_at": "2026-07-30T23:51:43.201Z",
  "finished_at": "2026-07-30T23:51:44.882Z",
  "duration_ms": 1681,
  "data_schema": "cathedral.node.test.v1",
  "data": { },
  "error": null,
  "warnings": [],
  "next": [ {"description": "...", "command": "cathedral ...", "safe": true} ]
}
```

`status` is `ok`, `failed`, or `blocked`. **`blocked` means nothing was
attempted** — a precondition was unmet — so no state changed and no cleanup is
needed.

`data_schema` versions the `data` payload independently, so a command can grow
its own shape without moving the protocol version.

### Streams

- **stdout** — under `--json`, exactly one envelope and nothing else, ever. Safe
  to pipe to a parser. Without `--json`, stdout carries the human rendering, so a
  command's output can be captured or piped like any other tool's.
- **stderr** — diagnostics only, and empty in normal operation. Never parse it.

Under `--json` the human view is silent, so stdout is a pure envelope. Without
`--json`, `cathedral doctor > log.txt` captures exactly what the operator saw, and
`cathedral doctor | grep hotkey` matches — the human view is on stdout, not stderr.

## Exit codes

Branch on these, not on message text. They are stable within a MAJOR version and
grouped so an unfamiliar code is still classifiable.

| Code | Name | Meaning |
|---|---|---|
| 0 | `OK` | Completed. For a verification, the verdict was PASS. |
| 10 | `NOT_READY` | A precondition failed. `error.remediation` says how to fix it. |
| 11 | `UNSUPPORTED` | This machine cannot do this, and no command changes that. |
| 12 | `CONFIG_INVALID` | Configuration missing, malformed, or inconsistent. |
| 13 | `CREDENTIAL_MISSING` | A required secret is not present. |
| 14 | `LOCKED` | Another process holds the role lock. Its pid and run id are in `detail`. |
| 20 | `VERIFY_FAILED` | Fail-closed verification refused the evidence. The node worked correctly. |
| 21 | `WORK_FAILED` | The engine ran and could not complete the work. |
| 22 | `TIMEOUT` | A bounded operation exceeded its deadline. State is preserved. |
| 30 | `USAGE` | Bad arguments. Never emitted after a side effect. |
| 31 | `NOT_FOUND` | A named run, artifact, or identifier does not exist. |
| 32 | `INCOMPATIBLE` | Protocol or engine mismatch. Stop and re-discover. |
| 40 | `NETWORK` | A required remote was unreachable. Always safe to retry. |
| 41 | `UPSTREAM` | A pinned engine failed in a way this layer does not model. |
| 50 | `CANCELLED` | Interrupted. Durable state was flushed; `resume` will continue. |
| 70 | `INTERNAL` | A bug in the node. Includes a diagnostics bundle path. |

**Retry** `40`, `22`, `14`, `41` with backoff. **Never retry** `11`, or anything
whose `error.remediation.requires_operator` is `true`.

Note the distinction that matters most: exit `20` means the node did its job and
the answer was no. It is not a malfunction and retrying will not change it.

## Errors

```json
"error": {
  "code": "identity.hotkey_missing",
  "message": "no hotkey configured, so work cannot be attributed to you",
  "remediation": {
    "summary": "Nothing was started.",
    "command": "cathedral config set distill hotkey <your-ss58-address>",
    "docs": null,
    "requires_operator": false
  },
  "detail": {}
}
```

`code` is dotted lowercase and matchable by prefix: `err.startswith("config.")`
classifies every configuration problem without enumerating them.

`remediation.command` is runnable verbatim.

`remediation.requires_operator: true` means **no command fixes this**. It needs
hardware, money, a credential, or an owner decision. Stop and escalate; do not
search for a workaround.

Code families: `env.`, `hardware.`, `install.`, `config.`, `identity.`,
`secret.`, `run.`, `verify.`, `contract.`, `network.`, `upstream.`, `usage.`,
`internal.`

## Discovery

```bash
cathedral capabilities --json
```

Returns the protocol version, every command, every exit code, the roles, the
conventions, and — per engine — whether each capability is genuinely available
**on this machine**. A capability is `available: true` only when running it here
would work. "Implemented upstream" is not "available".

`data.requires_owner_decision` collects everything no command can unlock, so you
read it once instead of discovering it three failures later.

## Driving a miner

```bash
cathedral capabilities --json                      # confirm protocol MAJOR
cathedral doctor --json                            # .data.roles.<role>.can_local_test
cathedral setup distill --json                     # idempotent
cathedral test distill --json                      # pays nothing, no chain access
cathedral status --json                            # what happened
```

Every command is safe to re-run. `setup`, `config set`, `secret set`, `stop`,
and `cleanup` are idempotent by design: calling them again when they have already
taken effect returns success without changing anything.

`--dry-run` on any command reports what would happen and changes nothing. The
envelope's `dry_run` field is `true` and no filesystem write occurs.

## Confirmations

A required confirmation is **never** hidden inside an interactive prompt. If one
is needed and cannot be obtained, the command exits `30` with
`usage.confirmation_required` and a remediation naming the flag:

```json
{"code": "usage.confirmation_required",
 "remediation": {"command": "cathedral update --yes"}}
```

Pass `--yes` to supply it.

## Identifiers

Results carry the exact identifiers the operator needs, under
`data.identifiers`. They are addressable: hand any of them back to
`cathedral evidence <id> --json` and get the run and events that produced it.

A Distill test returns `batch_nonce`, `task_ids`, `solved`, `score`; each check
carries its `task_id` and `poc_sha256`. A validator dry run returns `vector_id`,
`policy_version`, `signed_vector_sha256`, `uid_count`, `burn_uid`, `burn_share`,
and `uid_weights`.

## Events

Each run has a directory under `$CATHEDRAL_HOME/runs/<run_id>/`:

- `run.json` — the run record, updated as it progresses
- `events.jsonl` — one `cathedral.node.event.v1` per line
- `engine.log` — raw engine output, redacted

```json
{"schema":"cathedral.node.event.v1","ts":"2026-07-30T23:51:44.102Z",
 "run_id":"test-...","event":"CHECK","stage":"verify","status":"PASS",
 "detail":"level0 differential: ..."}
```

`cathedral logs --run <id> --json` returns them; `--follow` streams while a run
is live. `--raw` gives engine output instead when the noise is what you need.

## Interruption and resume

SIGINT or SIGTERM sends the engine a TERM, waits for it to flush, records the
run as `interrupted`, and exits `50`. The run record still describes what
happened, and `cathedral status --run <id>` tells the truth afterwards — a run
whose process died without finishing is reconciled to `interrupted` rather than
being reported as still running.

`cathedral resume <run-id>` continues. The engines keep their own durable fences
and journals, so resuming restarts the engine against that state; the node does
not claim a checkpoint the engines do not have, and says so in its response.

## Secrets

- Never pass a credential as an argument. The only accepted source is stdin:
  `printf '%s' "$KEY" | cathedral secret set NAME --stdin`
- Passing a literal value to a secret-reference config field is refused with
  `secret.unsafe_source`, before it can reach your shell history.
- Configuration stores the **name** of a secret, never its value.
  `cathedral config show --json` is always safe to include in a report.
- A coldkey, seed, or mnemonic is refused in every field, under every name.

## Boundaries

The node will not:

- accept a coldkey, seed, or mnemonic;
- enable chain writes — `--broadcast` is refused, with or without `--yes`;
- install or expose anything from the legacy `cathedralai/cathedral` repository;
- spend money, provision hardware, or register an identity.

When you hit one of these you will get `requires_operator: true`. Report it.

## Generated brief

```bash
cathedral agent-brief distill
```

Prints an instruction block generated from the live node — the current machine,
the current install state, the real blockers. Paste it into a coding agent. It
cannot describe a capability this machine does not have, because it is built
from the same capability report the contract exposes.

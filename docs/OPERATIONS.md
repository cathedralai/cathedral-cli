# Operations

Running a node day to day: what to expect, what to do when something goes
wrong, and what the node will not do for you.

## Where things live

```
$CATHEDRAL_HOME/                  default ~/.cathedral, mode 0700
  config/<role>.toml              safe to read; holds no credentials
  config/validator-engine.toml    generated; owner burn/lane settings live here
  secrets.env                     mode 0600; never printed
  engines/<role>/src              the pinned checkout
  engines/<role>/venv             that engine's isolated environment
  engines/<role>/installed.json   proof of what is installed
  runs/<run-id>/run.json          the run record
  runs/<run-id>/events.jsonl      meaningful state changes
  runs/<run-id>/engine.log        raw engine output, redacted
  state/<role>.lock               the role lock; self-healing
  logs/                           setup, update, and crash diagnostics
```

Set `CATHEDRAL_HOME` to run two independent nodes on one host. Nothing outside
that directory is written.

## Starting and stopping

```bash
cathedral start distill           # runs in this terminal
cathedral stop distill            # from another terminal
```

One role runs once per node. A second `start` reports the pid and run id of the
process that already holds the lock rather than racing it. A lock whose owner is
gone is reclaimed automatically — you never have to delete a stale lock file.

Ctrl-C sends the engine a TERM, waits for it to flush, records the run as
interrupted, and exits `50`. `cathedral status --run <id>` afterwards tells the
truth: a run whose process died without finishing is reconciled to `interrupted`
rather than reported as still running.

## Watching

```bash
cathedral status                        # every role, at a glance
cathedral status --run <id>             # one run in detail
cathedral logs distill --follow         # meaningful state changes, live
cathedral logs distill --raw -n 200     # unfiltered engine output
```

The default log view shows decisions and outcomes. `--raw` is for when the noise
is exactly what you need.

## Looking something up later

Every result carries the identifiers that matter. Hand any of them back:

```bash
cathedral evidence synthvuln:1d8e7f60:2
cathedral evidence 32c267a7-ed0e-4346-8ba1-a324c1ec6000
```

Identifiers are recorded per run and removed by `cleanup`, so keep the run if you
need the trail.

## Updating

```bash
cathedral update --check          # what a newer pin would change
cathedral update --yes            # apply
cathedral rollback --yes          # return to the previous revisions
```

An update refuses to run while a role is running — stop it first. It records the
outgoing revision before changing anything, which is what makes rollback
reinstall a known commit rather than a guess.

If an update fails partway, that engine is left **uninstalled** rather than
half-updated, and the failure names `cathedral rollback <role>` as the fix. A
node with a missing engine is a state the CLI understands; a node with a
half-installed one is not.

### Owner-controlled settings

What is yours is what you will **accept**: `require_policy` (which weight-policy
contract) and `weight_policy_key` (whose signature), plus your wallet and
network. They live in the node's configuration, not in engine files, so an
engine upgrade cannot reach them. `update` snapshots them before and after and
warns loudly if any moved — an alarm for something that should be structurally
impossible.

```bash
cathedral config get validator require_policy
cathedral config get validator weight_policy_key
```

The signing key is public by design. It is meant to be read aloud and checked
against Cathedral's published key, so it is shown in full in both the human and
`--json` views rather than masked.

**The burn share and the lane allocation are not yours, and are not settings.**
They arrive inside the Cathedral-signed weight vector and from Cathedral-signed
burn and allocation documents; nothing local changes them. Earlier versions of
this document — and of the config schema — offered `burn_fraction`,
`burn_destination` and `lane_allocation` as editable fields, which was worse than
useless: it let an operator believe they had changed the economics when nothing
had changed. If you want different economics, the lever is which contract and
which key you accept, above.

## Recovering

**"engine is not installed"** — `cathedral setup <role>`. Idempotent; safe to run
any time.

**"differs from the pinned revision"** — the checkout drifted.
`cathedral setup <role> --force` reinstalls from the pin.

**Verification failed (exit 20)** — the node worked correctly and the answer was
no. Nothing was submitted anywhere. Read the checks:
`cathedral logs <role> --run <id>`. Retrying will not change the result.

**"already running" (exit 14)** — the run id and pid are in the error detail.
`cathedral status <role>` shows it; `cathedral stop <role>` ends it.

**Internal error (exit 70)** — a bug in the node, not your setup. The response
names a diagnostics bundle under `logs/`. Set `CATHEDRAL_TRACEBACK=1` to also
print the traceback.

**Interrupted run** — `cathedral resume <run-id>`. The engines keep their own
durable fences and journals, so resuming restarts the engine against that state.
The node tells you that is what it is doing rather than implying a checkpoint the
engines do not have.

## Housekeeping

```bash
cathedral cleanup --runs --keep-days 7    # the safe default
cathedral cleanup --engine distill --yes  # remove one engine
cathedral cleanup --all --yes             # runs and engines
```

No variant removes configuration or secrets, including `--all`. Removing those
deserves its own explicit act.

## What the node will not do

- **Ask for a coldkey.** Not for mining, not for validating, not ever. Only a
  hotkey address. A coldkey, seed, or mnemonic is refused in every field.
- **Write to the chain.** `--broadcast` is refused, with or without `--yes`.
  Submitting weights needs a registered validator wallet with a permit and is an
  owner action taken against the engine directly, deliberately outside this
  node's reach.
- **Install anything from the legacy `cathedralai/cathedral` repository.**
- **Spend money, provision hardware, or register an identity.**

Anything in this list surfaces as `requires_operator: true` rather than as a
retryable failure, so an agent stops and escalates instead of looping.

## Before you spend money on Compute

An Intel TDX machine is only useful if its measurement is already on the signed
policy registry. A cryptographically perfect quote with an unlisted measurement
is refused every epoch, and no reproducible image is published yet, so you
cannot produce a matching measurement yourself.

Get the measurement approved before you provision or pay for anything.
`cathedral explain compute` says this too, in the place where it matters.

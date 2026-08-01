# Cathedral CLI

> **Early beta.** This repository is a review candidate. It is not deployed,
> does not activate rewards, and does not write weights on chain. The signed
> lifecycle foundation has local acceptance evidence. Independent review, the
> first-run setup wizard, and live CPU and Distill miner-to-validator proof are
> still required before launch.

One command to mine or validate on Cathedral SN39.

```bash
git clone https://github.com/cathedralai/cathedral-cli.git
cd cathedral-cli
./cathedral quickstart
```

No dependencies to install first. Run the node with Python 3.11-3.13. The
orchestrator uses only the standard library, so `./cathedral doctor` runs the
moment you have the files.

---

## What you can do here

| | |
|---|---|
| **Distill** | Find real vulnerabilities. Your model writes a proof-of-concept exploit for an already-patched bug; a validator verifies it by running it. |
| **Compute** | Sell confidential compute you can prove ran untampered, inside an Intel TDX confidential VM. |
| **Validator** | Verify what miners claim, compose one weight vector, and decide what goes on chain. |

Each is one pinned upstream engine. You do not need to know which repository any
of them lives in, and you never install more than the one you are using.

## Your first ten minutes

```bash
./cathedral quickstart            # pick a track — each says what it needs
./cathedral explain distill       # what it does, what it pays, what is not yet true
./cathedral doctor                # does this machine qualify?
./cathedral quickstart distill    # install, configure, and run a verified local test
```

The local test costs nothing, pays nothing, and touches no chain. On a clean
machine, Distill runs a verified local synthetic test.

```
── 4 · verified local test ──────────────────────────────────────────────
  … generate    four sealed challenges, one per difficulty level
  … verify      4/4 witnesses accepted
  ✓ level0      vulnerable build exit 1, patched build exit 0, decoy refused
  ✓ level1      vulnerable build exit 1, patched build exit 0, decoy refused
  ✓ level2      vulnerable build exit 1, patched build exit 0, decoy refused
  ✓ level3      vulnerable build exit 1, patched build exit 0, decoy refused

  ✓ verified    4 of 4 challenges solved and verified, score 15/15; every decoy refused
```

That is the real scoring predicate, run by the real engine. A decoy input is
included on purpose: if a random byte-string were ever accepted as a solve, the
test fails, because the differential would not be discriminating.

## Operating it with a coding agent

Most Cathedral miners are run by an agent, so the machine interface is the
primary one and the terminal view is a rendering of it.

```bash
./cathedral capabilities --json    # discovery: protocol, commands, exit codes
./cathedral agent-brief distill    # an instruction block to paste into an agent
```

Every command takes `--json`. Stdout carries exactly one versioned envelope;
diagnostics go to stderr. Exit codes are grouped so an unfamiliar failure is
still classifiable: `10-19` the environment is not ready, `20-29` the work ran
and failed, `30-39` the request was wrong, `40-49` the outside world.

Full contract: [docs/AGENT_CONTRACT.md](docs/AGENT_CONTRACT.md).

## Commands

```
quickstart      guided path from a clean machine to a verified local test
doctor          can this machine and identity do the work?
capabilities    what this node can do, and what needs an owner decision
explain         what a track does, what it needs, and what it pays

setup           install a pinned engine and write its configuration
config          read and write configuration (never holds a credential)
secret          store credentials safely; never printed

test            the verified local test — pays nothing, touches no chain
start / stop    begin and end mining or validating
status          what is running, and what recently happened
logs            stream meaningful state changes
resume / cancel continue or end an interrupted run
evidence        resolve any identifier this node emitted
cleanup         reclaim space; never removes config or secrets

update          move to new pinned engine revisions, safely
rollback        return to the previously installed revisions
agent-brief     print an instruction block for a coding agent
```

## Configuration and secrets

Two stores, deliberately separate.

`$CATHEDRAL_HOME/config/<role>.toml` holds everything safe to read aloud. A
field that needs a credential holds the **name** of a secret, not the secret, so
`cathedral config show` is safe to paste into an issue.

`$CATHEDRAL_HOME/secrets.env` is mode 0600 and is never printed, never passed as
an argument, and never committed. Values reach an engine only through its
environment.

```bash
printf '%s' "$MY_MODEL_KEY" | ./cathedral secret set DISTILL_API_KEY --stdin
./cathedral config set distill api_key_secret DISTILL_API_KEY
```

**Cathedral never asks for a coldkey.** Not for mining, not for validating, not
for any local test. Only a hotkey *address* is ever needed, and the node refuses
a coldkey, seed, or mnemonic in any field.

## What is honestly true today

The node reports capabilities from the live machine, so `cathedral capabilities`
is always more current than this file. As of the pinned revisions:

- **Distill** — the mechanism runs end to end and the local test is real.
  On-chain participation needs the operator key ceremony and the mechanism
  registered on chain. Per-solve Intel TDX binding is proven for the synthetic
  profile; an attested real-corpus solve is not proven. Emissions are not active.
- **Compute** — Intel TDX CPU evidence is proven on live hardware. Onboarding is
  operator-assisted, not self-service. Your measurement must be approved and
  signed into the policy registry *before you provision or pay for a machine*.
  AMD SEV-SNP and NVIDIA confidential-GPU scoring are not enabled.
- **Validator** — dry runs against the live signed feed work here.
  `cathedral-validator` is a derived copy of the validator extracted from
  `cathedralai/cathedral`; making it your production weight authority is a
  separate owner cutover decision. This node never enables chain writes.

A reachable endpoint, a valid quote, uptime, or a historical receipt never means
you are earning. Zero positive miners and a burn-only vector are valid,
fail-closed outcomes.

## Pinned engines

`cathedral.lock.json` pins the exact commit of each engine. A node installs those
commits and nothing else.

| Role | Upstream | Pinned |
|---|---|---|
| distill | `cathedralai/cathedral-distill` | `1488579842dc` |
| compute | `cathedralai/cathedral-compute` | `f3016a4521bb` |
| validator | `cathedralai/cathedral-validator` | `80dd56e4f431` |

`cathedralai/cathedral` is legacy. It is audited for required functionality but
never installed, and none of its publisher, validator, or mining paths are
exposed here.

Each engine gets its own virtual environment under
`$CATHEDRAL_HOME/engines/<role>/`. That is not tidiness: `cathedral-compute` and
`cathedral-validator` both publish a console script named `cathedral-validator`,
and `cathedral-compute`'s Python package is literally named `cathedral`.
Installed together, whichever landed last would silently win.

```bash
./cathedral update --check     # what a newer pin would change
./cathedral update --yes       # apply it; owner-controlled settings are preserved
./cathedral rollback --yes     # return to the previous revisions
```

An update refuses to run while a role is running, and verifies afterwards that
no owner-controlled setting moved: your wallet, your network, and — the ones
that matter most — the weight contract and signing key your validator will
accept.

**The burn share is not yours to set, and this node does not pretend otherwise.**
It comes from the signed weight vector under the pinned `validated_supply_v1`
contract, and the integration lane reads Cathedral-signed burn and allocation
documents. What you control is which contract and which signing key you accept.
`cathedral explain validator` says this in the place where it matters.

## Layout

```
cathedral                 the entry point; no dependencies
cathedral.lock.json       pinned engine revisions
cathedral_node/
  contracts/              the machine-facing contract: envelope, codes, versions
  engines/                one adapter per engine; translation, never reimplementation
  commands/               one module per command
  ui/                     the human rendering of the same envelope
tests/                    the contract, enforced
docs/                     the agent contract and the architecture
```

## Documentation

- [docs/AGENT_CONTRACT.md](docs/AGENT_CONTRACT.md) — the machine interface in full
- [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) — why it is built this way
- [docs/OPERATIONS.md](docs/OPERATIONS.md) — running, updating, recovering

## Tests

```bash
./scripts/dev-env.sh
./run-gate0.sh
```

Gate 1 and Gate 2 require a real signed release bundle and live engines. They
are separate from the local Gate 0 contract suite.

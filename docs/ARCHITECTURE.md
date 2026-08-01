# Architecture

Why the node is built this way, including the constraints that forced each
decision. Written so the next person changing it knows which parts are load
bearing.

## The shape

```
                      cathedral (one command)
                              │
              ┌───────────────┴───────────────┐
              │                               │
        contracts/                          ui/
   envelope · codes · versions      console · theme · render
              │                               │
              └───────────────┬───────────────┘
                        commands/
                     one module per verb
                              │
                        engines/
              distill · compute · validator
                    (adapters, not logic)
                              │
        ┌─────────────────────┼─────────────────────┐
        │                     │                     │
  cathedral-distill    cathedral-compute    cathedral-validator
   pinned, own venv     pinned, own venv     pinned, own venv
```

The engines are preserved exactly as their owners built them. Nothing here
reimplements verification, scoring, attestation, composition, or submission. An
adapter knows three things: which engine command to run, how to read what it
returns, and how to say that in the node's contract. When the node and an engine
would disagree about a fact, the engine wins.

## Decisions

### One envelope, two renderers

The agent contract is not a serialisation of the human output, and the human
output is not a pretty-printer bolted onto JSON. A command builds one `Envelope`
and returns it; `runner.execute` decides whether to `json.dump` it or hand it to
a renderer.

This is the only structural guarantee that the two can never drift. A field the
terminal shows must exist in the envelope, because the terminal reads the
envelope. A failure mode the JSON reports must render, because the same object
goes both ways.

### Isolated environments per engine, not tidiness

`cathedral-compute` publishes a top-level Python package named `cathedral` and a
console script named `cathedral-validator`. `cathedral-validator` publishes a
console script of that same name pointing at completely different code:

```
cathedral-compute   → cathedral.neuron.validator:main   (runtime epoch operator)
cathedral-validator → scaffold.cli:main                 (SN39 weight validator)
```

Installed into one environment, whichever landed last silently wins and an
operator gets the wrong program with no error. So each engine gets its own
virtualenv under `$CATHEDRAL_HOME/engines/<role>/venv`, and the node never
resolves an engine command through `PATH` — always an absolute path.

This also means installing Distill does not drag in `bittensor`, so its local
journey remains smaller than the validator installation.

### Zero dependencies in the orchestrator

The node uses only the Python standard library. Engine installation requires
Python 3.11-3.13. `git clone` and run with a supported interpreter.

The alternative — a package to install first — puts a dependency resolution
between an operator and the answer to "will this even work on my machine". That
is exactly backwards: `doctor` is the command most likely to be run on a machine
where something is wrong.

The engines have real dependencies. They get them, in their own environments.

### Verb first, role second

```
cathedral test distill
cathedral test compute
cathedral test validator
```

The first decision an operator makes is what they are doing; the role is the
object it acts on. For an agent it is a flat templatable surface where role is
one token.

Upstream names were not preserved. `cathedral-cybergym-agent --local`,
`cathedral worker serve`, and `cathedral-validator serve --dry-run --offline`
are three unrelated spellings of "try this safely". Keeping them would have
meant the operator learning three products.

### Pinned revisions in a lockfile

`cathedral.lock.json` names a full 40-character commit for each engine. Install
checks out exactly that commit, verifies `HEAD` matches, and refuses a checkout
with local modifications. The receipt that marks an install as real is written
last, so an interrupted install is simply "not installed" rather than a
half-state that looks fine.

`update` records the outgoing revision before changing anything, which is what
makes `rollback` reinstall a known commit rather than hoping a reinstall of "the
old version" resolves the same way.

### Owner settings are node state, not engine state

Burn fraction, burn destination, and lane allocation live in the node's config
and are projected onto the engine's TOML. An engine upgrade replaces engine
files; it cannot touch node config. `update` additionally snapshots those fields
before and after and warns if any moved — a defect alarm for something that
should be structurally impossible.

The projection is deliberately conservative: `_substitute` replaces only named
scalar keys inside named sections and passes everything else through
byte-identical, because the engine's config carries security-critical key pins
the node must not rewrite.

### Secrets travel through the environment only

`operate_argv()` builds a command line without ever reading a credential;
`operate_env()` supplies them separately. A secret therefore cannot reach `argv`,
which means it cannot appear in `ps` output for other users on the host. A test
asserts this per engine by putting a sentinel in every secret-shaped config
field and checking the resulting argv.

`redact.py` is a backstop for an engine that prints one anyway, applied before
anything reaches a log, the terminal, or an envelope.

### Local tests exercise the engine, not a fixture

The Distill local test runs the engine's own synthetic generator and its own
differential executor, inside the engine's own interpreter. It includes a decoy:
a random byte-string that must **not** be accepted. A test that only checks the
happy path would pass just as well against a verifier that accepted everything.

The Compute local test asks the engine's quote verifier four questions, three of
which must be refused: an unlisted measurement, a stale TCB, and an empty policy.
Proving the gate is closed is the point; proving a happy path exists is not.

The validator local test is one real offline tick against the live signed feed,
producing a real vector id and policy version.

### Honest capability reporting

A capability is `available: true` only when running it here would succeed.
Hardware probes return `unknown` rather than `no` when the question cannot be
answered on this platform — reporting "no TDX" from a macOS laptop would be a
lie an operator might act on.

Everything gated on an owner decision is marked `requires_operator` and
collected in one place, so neither a human nor an agent discovers those one
failure at a time.

## Repository ownership

| Repository | Role here |
|---|---|
| `cathedralai/cathedral-distill` | Installed. Owns Distill mining and verification. |
| `cathedralai/cathedral-compute` | Installed. Owns verified Compute mining and evidence. |
| `cathedralai/cathedral-validator` | Installed. Owns validation, composition, burn handling, guarded submission. |
| `cathedralai/cathedral` | **Never installed.** Legacy. Audited only. |

The node contains no product logic that belongs in an engine. If a behaviour
would be wrong for a direct user of `cathedral-distill`, it does not belong
here either — it belongs upstream.

Two honest boundaries the node states rather than papers over:

- `cathedral-validator` describes itself as a derived copy, not yet the
  authoritative validator source, and says not to deploy from it without an
  explicit cutover decision. The node installs it, supports local and dry-run
  use, and says exactly this wherever it matters.
- The validator's `--offline` removes chain access, not network access. The
  signed feed is still fetched over HTTPS, because verifying that feed is the
  thing being tested. The node says so rather than implying an air gap.

## Adding an engine

1. Add a pin to `cathedral.lock.json`.
2. Add an adapter subclassing `engines.base.Engine`. Implement `explain`,
   `capabilities`, `qualify`, `local_test`, `operate_argv`, `operate_env`, and
   optionally `interpret_line`.
3. Register it in `engines/__init__.py` and add the role to `lockfile.ROLES`.
4. Add its configuration fields to `config.SCHEMAS`.

The contract tests then apply to it automatically: `explain` must carry every
required key, `capabilities` must be shaped consistently, and `operate_argv`
must not leak a secret.

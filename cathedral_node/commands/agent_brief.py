"""`cathedral agent-brief` — the instruction block you hand to a coding agent.

Most Cathedral miners will be operated by an agent. This command produces the
text that makes that safe: what the agent may do unattended, what it must never
do, the exact commands, the exit codes it should branch on, and the boundaries
it must escalate rather than work around.

It is generated from the live node, not written by hand, so it can never
describe a capability this machine does not have.
"""

from __future__ import annotations

from typing import Any

from cathedral_node import config, engines, lockfile, machine, paths
from cathedral_node.contracts import Envelope
from cathedral_node.contracts.codes import Exit
from cathedral_node.contracts.version import PROTOCOL_VERSION, RESULT_SCHEMA, schema_id
from cathedral_node.engines import installer
from cathedral_node.runner import Context, command
from cathedral_node.ui.console import Console
from cathedral_node.ui.render import renders


@command("agent-brief")
def agent_brief(ctx: Context) -> Envelope:
    lock = lockfile.load()
    role = getattr(ctx.args, "role", None)
    roles = [role] if role else list(lockfile.ROLES)

    # `qualify()` and `capabilities()` execute installed code; hold the lease.
    with installer.active_view(lock) as (states, group, _detail):
        return _brief(ctx, lock, roles, states, group)


def _brief(ctx: Context, lock, roles, states, group) -> Envelope:
    facts: dict[str, Any] = {}
    for name in roles:
        engine = engines.load(name, lock, group)
        installed = states[name]
        cfg = config.load(name)
        qualification = engine.qualify(cfg)
        facts[name] = {
            "title": engine.title,
            "installed": installed.installed and not installed.drift,
            "revision": installed.revision,
            "can_local_test": qualification.can_local_test,
            "can_operate": qualification.can_operate,
            "blockers": qualification.blockers,
            "owner_gated": [
                {"capability": k, "detail": v.get("detail", "")}
                for k, v in engine.capabilities().items()
                if isinstance(v, dict) and v.get("requires_operator")
            ],
        }

    text = _markdown(facts, roles)
    data = {
        "protocol_version": PROTOCOL_VERSION,
        "roles": facts,
        "brief": text,
        "format": getattr(ctx.args, "format", "markdown"),
        "home": str(paths.home()),
    }
    env = Envelope.ok("agent-brief", data)
    env.data_schema = schema_id("agent_brief")
    return env


def _markdown(facts: dict[str, Any], roles: list[str]) -> str:
    exit_lines = "\n".join(
        f"| `{int(member)}` | `{member.name}` | {(member.__doc__ or '').strip()} |" for member in Exit
    )
    role_sections = "\n\n".join(_role_section(name, facts[name]) for name in roles)
    scope = ", ".join(facts[name]["title"] for name in roles)
    home = paths.home()

    blocked = [
        f"- **{facts[name]['title']}** — {item['capability'].replace('_', ' ')}: {item['detail']}"
        for name in roles
        for item in facts[name]["owner_gated"]
    ]
    blocked_block = "\n".join(blocked) if blocked else "- Nothing additional."

    return f"""\
# Operating a Cathedral node

You are operating a Cathedral node ({scope}) through the `cathedral` CLI.
Machine: {machine.summary()['system']} {machine.summary()['machine']}, python {machine.summary()['python']}.
Node home: `{home}`.

## Contract

- Protocol `{PROTOCOL_VERSION}`. Re-run `cathedral capabilities --json` after any update and
  stop if the MAJOR version has changed.
- Add `--json` to every command. Stdout is one `{RESULT_SCHEMA}` envelope; stderr is
  diagnostics. Never parse stderr.
- Branch on the exit code, not on message text. Codes are stable within a MAJOR version.
- `error.remediation.command`, when present, is runnable verbatim.
- `error.remediation.requires_operator: true` means **no command fixes this**. Stop and
  report it. Do not retry, and do not look for a way around it.
- Every command is safe to re-run. `setup`, `config set`, `secret set`, `stop`, and
  `cleanup` are idempotent.
- Add `--yes` where a confirmation is required. A required confirmation is never hidden
  inside an interactive prompt — you will always get exit `{int(Exit.USAGE)}` with the flag named.

## Exit codes

| Code | Name | Meaning |
|---|---|---|
{exit_lines}

Retry on `{int(Exit.NETWORK)}`, `{int(Exit.TIMEOUT)}`, `{int(Exit.LOCKED)}`, and `{int(Exit.UPSTREAM)}` with backoff. Never retry
`{int(Exit.UNSUPPORTED)}` or anything whose remediation requires an operator.

## Order of operations

```bash
cathedral capabilities --json          # discovery; confirm the protocol MAJOR
cathedral doctor --json                # qualification; read .data.roles.<role>.can_local_test
cathedral setup <role> --json          # idempotent install of the pinned engine
cathedral test <role> --json           # verified local test; pays nothing, no chain access
cathedral status --json                # what is running and what happened
```

{role_sections}

## Secrets

- Never pass a credential as an argument. The only accepted source is stdin:
  `printf '%s' "$KEY" | cathedral secret set NAME --stdin`
- Configuration stores the **name** of a secret, never its value. `cathedral config show`
  is always safe to include in a report.
- Never write a credential into the repository or into a run directory.

## Boundaries you must not cross

- **Never provide a coldkey, seed, or mnemonic.** The node refuses them; do not try to work
  around that refusal. Only a hotkey *address* is ever needed.
- Never enable chain writes. `--broadcast` is refused by this node by design.
- Never spend money, provision hardware, or register an identity without the operator saying so.
{blocked_block}

## Reporting

Report the envelope's `run_id`, `status`, `exit_code`, and any identifiers under
`data.identifiers` — they are the exact challenge, receipt, vector, and submission ids the
operator needs. Include `error.code` verbatim when something failed.
"""


def _role_section(role: str, facts: dict[str, Any]) -> str:
    lines = [f"### {facts['title']} (`{role}`)", ""]
    if facts["installed"]:
        lines.append(f"- Engine installed at `{(facts['revision'] or '')[:12]}`.")
    else:
        lines.append(f"- Engine not installed. Run `cathedral setup {role} --json` first.")
    lines.append(
        f"- Local test: {'available' if facts['can_local_test'] else 'blocked'} — `cathedral test {role} --json`"
    )
    lines.append(
        f"- Live operation: {'available' if facts['can_operate'] else 'blocked'} — `cathedral start {role} --json`"
    )
    if facts["blockers"]:
        lines.append("- Blockers:")
        for blocker in facts["blockers"]:
            fix = blocker.get("fix")
            suffix = f" Fix: `{fix}`" if fix else " No command fixes this; escalate."
            lines.append(f"  - {blocker.get('what', '')}.{suffix}")
    return "\n".join(lines)


@renders("agent-brief")
def _render(console: Console, data: dict[str, Any], env: Envelope) -> None:
    # The brief is the product here, so print it verbatim rather than styling it:
    # an operator copies these exact characters into an agent.
    console.blank()
    for line in data["brief"].splitlines():
        console.write(line)

"""`cathedral explain <role>` — what the track is, in plain language.

Deliberately separate from ``capabilities``. ``capabilities`` answers "what can
this machine do"; ``explain`` answers "should I do this at all". A first-time
operator reads this before installing anything.
"""

from __future__ import annotations

from typing import Any

from cathedral_node import engines, lockfile
from cathedral_node.contracts import Envelope
from cathedral_node.contracts.version import schema_id
from cathedral_node.runner import Context, command
from cathedral_node.ui.console import Console
from cathedral_node.ui.render import renders


@command("explain")
def explain(ctx: Context) -> Envelope:
    lock = lockfile.load()
    engine = engines.load(ctx.args.role, lock)
    data = dict(engine.explain())
    data["pinned_revision"] = lock.pin(ctx.args.role).short_revision
    env = Envelope.ok("explain", data)
    env.data_schema = schema_id("explain")
    env.then(f"Check whether this machine qualifies", f"cathedral doctor {ctx.args.role}")
    env.then(f"Install and test it", f"cathedral setup {ctx.args.role} && cathedral test {ctx.args.role}")
    return env


@renders("explain")
def _render(console: Console, data: dict[str, Any], env: Envelope) -> None:
    console.title(data["title"], data["tagline"])
    console.blank()
    console.para(data["what_you_do"], indent=4)

    # Everything past Engine.EXPLAIN_REQUIRED is optional BY DEFINITION, so it is
    # read with .get like every other optional section. Indexing this one directly
    # is what silently dropped `explain validator` into the degraded renderer: a
    # validator is not scored, it scores, so it supplies `who_sets_the_burn` and no
    # `how_you_are_scored`. The KeyError was caught upstream and the fallback still
    # printed something, so nothing looked broken.
    if data.get("how_you_are_scored"):
        console.blank()
        console.rule("how you are scored")
        console.para(data["how_you_are_scored"], indent=4)

    if data.get("who_sets_the_burn"):
        console.blank()
        console.rule("who sets the burn")
        console.para(data["who_sets_the_burn"], indent=4)

    if data.get("what_you_verify"):
        console.blank()
        console.rule("what you verify")
        console.bullets(data["what_you_verify"])

    if data.get("what_it_never_does"):
        console.blank()
        console.rule("what it never does")
        console.bullets(data["what_it_never_does"])

    console.blank()
    console.rule("what you need")
    console.bullets(data.get("what_you_need", []))

    if data.get("what_it_costs"):
        console.blank()
        console.rule("what it costs")
        console.para(data["what_it_costs"], indent=4)

    if data.get("before_you_spend"):
        console.blank()
        console.rule("before you spend money")
        console.para(data["before_you_spend"], indent=4)

    console.blank()
    console.rule("not yet true")
    console.bullets(data.get("not_yet_true", []))

    if data.get("who_sets_the_burn"):
        console.blank()
        console.rule("who sets the burn")
        console.para(data["who_sets_the_burn"], indent=4)

    if data.get("safety"):
        console.blank()
        console.rule("scope and safety")
        console.para(data["safety"], indent=4)

"""Command implementations.

Importing this package registers every command and its renderer. Order does not
matter; registration is by decorator.
"""

from cathedral_node.commands import (  # noqa: F401
    agent_brief,
    capabilities,
    cleanup,
    config_cmd,
    doctor,
    evidence,
    explain,
    logs,
    quickstart,
    recover,
    run,
    secret_cmd,
    setup,
    status,
    test,
    update,
)

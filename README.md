<div align="center">
  <h1>⛪ Cathedral CLI</h1>
  <p><strong>Two ways to mine. One way to validate. One command surface.</strong></p>
  <a href="https://www.youtube.com/watch?v=KQRz6r9HJAs">
    <img src="https://i.ytimg.com/vi/KQRz6r9HJAs/maxresdefault.jpg" width="800" alt="Watch the Cathedral Subnet Overview">
  </a>
  <p><a href="https://www.youtube.com/watch?v=KQRz6r9HJAs">Watch the Cathedral Subnet Overview</a></p>
  <p><code>EARLY BETA</code> · review candidate · no rewards or chain writes</p>
</div>

Cathedral CLI gives miners and validators one interface over the pinned Compute, Distill, and Validator engines. It keeps each engine isolated while sharing setup, configuration, logs, evidence, updates, and recovery.

## Start here

Requires Python 3.11-3.13.

```bash
git clone https://github.com/cathedralai/cathedral-cli.git
cd cathedral-cli
python3.11 ./cathedral quickstart
```

The first command shows every role and what it needs before installing anything. A signed Cathedral release and a trusted signer file are still required to install an engine.

## Choose a role

### Compute miner

Offer Intel TDX CPU work with measured evidence and result-bound receipts.

```bash
python3.11 ./cathedral explain compute
python3.11 ./cathedral doctor compute
python3.11 ./cathedral quickstart compute
```

Onboarding remains operator-assisted. Registration or uptime never guarantees positive weight.

### Distill miner

Find proof-of-concept exploits for already-fixed vulnerabilities. The validator reruns the vulnerable and patched builds before accepting a result.

```bash
python3.11 ./cathedral explain distill
python3.11 ./cathedral doctor distill
python3.11 ./cathedral quickstart distill
```

The local synthetic scoring test is implemented. Real-corpus attestation and live emissions are not yet proven.

### Validator

Verify admitted evidence, compose one weight vector, and fail closed when a claim cannot be proven.

```bash
python3.11 ./cathedral explain validator
python3.11 ./cathedral doctor validator
python3.11 ./cathedral quickstart validator
```

The early beta supports local and dry-run validation. Production authority and chain broadcasts remain disabled.

## Run it with an agent

```bash
python3.11 ./cathedral capabilities --json
python3.11 ./cathedral agent-brief <compute|distill|validator>
```

Every command supports JSON output. Secrets enter through stdin, never command arguments, logs, URLs, or committed configuration.

## Current state

| | Status |
|---|---|
| Unified command and JSON contract | Early-beta implementation |
| Signed install, update, recovery, and rollback foundation | Local implementation |
| Full Gate 0 result for this commit | Not yet proven |
| Live CPU and Distill miner-to-validator loops | Not yet proven |
| Production release, deployment, rewards, and chain writes | Not enabled |

## Reference

- [Agent contract](docs/AGENT_CONTRACT.md)
- [Architecture](docs/ARCHITECTURE.md)
- [Operations](docs/OPERATIONS.md)
- [Launch specification](docs/gate0-spec/CATHEDRAL-CLI-LAUNCH-PRD-TECH-SPEC-20260731.md)

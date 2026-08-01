<div align="center">
  <h1>⛪ Cathedral CLI</h1>
  <p><strong>Two ways to mine. One way to validate.</strong></p>
  <video controls width="800" src="https://github.com/user-attachments/assets/930814df-e648-40f2-8d1a-6adcaae3f3f4"></video>
  <p><a href="https://www.youtube.com/watch?v=KQRz6r9HJAs">Watch on YouTube</a> · <code>EARLY BETA</code></p>
</div>

One interface for Cathedral miners and validators.

## Pick a role

| Role | What it does |
|---|---|
| Compute miner | Runs Intel TDX CPU work and returns measured evidence with receipts. |
| Distill miner | Finds exploit proofs for fixed vulnerabilities. Validators rerun both builds before scoring. |
| Validator | Verifies evidence and composes weights. Chain broadcasts stay off by default. |

## Quickstart

Requires Python 3.11-3.13.

```bash
git clone https://github.com/cathedralai/cathedral-cli.git
cd cathedral-cli
python3.11 ./cathedral quickstart
```

## Let the CLI guide you

```bash
# Human guidance
python3.11 ./cathedral explain compute
python3.11 ./cathedral doctor compute

# Agent guidance
python3.11 ./cathedral agent-brief compute
python3.11 ./cathedral capabilities --json
```

Replace `compute` with `distill` or `validator`.

Engine installation requires a signed Cathedral release. Rewards and chain writes stay off by default in early beta.

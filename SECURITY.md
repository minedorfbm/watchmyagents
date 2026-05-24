# Security Policy

## How Watch My Agents handles your secrets

WMA is designed so that **your data and credentials stay on your machine**. This document describes how, and where the trust boundaries lie.

### Your Anthropic API key

WMA needs your Anthropic API key to call the Managed Agents REST API on your behalf.

| Property | Behavior |
|---|---|
| **Source** | Environment variable `ANTHROPIC_API_KEY` or `--api-key` CLI flag |
| **Storage** | Held in process memory for the duration of a `wma-fetch` run. Never persisted to disk by WMA. |
| **Network** | Sent only to `api.anthropic.com` over HTTPS with strict certificate verification (`rejectUnauthorized: true`) |
| **Logging** | The key is never written to NDJSON logs, never printed in error messages, never included in any export |
| **Telemetry** | WMA performs zero telemetry today. No phone-home, no usage reporting. |

**Recommendation:** generate a workspace-scoped API key with read-only permissions on the agents you want to monitor. See [Anthropic Console → API Keys](https://console.anthropic.com/settings/keys).

### Local log files

`wma-fetch` writes NDJSON files to `./watchmyagents-logs/<agent_id>/<date>.ndjson` with the following protections:

- Directory mode: `0700` (only your user can read/list)
- File mode: `0600` (only your user can read/write)
- No encryption at rest by default — files are plaintext JSON Lines on disk

**Add `watchmyagents-logs/` to your `.gitignore`** to avoid committing prompts and tool outputs to a repo.

### What WMA does NOT do

- ❌ Does not phone home, telemetry, analytics, or usage reporting
- ❌ Does not send any data to WMA-controlled servers
- ❌ Does not store, log, or transmit your Anthropic API key anywhere except `api.anthropic.com`
- ❌ Does not require an account, signup, or license key

## Threat model

WMA is built to give visibility into your AI agent's behavior. It is **observational**, not preventive.

### What WMA defends against

- **Blind spots in agent behavior.** Tool calls, prompts, state transitions, errors are all captured for after-the-fact analysis.
- **Token-only observability tools.** WMA captures every action including zero-token ones (`tool_use`, `state_transition`, etc.) that are the most security-relevant.
- **Vendor lock-in.** NDJSON is portable; you own the data.

### What WMA does NOT defend against

- **Real-time attack prevention.** WMA observes after events occur. For inline policy gating, see the upcoming Shield product.
- **A compromised host.** If an attacker has read access to your user account, they can read the log files. Consider encryption at rest (filesystem-level, or future opt-in via `age`) for sensitive environments.
- **Tampering with local logs.** Files are append-only by convention, not enforced. A future release will add a per-line hash chain for tamper-evident audit.
- **A compromised Anthropic API.** WMA trusts the events delivered by Anthropic. This is out of scope.

## Supply chain

- All code is open source on [GitHub](https://github.com/minedorfbm/watchmyagents)
- Zero runtime dependencies (uses Node.js 18+ built-ins only)
- One dev dependency (`@anthropic-ai/sdk`) for the optional adapter examples
- Future releases will use `npm publish --provenance` for SLSA build attestation

## Reporting a vulnerability

If you discover a security issue, **please do NOT open a public GitHub issue.**

Email: [minedor@watchmyagents.com](mailto:minedor@watchmyagents.com)

Include:
- A description of the issue and its impact
- Steps to reproduce
- The version of WMA affected (`npm list -g watchmyagents`)
- Your suggested fix, if any

We aim to acknowledge reports within 72 hours and provide an initial assessment within 7 days. Coordinated disclosure preferred.

## Updates

This policy may be updated as the product evolves (notably when Shield, encrypted exports, and anonymized telemetry ship). Watch the repository for changes.

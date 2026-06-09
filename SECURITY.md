# Security Policy

## How Watch My Agents handles your secrets

WMA is designed so that **your data and credentials stay on your machine**. This document describes how, and where the trust boundaries lie.

### Your Anthropic API key

WMA needs your Anthropic API key to call the Managed Agents REST API on your behalf.

| Property | Behavior |
|---|---|
| **Source** | Environment variable `ANTHROPIC_API_KEY` or `--api-key` CLI flag |
| **Storage (CLI mode)** | Held in process memory for the duration of a `wma-fetch` run. Not persisted to disk. |
| **Storage (service mode)** | Persisted to `~/.watchmyagents/env` with mode `0600` (user-only read/write) so the launchd / systemd unit can restart the daemon without prompting. See [Service-mode credentials](#service-mode-credentials) below for the exact layout. |
| **Network** | Sent only to `api.anthropic.com` over HTTPS with strict certificate verification (`rejectUnauthorized: true`) |
| **Logging** | The key is never written to NDJSON logs, never printed in error messages, never included in any export |
| **Telemetry** | WMA performs zero telemetry today. No phone-home, no usage reporting. |

**Recommendation:** generate a workspace-scoped API key with read-only permissions on the agents you want to monitor. See [Anthropic Console → API Keys](https://console.anthropic.com/settings/keys).

#### Service-mode credentials

When you run `wma-service install`, WMA registers a launchd (macOS) or systemd (Linux) unit that needs to restart the watch daemon across reboots without human intervention. The daemon's environment is therefore loaded from a small file owned by your user account:

| Path | Mode | Owner | Contents |
|---|---|---|---|
| `~/.watchmyagents/` | `0700` | your user | Holds the env file and the launcher shell script |
| `~/.watchmyagents/env` | `0600` | your user | `KEY=value` lines for `ANTHROPIC_API_KEY`, `WMA_API_KEY`, `WMA_SIGNALS_SALT`, `WMA_FORTRESS_BASE_URL` |
| `~/.watchmyagents/<label>.launcher.sh` | `0600` | your user | Reads the env file with a literal `read -r` loop (no shell interpolation), then `exec`s `wma-fetch`. |

Hardening notes:
- The launcher loads secrets with `while IFS='=' read -r k v` instead of `. file` / `source file`. Sourcing would shell-evaluate every value, so a value containing `$(cmd)` would execute at every restart. The literal read assigns the bytes verbatim.
- Values are validated before write: a newline anywhere in a credential aborts the install (would corrupt the env file or inject extra lines).
- To wipe the credential without uninstalling the service: `chmod 600 ~/.watchmyagents/env && : > ~/.watchmyagents/env` (the daemon will exit on the next missing-env check).
- Full removal: `wma-service uninstall` deletes the unit, the launcher, the env file, and the `~/.watchmyagents` directory.

### Local log files

`wma-fetch` writes NDJSON files to `./watchmyagents-logs/<agent_id>/<date>.ndjson` with the following protections:

- Directory mode: `0700` (only your user can read/list)
- File mode: `0600` (only your user can read/write)
- No encryption at rest by default — files are plaintext JSON Lines on disk

**Add `watchmyagents-logs/` to your `.gitignore`** to avoid committing prompts and tool outputs to a repo.

### What WMA does NOT do

- ❌ No phone-home, no usage analytics, no silent telemetry — WMA never opens a network connection to a WMA-controlled endpoint on its own.
- ❌ Does not store, log, or transmit your Anthropic API key anywhere except `api.anthropic.com`.
- ❌ Does not require an account, signup, or license key.

### Fortress upload — strictly opt-in

Since v0.5.0, WMA supports an **opt-in** cloud component (WMA Fortress) for teams who want a multi-agent dashboard + cross-fleet Guardian analysis. The upload only happens when you explicitly invoke `--upload` on `wma-fetch`, run `wma-upload-fortress`, or run `wma-shield --policies-source fortress`. The defaults across all CLIs are zero-cloud — your machine stays the only place raw data ever exists.

What goes to Fortress when you opt in:
- ✅ The **anonymized signals payload** (counts, latencies, salted IoC hashes, sequences, classification metadata) — see [`docs/CONTAINMENT.md`](docs/CONTAINMENT.md) for the bit-exact contract and the 6 invariant tests that lock it down.
- ✅ Routing identifiers (`provider`, `native_agent_id`, optionally the human `display_name` — see `--no-send-agent-names` to opt this out).

What does **NOT** go to Fortress, ever:
- ❌ Raw prompts, agent outputs, tool inputs, tool outputs, error message text, raw URLs, raw commands, raw queries — these stay in your local `watchmyagents-logs/`.
- ❌ Your Anthropic API key. Fortress authenticates with a separate `WMA_API_KEY` issued from your Fortress account and never sees `ANTHROPIC_API_KEY`.

## Threat model

WMA combines **two complementary layers**:
- **Watch** (`wma-fetch`, `wma-inspect`) — observational. Captures every agent action into local NDJSON for after-the-fact audit.
- **Shield** (`wma-shield`, shipped in v0.2.0) — preventive. Streams agent events in real time and enforces policies via `user.tool_confirmation` (block before execution when the agent has `permission_policy: always_ask`) or `user.interrupt` (terminate after a violating tool ran, when always_ask is not configured).

### What WMA defends against

- **Blind spots in agent behavior.** Watch captures tool calls, prompts, state transitions, and errors for after-the-fact analysis.
- **Token-only observability tools.** WMA captures every action including zero-token ones (`tool_use`, `state_transition`, etc.) that are the most security-relevant.
- **Inline policy violations** (Shield). When the agent has `permission_policy: always_ask` configured, Shield blocks tool calls before execution. When not, Shield interrupts the session on first violation (the offending tool already ran, but the agent loop stops).
- **Stale enforcement after a policy update.** A new policy accepted in the Fortress dashboard is active in Shield within ~1 second via SSE + Postgres realtime (validated in production on v1.1.0). The 60s polling refresh is a fallback for environments where the SSE channel can't be established (firewall, proxy stripping `text/event-stream`).
- **Lost audit trail for blocked / denied / interrupted tool calls.** Tool calls that started but never produced a result (Shield pre-block, operator denial, mid-execution kill, session termination) are logged as explicit `tool_use` entries with `status: error` and `error: "no_result_observed"` — they cannot disappear silently from the audit. (Fix shipped in v1.1.1 after the Codex P1 finding.)
- **Vendor lock-in.** NDJSON is portable; you own the data.

### What WMA does NOT defend against

- **A compromised host.** If an attacker has read access to your user account, they can read the log files. Consider encryption at rest (filesystem-level, or future opt-in via `age`) for sensitive environments.
- **Tampering with local logs (full coverage).** As of v1.2.0, `shield_decision` rows carry a SHA-256 hash chain (`prev_hash` + `chain_hash`) — `verifyDecisionChain()` detects in-place modification, mid-chain deletion, and insertion. This is **local tamper-evidence**, not tamper-proof: (a) tail truncation (removing the most recent rows) is invisible to an append-only chain, and (b) an attacker with the Shield binary can mint a fresh chain from scratch by re-executing. Both gaps are closed by Fortress-side append-only ingest (planned). Watch's non-decision rows (tool_use, etc.) remain append-only-by-convention and are NOT chained.
- **Shield being killed.** Shield is an external process. If killed, the agent runs without enforcement until Shield restarts. Run under a process supervisor (systemd, pm2, docker `restart: always`) in production.
- **Pre-installation activity.** Shield only enforces from the moment it attaches forward. Past events are not retroactively replayed or re-evaluated.
- **A malicious policy file.** Shield's policy engine refuses obviously unsafe regex patterns (e.g. catastrophic backtracking) and truncates inputs before regex tests to mitigate ReDoS. But a user-controlled policy file remains a code-adjacent input — treat it as you would treat sourcecode.
- **A compromised Anthropic API.** WMA trusts the events delivered by Anthropic. This is out of scope.

## Supply chain

- All code is open source on [GitHub](https://github.com/minedorfbm/watchmyagents)
- Zero runtime AND dev dependencies (uses Node.js 18+ built-ins only). Run `npm ls --omit=dev` or check `package.json#dependencies` / `devDependencies` — both are empty.
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

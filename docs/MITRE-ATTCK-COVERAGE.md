# MITRE ATT&CK + ATLAS coverage — WMA v1.2.0

**Status: live as of v1.2.0 (June 2026)**
**Scope: WMA SDK (Watch + Shield). Guardian/Fortress complements are tracked separately.**

This document maps MITRE ATT&CK Enterprise tactics + MITRE ATLAS techniques (the AI-specific extension) to the WMA SDK's detection and enforcement capabilities. It is intended for security buyers evaluating WMA against their existing detection stack, and for engineers extending the policy library.

Coverage is graded as:

| Grade | Meaning |
|-------|---------|
| **Enforce** | WMA can BLOCK the technique pre-execution via a Shield policy. Real-time, in-band. |
| **Detect** | WMA observes and logs the technique via Watch but does not enforce. Surfaces in `wma-inspect` + Fortress. |
| **Partial** | Coverage exists but is heuristic, depends on payload shape, or requires a customer-authored policy. |
| **Gap** | Out of scope for v1.2.0. Tracked as roadmap. |

---

## What WMA is and isn't

WMA is a **runtime control plane** for autonomous AI agents. It sees every tool call, every model response, and every API event from a managed-agent platform (Anthropic Agent SDK today, AgentCore + OpenAI + LangGraph next). It does NOT:

- Inspect the LLM's reasoning chain or system prompt for prompt-injection content. That belongs upstream (input filtering, jailbreak detection). WMA reacts to BEHAVIOR, not intent.
- Replace endpoint EDR or network controls. The agent runs on a customer-owned machine; WMA sees the agent's actions, not OS-level syscalls.
- Audit pre-installation activity. Shield is forward-looking only — see [[feedback_shield_post_install_only]].

What WMA does cover is the agent layer: parameter validation, behavioral throttling, exfil prevention, **local** audit-chain tamper-evidence (see §T1070 for the precise scope — Shield's NDJSON is hash-chained per process; truncation and binary-replay are out-of-scope for the local chain), and a continuous Watch→Guardian→Shield loop.

---

## ATT&CK Enterprise coverage

### TA0001 — Initial Access (not applicable to agent runtime)

WMA does not see the path by which a malicious instruction reaches the agent. If a prompt injection lands via a customer-facing form, that's an upstream concern. Once the agent ACTS on it, WMA sees the action and can block it.

### TA0002 — Execution

| Technique | WMA capability | Grade |
|---|---|---|
| **T1059 Command and Scripting Interpreter** (bash, python via tool) | Shield policy: `tool_name === 'bash'` + parameter regex / allowlist. Now extensible via v1.2.0 DSL (`length_gt`, `in_range` on arguments). | **Enforce** |
| **T1059.004 Unix Shell** | Same as above with `input.command` field-path matching. | **Enforce** |
| **T1106 Native API** (agent calling OS APIs via custom tool) | Custom-tool fingerprint via `buildFortressDecisionPayload` (anonymizer allowlist). Custom tools without a salted hash are dropped from upload but still evaluated locally. | **Detect** |
| **T1204 User Execution** | Agent acting on behalf of user is the design — out of scope. | Gap (intentional) |

### TA0003 — Persistence

| Technique | WMA capability | Grade |
|---|---|---|
| **T1053 Scheduled Task/Job** (cron, launchd via tool) | Shield policy on `tool_name in [bash, file_write]` + `input.path` regex against `crontab`, `/etc/cron.d`, `~/Library/LaunchAgents`. | **Partial** (customer-authored) |
| **T1136 Create Account** (agent provisioning credentials) | Detect via `tool_name in [http_post, web_fetch]` + URL regex on identity providers. | **Partial** |
| **T1547 Boot or Logon Autostart** | Same as T1053 — file-write path detection. | **Partial** |

### TA0004 — Privilege Escalation

| Technique | WMA capability | Grade |
|---|---|---|
| **T1548 Abuse Elevation Control** (sudo, polkit) | Bash policy: regex on `input.command` for `sudo`/`pkexec`. | **Enforce** |
| **T1078 Valid Accounts** (agent using stolen creds) | Out of scope — credential storage is upstream. | Gap |

### TA0005 — Defense Evasion

| Technique | WMA capability | Grade |
|---|---|---|
| **T1070 Indicator Removal** (agent deleting its own logs) | **Local tamper-evidence only.** v1.2.0 audit chain (prev_hash + chain_hash on shield_decision NDJSON, SHA-256, per Shield process). `verifyDecisionChain()` detects in-place modification, mid-chain deletion, and insertion at the exact index. Out of scope locally: (a) tail truncation — append-only chains can't detect removal of the most recent rows from the end; (b) binary-replay — an attacker who can re-execute the Shield binary can mint a fresh chain from scratch. Both gaps are closed by Fortress-side append-only ingest (planned). Until then, this is "tamper-evident", not "tamper-proof". | **Detect (local only)** |
| **T1562 Impair Defenses** (agent disabling WMA) | Service supervision via launchd/systemd respawn. Watch records `wma-shield` lifecycle events to its NDJSON. | **Detect** |
| **T1027 Obfuscated Files** (base64-encoded payloads) | Watch captures full tool_input locally (Containment). Shield policy can match `length_gt` on suspicious fields. Doesn't decode base64 — heuristic only. | **Partial** |

### TA0006 — Credential Access

| Technique | WMA capability | Grade |
|---|---|---|
| **T1555 Credentials from Password Stores** | Bash + file_read policy: deny path-regex on `Keychain`, `.aws/credentials`, `secrets.json`. | **Enforce** (customer policy) |
| **T1552 Unsecured Credentials** (agent grepping for tokens) | Same shape — file_read denial. | **Enforce** (customer policy) |

### TA0007 — Discovery

| Technique | WMA capability | Grade |
|---|---|---|
| **T1083 File and Directory Discovery** | Watch logs every bash + file_list call. Detect-only — discovery is a noisy signal in benign agents. | **Detect** |
| **T1057 Process Discovery** | Same — bash `ps`/`lsof` invocations logged. | **Detect** |
| **T1018 Remote System Discovery** | Watch logs network reconnaissance via tool calls. | **Detect** |

### TA0008 — Lateral Movement (out of scope at single-agent layer)

Lateral movement across agent fleets is a Guardian/Fortress concern (fractal loop at Fleet level — see [[project_recursive_fractal_loop]]).

### TA0009 — Collection

| Technique | WMA capability | Grade |
|---|---|---|
| **T1119 Automated Collection** (agent grepping data) | v1.2.0 context tracker: `ctx.recent_error_rate > 0.5` + `ctx.event_count_recent` for flailing-agent detection. Combined with tool_name in [file_read, bash] for behavioral throttle. | **Enforce** |
| **T1005 Data from Local System** | File-read policy with path regex. | **Enforce** (customer policy) |

### TA0010 — Exfiltration

This is the headline use case. v1.2.0's DSL extensions were built specifically for this tactic.

| Technique | WMA capability | Grade |
|---|---|---|
| **T1567 Exfiltration Over Web Service** | Shield policy: `tool_name in [web_fetch, http_post]` + `input.bytes > 1_000_000` (v1.2.0 `gt`) + `input.method === 'POST'`. See realistic test case in `test/policy-dsl-extensions.test.js`. | **Enforce** |
| **T1041 Exfiltration Over C2 Channel** | URL allowlist via `not_regex` + host allow-list. | **Enforce** |
| **T1048 Exfiltration Over Alternative Protocol** | Custom tool fingerprint required; otherwise detected via Watch only. | **Partial** |
| **T1020 Automated Exfiltration** (loop) | Context tracker: `ctx.recent_error_rate` + `ctx.event_count_recent` to spot repeated exfil-shaped calls. | **Enforce** |

### TA0011 — Command and Control

| Technique | WMA capability | Grade |
|---|---|---|
| **T1071 Application Layer Protocol** (HTTPS C2) | Same as T1567 — URL allowlist. After-hours context narrows the window: `ctx.hour_of_day_utc in_range [22,23]`. | **Enforce** |
| **T1568 Dynamic Resolution** | URL regex against DGA shapes. | **Partial** |

### TA0040 — Impact

| Technique | WMA capability | Grade |
|---|---|---|
| **T1485 Data Destruction** (agent `rm -rf`) | Bash policy: regex on `rm -rf` + path. | **Enforce** (customer policy) |
| **T1486 Data Encrypted for Impact** (ransomware via agent) | Tool sequence detection requires Guardian — Shield does single-event policies. | **Gap** (planned for v1.3) |

---

## MITRE ATLAS coverage (AI-specific)

ATLAS is the AI-extension to ATT&CK. The most relevant subset for an agent runtime:

| ATLAS technique | WMA capability | Grade |
|---|---|---|
| **AML.T0051 LLM Prompt Injection** | Behavioral, not content-based: WMA does NOT inspect the prompt itself. Detected indirectly via the agent's resulting tool calls — if the injection induces an exfil attempt, the exfil policy fires. Custom-tool fingerprints + context tracker help spot anomalies. | **Partial** |
| **AML.T0044 Insecure ML Supply Chain** | Out of scope — upstream concern. | Gap |
| **AML.T0024 Exfiltration via ML Inference API** | Same as ATT&CK T1567 — agent calling out via tool. | **Enforce** |
| **AML.T0040 ML Model Inference API Access** (agent invoking another model) | Tool-name allowlist via `not_in`. | **Enforce** |
| **AML.T0053 LLM Jailbreak** | Same as prompt injection — behavioral detection downstream. | **Partial** |
| **AML.T0048 External Harms** (agent causing real-world action) | Context tracker (after-hours, error-rate) + custom-tool policy. Strongest control is rate limiting via Anthropic's `interrupt`. | **Enforce** |
| **AML.T0050 Command and Scripting Interpreter** (via LLM) | Same as ATT&CK T1059. | **Enforce** |
| **AML.T0055 Unsecured Credentials** (LLM accessing creds) | Same as ATT&CK T1552. | **Enforce** (customer policy) |
| **AML.T0011 User Execution** (operator confirming agent action) | This IS Shield's `tool_confirmation` mode — operator must approve each tool call. v1.0.x feature. | **Enforce** |

---

## Honest gaps

Items deliberately out of scope or planned for later versions:

1. **Multi-event sequences.** Shield evaluates one event at a time. Patterns like "5 file_reads in 10 seconds then http_post" need stateful detection — partially covered by v1.2.0's `ctx.recent_error_rate` + `ctx.event_count_recent`, fully covered when Guardian Core lands.
2. **Prompt injection content inspection.** Out of scope. Use upstream input filters.
3. **Network egress at the OS level.** WMA sees tool calls, not raw sockets. Pair with a host firewall for defense-in-depth.
4. **Truncation of the audit chain.** v1.2.0 detects modification + insertion + deletion within a chain, but trailing-tail truncation is invisible locally. Fortress-side append-only ingest (planned) closes this.
5. **Cross-process audit chain.** Each Shield restart begins a new chain segment. Multi-process collusion requires the Fortress sink.
6. **OpenAI / AgentCore / LangGraph adapters.** Today only Anthropic-managed agents are wired through Watch + Shield. Phase 2 (post v1.2.0) brings the other three.

---

## How to verify a claim in this table

Every "Enforce" row above maps to a concrete test in `test/`:

- DSL primitives (`gt`, `in_range`, `length_gt`) → `test/policy-dsl-extensions.test.js`
- Context attributes (`ctx.hour_of_day_utc`, `ctx.recent_error_rate`) → `test/policy-context.test.js`
- Audit chain tamper-evidence → `test/decision-chain.test.js`
- Existing match primitives (`in`, `not_in`, `regex`, `regex_any`) → `test/policy.test.js`
- ReDoS / payload-size safety → `test/policy-redos.test.js`

Run the full suite: `node --test` (290+ tests as of v1.2.0).

---

## Customer template policies

A starter pack of policies covering the most common ATT&CK techniques in this document is shipped at [`examples/policies/mitre-starter.json`](../examples/policies/mitre-starter.json) (available both in the GitHub repo and inside the npm tarball from v1.2.1 onward — `node_modules/watchmyagents/examples/policies/mitre-starter.json`).

The bundle covers ten techniques: T1567 (exfil large POST), T1041 (C2 host allowlist), T1485 (data destruction), T1548 (privilege escalation), T1059 (oversized bash command), T1083 (after-hours discovery — late + early variants), T1020 (flailing-agent throttle via `ctx.recent_error_rate`), T1053 (cron persistence), T1552 (credential-store reads).

**Every policy ships in `mode: 'shadow'`.** That's deliberate — every blocked agent action is a potential business interruption, so the first run only LOGS would-be decisions without enforcing. Calibrate against your real workload (review what would have been blocked + tune the regex thresholds), then promote each rule individually to `mode: 'enforce'`. See [[project_recursive_fractal_loop]] for the full observe → shadow → enforce → retired lifecycle.

The starter is validated against the policy engine on every release (see `test/mitre-starter.test.js`) — if a regex falls afoul of the ReDoS heuristic in a future change or the lifecycle invariant breaks, the test suite blocks the release.

# Containment — the WMA architectural invariant

> **Raw payloads (prompts, agent outputs, tool arguments — URLs, queries, paths, commands, raw error messages) MUST NEVER leave the customer machine via any WMA upload path. The only bytes that cross to WMA Fortress are anonymized signals: counts, salted SHA-256 hashes, latencies, sequences, classification, and routing metadata.**

This is the architectural promise of WatchMyAgents. Every byte that crosses the WMA cloud boundary passes through `src/anonymizer.js`. Adapters that bypass this gate are forbidden.

---

## Why this invariant exists

Customers run agents that:
- Take **internal URLs** as input (corporate intranet, dev infrastructure)
- Generate **code that contains secrets** (API keys, credentials, signing material)
- Process **queries about confidential data** (legal cases, medical records, M&A)
- Operate in **regulated environments** (HIPAA, SOC 2, EU AI Act, ISO 42001)

If WMA shipped raw payloads to its cloud, every WMA customer would need a vendor security review of WMA's cloud infrastructure to procure WMA. By holding raw payloads on the customer's machine **forever**, WMA flips the threat model: there is nothing to steal from WMA's cloud.

> The WMA cloud (Fortress) is *payload-blind by construction*. A breach of Fortress reveals counts, latencies, and salted hashes — never your prompts, your URLs, or your code.

---

## The invariant applies to all 3 SDK patterns

WMA ships in three distribution patterns (see `docs/SOURCE-ADAPTER-CONTRACT.md`). Each honors Containment differently, but the bytes-crossing-the-boundary rule is identical.

### Pattern #1 — Remote API daemon

**SDKs:** `watchmyagents` npm CLI (current) + future remote-API adapters
**Frameworks covered:** Anthropic Managed Agents, AWS Bedrock AgentCore Watch, OpenAI Assistants/Responses, LangGraph Platform Cloud, CrewAI Enterprise

**Architecture:**
```
┌─────────────────────────────────────────────────────────────┐
│                     CUSTOMER MACHINE                         │
│                                                              │
│   Vendor REST API   ──HTTPS──→   wma-fetch (daemon)         │
│   (Anthropic, etc.)              uses customer's vendor key │
│                                          ↓                  │
│                                  local NDJSON               │
│                                  (chmod 600, ~/.wma/logs)   │
│                                          ↓                  │
│                                  anonymizer.js              │
│                                  (in-process, no network)   │
│                                          ↓                  │
└──────────────────────────────────────────┼──────────────────┘
                                           │
                                           ↓ HTTPS, only anonymized signals
                                  ┌─────────────────────┐
                                  │  WMA Fortress       │
                                  │  (no raw payloads)  │
                                  └─────────────────────┘
```

**Guarantee:**
1. The vendor API is reached using the customer's vendor key — WMA cloud never sees the vendor key.
2. Events are written to local NDJSON (`chmod 600`). These files are never transmitted anywhere by WMA.
3. The anonymizer is invoked from within the daemon's own process; there is no network hop between "raw NDJSON" and "signals payload".
4. Only the signals payload is POSTed to Fortress.

**Forbidden:**
- POST any raw NDJSON entry (the file content itself) to any endpoint.
- POST raw URLs, prompts, outputs, error messages, or any field from `entry.input` / `entry.output` beyond what the anonymizer derives.
- Forward raw events to a "staging" endpoint for later anonymization.

### Pattern #2 — In-process instrumentation library

**SDKs:** `watchmyagents-instrument` (PyPI, npm — coming)
**Frameworks covered:** LangGraph self-hosted, CrewAI, AutoGen / AG2, OpenAI Agents Python SDK, Google ADK, Hermes Agent, OpenClaw, DIY (Anthropic / OpenAI raw SDK loops)

**Architecture:**
```
┌─────────────────────────────────────────────────────────────┐
│                     CUSTOMER MACHINE                         │
│                  Customer's agent process                    │
│                                                              │
│   Agent runtime code                                         │
│       ↓                                                      │
│   tool_call() → wma-instrument hook (in-process)             │
│                       ↓                                      │
│                  anonymizer (in-process, no network)         │
│                       ↓                                      │
└─────────────────────────────────────────────────────────────┘
                       ↓ HTTPS, only anonymized signals
              ┌─────────────────────┐
              │  WMA Fortress       │
              │  (no raw payloads)  │
              └─────────────────────┘
```

**Guarantee:**
1. The WMA instrument library runs **inside the customer's agent process**.
2. It hooks the framework's tool-use lifecycle *before* any network call to an LLM provider.
3. Anonymization happens **in-process** before any outbound network egress.
4. The only WMA-related egress is HTTPS to Fortress with the signals payload.

**Forbidden:**
- Call any non-Fortress endpoint from inside the instrument library.
- POST raw payloads to a "staging" endpoint for any reason.
- Use a third-party telemetry / APM service that captures raw data (Sentry, DataDog APM, OpenTelemetry to a non-customer collector, etc.).
- Defer anonymization to a background queue that is not local-only.

**Key constraint:** the customer's process trusts the WMA library. If the library leaks raw payloads, the customer's compliance posture is compromised by transitive trust. The library MUST be auditable; the anonymization MUST be byte-exact provable.

### Pattern #3 — AWS Lambda interceptor

**SDKs:** `wma-bedrock-interceptor` Terraform module (coming)
**Frameworks covered:** AWS Bedrock AgentCore (sync_confirm enforcement via Gateway REQUEST interceptors)

**Architecture:**
```
┌─────────────────────────────────────────────────────────────┐
│                CUSTOMER'S AWS ACCOUNT                        │
│                                                              │
│   Bedrock AgentCore Gateway  ──intercepts──→  WMA Lambda     │
│                                                  ↓           │
│                                          anonymizer          │
│                                          (in Lambda runtime) │
│                                                  ↓           │
│                                          customer-controlled │
│                                          OTEL collector      │
│                                          (optional)          │
│                                                  ↓           │
└──────────────────────────────────────────────────┼──────────┘
                                                   │
                                                   ↓ HTTPS, only anonymized signals
                                          ┌─────────────────────┐
                                          │  WMA Fortress       │
                                          │  (no raw payloads)  │
                                          └─────────────────────┘
```

**Guarantee:**
1. The Lambda is provisioned in the **customer's AWS account** via the WMA Terraform module — customer-controlled IAM, customer-owned VPC if applicable.
2. The Lambda receives the request payload from AgentCore Gateway, anonymizes it inside the Lambda runtime, and only ships the signals to Fortress.
3. The Terraform module's source is auditable; the customer can pin a specific commit and re-build.

**Forbidden:**
- Egress to any non-Fortress endpoint (the Lambda's outbound IAM policy is scoped to Fortress only).
- Persist raw tool-call payloads in S3, DynamoDB, or any AWS service (the Lambda's role grants no write access to durable storage).
- Use AWS observability tools (X-Ray, default-mode CloudWatch Logs) that would capture raw payloads — only customer-controlled OTEL collectors with explicit anonymization configuration.

**Strong default:** the Terraform module provisioning the Lambda **also** provisions a customer-controlled ADOT collector configured to anonymize before any cross-region egress.

---

## How Containment is verified

### Automated invariant tests (`test/containment.test.js`)

| Test | What it asserts |
|---|---|
| no-raw-input-leak | Inject raw URLs, queries, commands into events → assert none appear in the signals output |
| no-raw-content-leak | Inject raw prompts / outputs → assert none appear in the signals output |
| hash-determinism | `hashWithSalt(value, salt)` is deterministic so customers can re-derive IoC hashes locally |
| hash-presence | Raw URL injected → its salted hash is present in `ioc_hashes` (proves the value WAS observed without revealing it) |
| payload-shape | The signals payload has exactly the allowed top-level keys and exactly the allowed inner payload keys — no surprise field can carry raw data |

These tests run on every commit (`node --test`). A regression flips one of them red immediately.

### Code review

- `src/anonymizer.js` is the single bottleneck. Any change to it requires a Containment-impact statement in the PR description.
- Every new Source adapter passes the Pre-PR checklist in `docs/SOURCE-ADAPTER-CONTRACT.md` (§8).

### Customer-side audit

- Customers can run `tcpdump` on the egress interface of any WMA process to verify only Fortress URLs are reached.
- The `wma-anonymize --dry-run` CLI lets customers preview *exactly* what would be sent to Fortress before they enable upload.
- The signals payload schema is documented in the README + this file; customers can write their own egress filter (e.g., a forward proxy) to validate by structure.

### Fortress-side guarantee

The Fortress `ingest-signals` Edge Function **explicitly rejects** any payload field outside the documented schema. The schema does not include `input`, `output`, `error` (as text), or any other raw-content carrier. This is the customer-side complement to the SDK guarantee: even if a future SDK regression accidentally shipped raw data, Fortress would reject the payload.

---

## What if Fortress is breached?

A breach of Fortress reveals:
- **Counts**: how many `tool_use` events per customer per agent per window.
- **Latencies**: p50/p95/max per tool.
- **Salted IoC hashes**: opaque 32-char SHA-256 prefixes that cannot be brute-forced without the customer's salt.
- **Sequence patterns**: `"tool_use → tool_use → message"` as opaque labels.
- **Classification metadata**: agent type + confidence + stage.
- **Routing identifiers**: agent IDs, display names, provider name.

A breach of Fortress does **NOT** reveal:
- Any prompt.
- Any agent output.
- Any URL, file path, command, or query.
- Any error message text.
- Any customer code, customer data, or PII.

This is the architectural property — not a configuration that can be turned off.

---

## Related

- `docs/SOURCE-ADAPTER-CONTRACT.md` — Source contract authors follow Containment per §6.
- `src/anonymizer.js` — the canonical anonymization implementation.
- `test/containment.test.js` — the regression-proof test suite for this invariant.
- `memory/project_containment_architecture.md` — the design memo (internal context).

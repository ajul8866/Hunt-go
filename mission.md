## Mission
Build `huntgo` at `./huntgo`: an autonomous, blackboard-driven bug-bounty campaign engine that uses Claude Code as its worker runtime. Given an authorized origin, goal, scope, rules of engagement, and optional hints, it MUST self-direct: generate its own intents, choose its own tools and techniques, write custom scripts, use browser/proxy/shell/OOB, chain verified findings, and produce submission-ready reports. It MUST NOT be a fixed pipeline, a scanner checklist, or a zoo of hardcoded specialist roles.

## Autonomy contract
- After `huntgo run`, no human step-by-step interaction is required. Ordinary in-scope actions proceed without approval.
- The engine decides what to explore next from the graph state. The dispatcher only schedules work and enforces limits; it never chooses targets or techniques.
- Workers are interchangeable. There are no fixed "recon agent", "SQLi agent", or "report agent" roles. Behavior emerges from the task type, graph context, hints, and available tools.
- Workers MAY write and run custom code, install tools inside the sandbox, use arbitrary CLI tools through the egress proxy, drive a real browser, and pursue novel attack paths. Do not constrain them to a technique allowlist.
- The engine MUST keep working until the goal is proven, the budget is exhausted, the operator pauses it, or the safety layer stops it. It MUST revisit failed intents when new facts appear and MUST NOT stop after one pass.
- Human input is optional `Hint` injection: focus, avoid, canary, credential reference, endpoint context, strategy, safety guidance, approval. Hints guide judgment; they do not become a workflow.
- The only hard invariants are authorization/scope, rules of engagement, non-destructiveness, evidence, and audit. Safety is a boundary, not a cage.

## Design lineage
Study these public systems and borrow architectural patterns, not code:
- Cairn (`github.com/oritera/Cairn`): Fact/Intent/Hint blackboard, OODA workers, no fixed roles, stigmergic coordination, Bootstrap/Reason/Explore tasks, dispatcher + worker containers, local Claude Code mode.
- Strix (`github.com/usestrix/strix`): full offensive toolkit in a sandbox, HTTP proxy, browser, terminal, Python runtime, validated PoCs, run artifacts, agent-native CLI/skills.
- XBOW (`docs.xbow.com`): undirected testing by default, guidance/canaries, safety judge plus deterministic rules, protected endpoints, rate limits, target health monitoring, evidence-based validation.
- ARTEX: a cautionary example of fully autonomous fleets. Its lesson is that autonomy without hard egress/scope containment and audit is unsafe. Build containment first.
Write original code. Do not copy AGPL or other source.

## Target tree
```text
huntgo/
├── pyproject.toml
├── README.md
├── CLAUDE.md
├── Dockerfile
├── compose.yaml
├── .claude/
│   ├── settings.json
│   ├── hooks/guard_operator.py
│   ├── skills/huntgo-{init,run,status,graph,hint,pause,resume,report,replay,doctor,scope,worker}/SKILL.md
│   └── agents/{huntgo-operator,huntgo-verifier,huntgo-reporter,huntgo-safety}.md
├── prompts/
│   ├── worker/{bootstrap,reason,explore,conclude,report,reflect}.md
│   ├── judge/safety.md
│   └── operator.md
├── examples/{scope.example.yaml,goal.example.md,identities.example.yaml,hints.example.yaml}
├── huntgo/
│   ├── __init__.py  __main__.py  cli.py  config.py  errors.py  models.py
│   ├── blackboard/{__init__,store,api,artifacts,events,schemas}.py
│   ├── server/{__init__,app,main}.py
│   ├── dispatcher/{__init__,scheduler,leases,tasks,conclude,health}.py
│   ├── runtime/{__init__,claude_sdk,claude_cli,container,local,mock,workspace,transcripts}.py
│   ├── tools/{__init__,mcp_server,http_recorder,proxy,browser,oob,shell,blackboard_api}.py
│   ├── policy/{__init__,scope,roe,rules,judge,egress,redaction,protected}.py
│   ├── evidence/{__init__,ledger,bundle,verify}.py
│   ├── memory/{__init__,store,priors,replay,reflect}.py
│   └── report/{__init__,builder,platforms,cvss}.py
└── tests/
    ├── unit/{test_graph,test_scheduler,test_leases,test_policy,test_evidence,test_report,test_prompts}.py
    ├── integration/{test_mock_campaign,test_resume,test_replay,test_safety,test_tools}.py
    ├── lab/{app.py,run.py,seed.py,scripted_worker.py}
    └── fixtures/{...}
```

Dependencies: `claude-agent-sdk`, `fastapi`, `uvicorn`, `httpx[http2]`, `pydantic>=2`, `PyYAML`, `websockets`; dev `pytest`, `pytest-asyncio`; optional extra `browser`: `playwright`. Python 3.12+.

## 1. Campaign manifest
`scope.yaml`, `goal.md`, and `identities.yaml` are required for a run. Lock them into the campaign with a canonical SHA-256. Strict validation; reject unknown keys; reject literal secrets.

```yaml
authorization:
  program: "Example"
  platform: hackerone        # hackerone|bugcrowd|intigriti|yeswehack|other
  policy_url: "https://example.com/policy"
  authorized_by: "handle"
  authorized_at: "2026-01-01"
  expires_at: "2030-12-31"
scope:
  include: ["https://app.example.com", "https://*.api.example.com"]
  exclude: ["https://app.example.com/admin"]
roe:
  tier: intrusive            # passive|active|intrusive: risk budget, never a technique allowlist
  forbidden: [dos, destructive, persistence, lateral_movement, data_exfiltration]
  state_change: own_resources_only   # none|own_resources_only
  allow_cloud_metadata: false
  allow_oob: true
  allow_browser: true
  allow_tool_install: true
  allow_raw_sockets: false
  allow_cache_poisoning: false
limits:
  max_requests: 100000
  max_rps: 10
  max_concurrency: 4
  max_runtime_seconds: 28800
  max_llm_usd: 50
  max_worker_turns: 200
  max_payload_bytes: 65536
  max_artifact_bytes: 10485760
protected:
  never_attack: ["/logout", "/account/delete", "/billing/charge"]
  auth_only: ["/login", "/oauth/token"]
identities:
  - label: anonymous
    role: anonymous
  - label: alice
    role: user
    bearer: env:HUNTGO_ALICE_TOKEN
  - label: bob
    role: user
    cookie: env:HUNTGO_BOB_COOKIE
```

`goal.md` states the success condition and report contract, for example: find and validate the highest-impact in-scope vulnerabilities, prioritize access control, authentication, injection, SSRF, business logic, and chains; produce platform-ready reports; stop at budget. It is guidance, not a checklist. `hints.yaml` contains human judgment: focus, avoid, canary, credential refs, endpoint context, strategy, safety, approval.
Safe mode refuses to start without valid authorization, non-empty scope, a goal, RoE, limits, and required identities. Expired authorization, missing keys, literal secrets, unknown keys, or out-of-scope targets exit `3` before any worker starts.

## 2. Blackboard graph
The graph is the plan and the memory. SQLite with WAL, foreign keys, FTS5, and a single writer. Artifacts are content-addressed files with SHA-256 and sensitivity tags.
Core records:
- `Campaign`: id, origin, goal, scope digest, RoE, budget, status, created_at.
- `Fact`: confirmed objective result; description, evidence IDs, proof level, confidence, tags, source intent, author worker, created_at. `Fact` is not an opinion; it must be reproducible.
- `Intent`: declared exploration direction; `from_fact_ids`, description, priority, status, claimed_by, lease_expires, attempts, cost, outcome. Intents are how the graph grows.
- `Hint`: human judgment; kind, content, author, active, created_at. Workers read hints on every task.
- `Artifact`: raw evidence; kind, path, sha256, size, mime, redaction state, creator.
- `Finding`: a fact promoted to a vulnerability; title, severity, CVSS 3.1, CWE, asset, identities, impact, remediation, proof level, evidence bundle, report state.
- `Chain`: finding IDs, preconditions, effects, combined impact, proof level.
- `Event`: append-only audit record with `prev_hash` and `hash`; tool call, network, judge decision, fact, intent, hint, lease, report, error.

API (local token auth, bind 127.0.0.1 by default):
`GET /campaigns/{id}/graph`, `GET /campaigns/{id}/status`, `POST /facts`, `POST /intents`, `POST /hints`, `POST /artifacts`, `POST /intents/{id}/claim`, `POST /intents/{id}/heartbeat`, `POST /intents/{id}/release`, `POST /intents/{id}/complete`, `POST /campaigns/{id}/complete`, `POST /campaigns/{id}/pause`, `POST /campaigns/{id}/resume`, `GET /events`.
All writes are transactional. Claiming is atomic. Duplicate facts and duplicate intents are detected by normalized fingerprints. Long descriptions reference artifacts instead of embedding blobs. Redact secrets and PII at write time.

## 3. Dispatcher and generic workers
The dispatcher is the sole writer to the protocol. It never decides what to attack. It schedules task types from graph state:
- `bootstrap`: origin + goal + hints; attempt direct progress; return facts and/or intents; `complete` only with proof.
- `reason`: full graph snapshot + valid facts + open intents + hints + relevant cross-campaign memories; decide `complete`, new intents, or no-op. It does not execute.
- `explore`: claim exactly one open intent; execute with any tools; return one or more facts, artifacts, and optional child intents.
- `conclude`: interrupt a long worker and demand an incremental summary; never pretend partial work is complete.
- `report`: verify facts/evidence and build platform reports; no new exploitation beyond reproduction.
- `reflect`: post-campaign summary into cross-campaign memory; reusable patterns, no secrets.

Scheduling rules: ensure a bootstrap exists; request reason when the graph changes and no reason task is running; schedule explore tasks while open intents and worker capacity exist; enforce leases, heartbeats, TTL, retry caps, and conclude timeouts; stop on complete, pause, budget, or safety halt. A killed worker leaves its intent reclaimable. A worker is a process, not a persona.
Strict JSON output contracts. Invalid JSON is rejected, logged, and retried once; repeated invalid output is quarantined. Workers communicate only through the blackboard; no direct worker-to-worker messages. Stigmergy, not chat.

## 4. Claude Code worker runtime
Use the Python Agent SDK (`claude-agent-sdk`) as the primary runtime; `ClaudeSDKClient` for long-running workers so `interrupt()` and conclude work. Use `ClaudeAgentOptions` with:
- `system_prompt={"type":"file","path":"prompts/worker/<task>.md"}`
- `setting_sources=[]` so host/user CLAUDE.md, skills, and settings do not contaminate the worker.
- `cwd` = an isolated per-worker workspace.
- `max_turns`, `max_budget_usd`, `model`, and `env` from campaign config.
- `allowed_tools` for Bash, Read, Write, Edit, Glob, Grep, TodoWrite, and `mcp__huntgo__*`.
- `disallowed_tools` for `WebFetch`, `WebSearch`, `Agent`, `Skill`, `AskUserQuestion`, and recursive `claude` invocation.
- `mcp_servers={"huntgo": sdk_mcp_server}` exposing the blackboard and controlled tools.
- `hooks={"PreToolUse":[HookMatcher(matcher=None, hooks=[judge_hook])]}`. The hook runs on every tool call, including allowed ones. It calls the safety judge and denies with a documented permission decision; fail closed on judge error.
Do NOT rely on `can_use_tool` for enforcement: allow rules and permission modes can shadow it. The PreToolUse hook is authoritative.
Do NOT use `--bare` for workers that depend on hooks; use the SDK or a generated settings file and verify hooks load.
Save every worker transcript, session ID, usage, cost, stderr tail, and final JSON to `runs/<worker_id>/`. Support local mode (host Claude Code auth) and container mode (Docker sandbox, network restricted to the egress proxy). Local mode is trusted-host only; README must warn. Container mode is the default recommendation for real targets.

The worker prompt files are part of the engine:
- `bootstrap.md`: origin, goal, hints; be autonomous; produce facts/intents; complete only with proof.
- `reason.md`: YAML graph, valid facts, open intents, hints, memories; output complete/intents/no-op; no execution.
- `explore.md`: graph, claimed intent, hints; use any tool within RoE; write facts with evidence; propose child intents; stop when exhausted.
- `conclude.md`: stop exploring now; summarize incremental facts; never claim completion.
- `report.md`: verify evidence, reproduce, build reports; exclude failures; no invention.
- `reflect.md`: summarize what worked/failed into reusable memory.
Every prompt MUST say: you are a worker, not a chatbot; the blackboard is shared; claim one intent; no user questions; no hidden chain-of-thought; output strict JSON only; long data goes to artifacts; facts must be objective and reproducible.

## 5. Tools, sandbox, egress
Workers need a real toolkit, not a toy:
- Bash shell in an isolated workspace.
- Python runtime for custom exploit scripts.
- HTTP recorder: `huntgo http` / MCP `http_request` sends requests, enforces scope/rate, records raw request/response, hashes, and identity.
- Scope-enforcing forward proxy: HTTP and CONNECT, host/port allowlist, rate limit, request log; workers get `HTTP_PROXY`/`HTTPS_PROXY`. Container network policy allows only the proxy. Local mode relies on the judge and must be documented as weaker.
- Browser: Playwright headless Chrome, proxied, with navigation, click, type, JS execution, screenshots, traces, network capture, and route interception. Use it for XSS execution, auth flows, CSRF PoCs, and visual evidence.
- OOB: local HTTP callback for tests and an Interactsh-compatible provider configured by env (`HUNTGO_OOB_SERVER`, `HUNTGO_OOB_TOKEN`). Unique token per probe; correlate callbacks; store interaction evidence.
- Artifact store: raw HTTP, screenshots, traces, scripts, command output, hashes.
- Optional MCP servers and tool installation inside the sandbox. Do not install on the host.
- No direct `WebFetch`/`WebSearch`; all target egress is recorded. No recursive Claude invocation. No writes outside the workspace.
Container image: Python + Node + Claude Code + a curated security toolkit (at minimum httpx, nuclei, ffuf, katana, subfinder, naabu, arjun, dalfox, sqlmap, jwt_tool, interactsh-client, playwright, curl, jq, git). Document that workers may install more inside the container.

## 6. Safety, RoE, judge
Safety is a boundary, not a workflow.
- Deterministic rules run first: out-of-scope host/port/scheme; forbidden methods/paths; protected endpoints; metadata IPs; private IPs unless allowed; destructive commands; persistence; lateral movement; credential dumping; data exfiltration; DoS patterns (concurrency, payload size, recursion); direct egress bypass; secret writes; recursive agent/skill calls; writes outside workspace.
- LLM safety judge runs only for ambiguous or high-impact actions. Input: tool call, action summary, scope summary, RoE, relevant hints, target health, budget. Output: allow/deny, reason, constraints, requires-hint. It may only restrict, never widen.
- High-impact actions (state change, upload, auth attempts against real accounts, metadata, raw sockets, cache poisoning) require a matching pre-approved hint or are denied with a pending approval. Ordinary in-scope read-only/canary work proceeds autonomously.
- Target health monitor: baseline latency/error rate; on degradation reduce RPS/concurrency, pause, and resume after recovery. Record the event.
- Protected endpoints: never attack logout, delete, payment, password reset, or other disruptive paths; auth-only endpoints may be used to authenticate but not attacked.
- Every decision is audited; pause/kill switch is immediate; all workers stop on pause.
- Redaction: cookies, authorization headers, tokens, keys, PII values at artifact/event/report boundaries. Secrets are referenced as `env:NAME`, never stored.

## 7. Cross-campaign memory
A separate `memory.db` stores reusable patterns: technologies, endpoints, successful intents, failed approaches, canaries, report snippets, chain patterns, target fingerprints. FTS5 retrieval. `reflect` writes post-campaign insights. `reason` receives the top relevant memories; workers decide how to use them. `replay --campaign C --mode offline` rebuilds the graph and report with zero network calls. `replay --campaign C --mode fork` starts a new campaign seeded with selected facts/hints and the same scope, without automatically repeating exploitation. `resume` continues a campaign after crash/pause with leases recovered and budgets preserved.

## 8. Evidence and reporting
Proof levels: `P0` observation, `P1` differential control, `P2` deterministic replay, `P3` independent corroboration/OOB, `P4` runtime/cross-identity/state effect. A finding fact MUST declare its proof level and evidence IDs. The report task re-runs each reproduction through the sandbox; if it fails, the finding is downgraded and excluded. No LLM-only claims. Cross-tenant data, browser execution, and state effects require P4.
Reports: Markdown + JSON, optional SARIF; platform templates for HackerOne, Bugcrowd, Intigriti, YesWeHack, generic. Include title, severity, CVSS 3.1 vector/score, CWE, asset, identities, summary, reproduction steps, raw evidence, impact, remediation, chain narrative, scope digest, RoE flags, tool versions, evidence hashes. Redact secrets. Refuse with exit `4` if an included finding is below threshold, lacks replay, or has broken evidence. Zero verified findings is valid and produces a clean report. NEVER include candidates, rejected facts, or unverified chains. Chain reports require every link verified; severity never exceeds the strongest verified link.

## 9. Claude Code operator pack
Project skills: `/huntgo-init`, `/huntgo-run`, `/huntgo-status`, `/huntgo-graph`, `/huntgo-hint`, `/huntgo-pause`, `/huntgo-resume`, `/huntgo-report`, `/huntgo-replay`, `/huntgo-doctor`, `/huntgo-scope`, `/huntgo-worker`. Each has valid frontmatter (`description`, `argument-hint`, `allowed-tools`), invokes only the CLI, prints refusals verbatim, and never sends target traffic directly.
Subagents: `huntgo-operator` (drive CLI), `huntgo-verifier` (read-only evidence replay), `huntgo-reporter` (report generation, no new findings), `huntgo-safety` (RoE/hint review, no execution). These are operator conveniences, not engine roles; the engine workers remain interchangeable.
`CLAUDE.md` MUST state: authorized programs only; operate through huntgo; never bypass the judge or proxy; hints guide but do not authorize out-of-scope action; only verified findings are reportable; stop on pause; no secrets in files or logs.
`.claude/settings.json` allows huntgo/pytest/python; denies curl/wget/nmap/nc and direct target traffic. `.claude/hooks/guard_operator.py` blocks out-of-scope URLs and raw network tools in the operator session. Note that settings/hooks are defense-in-depth; the engine judge/proxy is the boundary.

## 10. CLI
`huntgo init --scope scope.yaml --goal goal.md --identities identities.yaml`; `huntgo scope check`; `huntgo serve`; `huntgo dispatch --config dispatch.yaml`; `huntgo run --scope ... --goal ... --identities ... --worker claude --max-budget-usd N`; `huntgo status --campaign ID --json`; `huntgo graph --campaign ID --format mermaid|json`; `huntgo hint --campaign ID --kind focus|avoid|canary|credential|strategy|safety|approval`; `huntgo pause|resume --campaign ID`; `huntgo report --campaign ID --platform hackerone|bugcrowd|intigriti|yeswehack|generic`; `huntgo replay --campaign ID --mode offline|fork`; `huntgo worker --task bootstrap|reason|explore|conclude|report|reflect --campaign ID`; `huntgo export --campaign ID --format json|sarif`; `huntgo doctor --json`. All machine-readable outputs are stable.

## 11. Verification lab and tests
Build a loopback lab in `tests/lab/` with seeded identities and secure decoys: IDOR/BOLA, BFLA, mass assignment, SQLi, SSTI, SSRF with callback, reflected/stored XSS, JWT weakness, GraphQL authz, CORS reflection, open redirect, race condition on an owned resource, upload/SVG, exposed `.git`/`.env`, and decoys for each. No real secrets; fake values only.
Test layers:
- Unit: schemas, graph store, leases, scheduler, budget, judge rules, redaction, evidence ledger, report gating, prompt rendering.
- Integration with `mock` backend: bootstrap → intents → explore → facts → reason → complete → report; invalid JSON retry; lease expiry and reclaim; crash/resume; pause; budget stop; safety denial; tampered evidence; unaudited claim.
- Scripted lab worker: a deterministic non-LLM worker uses the real MCP tools/HTTP recorder to find 3 verified lab findings, reject 1 decoy, produce 1 verified chain, and generate a report containing only verified items. This proves the engine and evidence path without LLM cost.
- Live smoke (optional, `HUNTGO_LIVE_TEST=1`): a real Claude Code worker runs against the lab with a small budget; assert at least one fact, at least one verified finding, no policy violations, and a transcript. Skip with a clear reason when auth/CLI is unavailable.
- Claude pack: 12 skills and 4 agents parse with valid frontmatter; `.claude/commands/` absent; hook config valid.
- Refusal matrix: missing scope/RoE/goal/limits; expired authorization; out-of-scope target; protected endpoint; metadata without opt-in; state change without permission; direct egress bypass; no local API token; each exits `3` or non-zero and opens no socket.
- Replay offline: zero network calls; report re-verified from stored evidence. Fork: new campaign receives facts/hints; no automatic exploitation.
- Cross-campaign memory: reflect writes a reusable pattern; new reason context includes it; no secrets.
- No false positives: sub-threshold, tampered, or failed-replay findings are excluded from reports; the scripted decoy is never reported.

## 12. Engineering constraints
Async-first (`asyncio.TaskGroup`); bounded concurrency; SQLite single writer; WAL; atomic state writes; fsync journal; hash-chained events; content-addressed artifacts. Type hints on public APIs; pydantic at boundaries; typed errors; no bare `except`, `shell=True`, `eval`, or YAML `unsafe_load`. Windows-compatible paths and UTF-8; Docker optional. Deterministic tests with fixed seeds; no real DNS or external targets. Structured JSON logs; secrets never logged. TLS verification on. Respect `Retry-After`; detect WAF/block/health degradation and back off, never report them as findings. No TODO, stub, placeholder, or fabricated output.

## 13. Acceptance criteria
- [ ] `python -m pip install -e ".[dev]"` succeeds; `pytest -q` passes.
- [ ] `huntgo doctor --json` validates SDK/CLI availability, auth, DB, proxy, optional browser/Docker, scope, hook, and a no-network self-test.
- [ ] Mock campaign completes with bootstrap/reason/explore/conclude/report, resume after kill, and a report containing only verified facts.
- [ ] Scripted lab campaign produces ≥3 verified findings, rejects ≥1 decoy, produces a verified chain, and writes a platform report.
- [ ] Every report finding has evidence IDs, proof level, replay result, CVSS, and CWE; tampered or sub-threshold findings are excluded.
- [ ] Refusal matrix passes with no socket opens; safety hook denies destructive commands and out-of-scope URLs.
- [ ] `replay --mode offline` makes zero network calls; `replay --mode fork` seeds context without auto-exploitation.
- [ ] Cross-campaign memory is read by `reason` and contains no secrets.
- [ ] 12 skills and 4 agents load structurally; no `.claude/commands`; hook config valid.
- [ ] README covers install, manifest, autonomy model, blackboard, worker runtime, judge, tools, memory, reporting, operator commands, security caveats, and limitations.
- [ ] No fixed phase pipeline, no fixed role taxonomy, no technique allowlist in the engine. The graph drives behavior.

## 14. Action boundaries
Proceed autonomously with reversible, in-scope work. Stop and ask before: adding dependencies beyond the declared set; changing graph/evidence/report schemas; contacting a non-loopback host during development; enabling a forbidden RoE capability; deleting anything outside `./huntgo`; pushing to git. If a test fails twice after distinct fixes, report the exact command and output and stop. NEVER weaken, delete, or skip a test to pass.

## 15. Final response
Report the file tree, actual install/test/doctor output, mock campaign transcript, scripted lab finding matrix, safety denial examples, report paths, and remaining limitations. Ground every claim in observed output.

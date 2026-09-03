# VerificationForge Architecture

## Purpose

VerificationForge is a language-agnostic, evidence-first software verification runtime and development firewall. Its core must remain independent of any individual programming language or external verification product.

## Dependency direction

The workspace is split into four architectural layers:

1. **Core contracts — `verificationforge-core`**
   Defines requirements, findings, evidence semantics, graph models, policies, execution contracts, language/toolchain contracts, specialist verification interfaces, and development-firewall policy types. This layer must not depend on concrete languages.
2. **Runtime — `verificationforge-runtime`**
   Detects project ecosystems, registers adapters, plans verification, captures content-addressed repository snapshots, computes change impact, schedules work under resource budgets, stores cache results, records durable run journals, enforces certification policy, and exposes controlled agent-development operations.
3. **Adapters — `verificationforge-adapter-*`**
   Concrete language/toolchain integrations. Rust and Python are the first-class initial adapters. New languages are added here without changing verification-engine semantics.
4. **Composition — `verificationforge-cli` and future applications/services**
   Selects concrete adapters and execution backends, loads policy/configuration, invokes the runtime, and presents machine- and human-readable results.

Dependencies flow inward toward core contracts. Concrete adapters may depend on the core. The core must never import a concrete adapter.

## Adapter model

`LanguageAdapter` is the primary language extension boundary. `ToolchainAdapter`/toolchain probing isolates compiler, formatter, linter, and test-runner behavior. `SpecialistVerificationAdapter` covers domains such as security, dependency analysis, coverage, mutation, fuzzing, concurrency, UI/API/protocol validation, stress, fault injection, formal proof, and provenance. `ExecutionAdapter` keeps process execution replaceable and prevents orchestration code from assuming a local shell.

Unsupported verification is explicit. An adapter must not fabricate PASS when a technique is unavailable.

## Executable specifications and graphs

Requirements can exist before implementation. The runtime links three graph families:

- **RequirementGraph** — intended behavior and relationships between requirements.
- **Universal CodeGraph** — implementation entities and dependency relationships across repository boundaries.
- **EvidenceGraph** — verification evidence connecting requirements and implementation to reproducible results/artifacts.

Graph queries are used to detect missing or stale proof rather than treating a successful command exit as sufficient evidence by itself.

## Content-addressed scheduling

Repository snapshots are content-addressed. A snapshot diff identifies changed paths, which map into `UniversalCodeGraph` symbols. Dependency-cone analysis computes affected symbols. When changed paths cannot be mapped safely, the planner escalates to full verification instead of guessing.

Verification cache keys include content identity, adapter identity, check kind, verification level, and policy version. This makes reuse explicit and invalidates cached evidence when relevant inputs change.

Resource-aware scheduling groups verification tasks without exceeding declared CPU, memory, or GPU budgets. Durable run journals record progress, heartbeats, checkpoints, completion, and failures and support stall detection.

## Progressive gates

Verification depth increases with lifecycle risk:

- **Patch** — fast repository correctness and targeted verification.
- **Checkpoint** — broader integration and affected specialist checks.
- **Commit** — complete normal verification and stronger adversarial sampling.
- **Certification** — exhaustive policy-selected verification required for a releasable artifact.

A check may return PASS only when it carries reproducible evidence. Unsupported and skipped checks remain distinct states and policy decides whether they are acceptable for the requested gate/risk tier.

## Development firewall

Agent-driven development uses `ControlledDevelopmentSession`. It binds operations to a canonical repository root and an agent identity, evaluates every operation through `DevelopmentFirewallPolicy`, and records accepted/rejected actions in an operation ledger.

The controlled boundary covers reads, writes, dependency-file changes, exact patches, deletes, renames, structured command/test execution, Git commit authorization, and certification authorization. It rejects traversal, absolute-path escape, symlink traversal, and direct `.git` mutation. Commits require evidence. Certification additionally requires an engine-issued certification identifier and no blocking findings.

## Security model

VerificationForge fails closed at security boundaries. Native repository security checks and specialist adapters can create blocking findings. Ordinary agent actions cannot suppress a blocking finding or manufacture certification evidence. External analyzers stay behind adapter/process boundaries to keep both trust and licensing boundaries explicit.

## Adding a language

A new language integration should:

1. implement language detection and the generic adapter contracts;
2. expose real formatter/build/type/lint/test capabilities only when available;
3. convert tool output into structured findings and reproducible evidence;
4. add deterministic fixtures proving successful verification and expected failure behavior;
5. require no change to the core verification engine merely to recognize the new language.

This invariant is part of VerificationForge's production-capable definition.

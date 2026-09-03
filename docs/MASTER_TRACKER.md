# VerificationForge Master Tracker

This is the canonical capability roadmap. It intentionally describes required capabilities rather than naming external products or projects.

## Foundation
- [x] Public MIT governance, contribution, security, and architecture documentation
- [x] Generic LanguageAdapter, ToolchainAdapter, ExecutionAdapter and specialist verification adapter interfaces
- [ ] Automatic language, framework, build-system, package-manager, test-system, UI, API, database, smart-contract, shader and infrastructure detection
- [x] Mixed-language repository support

## Before-code verification
- [ ] Executable requirements, features, functions, interfaces, UI controls, inputs/outputs, preconditions, postconditions, invariants, error behavior, security/authorization rules, persistence, performance/resource limits, concurrency, state machines, compatibility, accessibility and reliability rules
- [x] Convert specifications into verification obligations before implementation exists
- [ ] Design-level state exploration, reachability, invariant checking, distributed/concurrent modeling, architecture policy checks and threat modeling

## Graph model
- [x] RequirementGraph for intended behavior and requirement relationships
- [x] Universal CodeGraph for repositories, packages, modules, files, types, functions, calls, variables, imports, control/data flow, dependencies, APIs, UI controls, databases, processes, network/filesystem/native/security boundaries and concurrency primitives
- [x] EvidenceGraph linking requirement -> implementation -> verification evidence -> artifact
- [x] Queries for orphaned requirements, unrequested implementation, weakly proven code and stale evidence

## Scheduling and execution
- [x] Content-addressed inputs/results
- [x] Fine-grained changed-symbol and dependency-cone impact analysis
- [ ] Local/shared/distributed caches with safe invalidation
- [ ] Local, sandbox, container, VM, remote-runner and distributed execution backends
- [x] Resource-aware scheduling
- [x] Durable checkpoints, heartbeats and hang/stall/deadlock detection

## Verification gates
- [x] Patch gate: parse, format, build/type/lint, secrets, placeholders, impact analysis and targeted tests
- [x] Checkpoint gate: affected integration/property/security/dependency/UI/API verification
- [ ] Commit gate: complete normal tests, coverage, mutation sampling, fuzz sampling and security verification
- [ ] Certification gate: full mutation, extended fuzz, race/concurrency, stress, fault injection, resource leaks, full UI exploration, dependency/security/history scanning, sandbox behavior and reproducibility

## Correctness and adversarial testing
- [ ] Unit and integration testing
- [ ] Generated tests from specifications, signatures, types, invariants, states, branches, boundaries and historical bugs
- [ ] Property testing and state-machine sequence exploration with shrinking
- [ ] Mutation testing with critical surviving mutants blocking certification
- [ ] Coverage-guided fuzzing with persistent corpus, minimization and regression promotion
- [ ] Differential and black-box testing fallbacks where native tooling is weak
- [ ] Race, deadlock, livelock, atomicity, cancellation, ordering, duplication and starvation verification
- [ ] Stress, soak and resource-leak verification
- [ ] Fault injection for storage, network, database, permissions, clocks, process crashes, malformed/partial responses, saturation, cancellation and interrupted writes

## Security
- [ ] Static, data-flow and taint analysis
- [ ] Hardcoded-secret and repository-history scanning
- [ ] Dependency, vulnerability, supply-chain and license checks
- [ ] Authentication, authorization, injection, traversal, command execution, deserialization, crypto/randomness, logging, permissions and network-exposure checks
- [ ] Suspicious trigger/logic-bomb analysis across time, identity, host, machine, network, environment, files, processes, VCS state, counters, licensing and randomness
- [ ] Dynamic suspicious-trigger verification with fake clocks/environments/identities/network conditions

## Placeholder and fake implementation detection
- [ ] Explicit TODO/FIXME/XXX/unimplemented/NotImplemented/pass/empty-body detection
- [ ] Semantic detection for always-success/failure, constant auth decisions, empty persistence, log-instead-of-work, catch-all success, swallowed failures, hardcoded test/network/database responses, bypassed validation and disabled security

## UI/API/protocol verification
- [ ] Automatic interactive-control inventory
- [ ] Existence, visibility, click/keyboard/accessibility, handler, success/failure/loading/disabled/rapid-click/double-submit/navigation/dialog/form/menu/route/error-recovery testing
- [ ] Dead interactive controls block certification
- [ ] HTTP, event/message, RPC, streaming, WebSocket, CLI and IPC contract verification
- [ ] Compatibility verification across revisions

## Formal/extreme tier
- [ ] Preconditions, postconditions and loop invariants
- [ ] Memory/integer-safety properties
- [ ] Symbolic execution and constraint solving
- [ ] Model checking and proof harnesses
- [ ] Counterexample generation
- [ ] Long fuzz/stress campaigns

## Agent development firewall
- [x] Controlled read/write/patch/delete/rename/dependency/command/test/commit/certification operations
- [x] Track agent identity, requirement, files, symbols, commands, results, fix attempts and regression tests
- [x] Agents cannot self-declare PASS
- [x] Adversarial semantic reviewers create verification obligations but cannot grant certification

## Interchange, provenance and observability
- [ ] Standard machine-readable import/export for findings, tests, coverage, component/dependency inventories, vulnerabilities, provenance, API/event/RPC contracts, traces, metrics and logs
- [x] Provenance chain: agent -> requirement -> patch -> verification -> commit -> build -> artifact
- [ ] Per-operation timestamps, duration, progress, inputs/outputs, resource use, checkpoints and heartbeat

## Language and ecosystem expansion
- [x] Rust
- [x] Python
- [ ] C
- [ ] C++
- [ ] C#
- [ ] Java
- [ ] Kotlin
- [ ] Scala
- [x] Go
- [ ] JavaScript
- [ ] TypeScript
- [ ] Swift
- [ ] Objective-C
- [ ] Dart
- [ ] PHP
- [ ] Ruby
- [ ] Lua
- [ ] Perl
- [ ] R
- [ ] Julia
- [ ] Haskell
- [ ] OCaml
- [ ] F#
- [ ] Elixir
- [ ] Erlang
- [ ] Zig
- [ ] Nim
- [ ] D
- [ ] Fortran
- [ ] COBOL
- [ ] Bash
- [ ] PowerShell
- [ ] SQL dialects
- [ ] Solidity
- [ ] Vyper
- [ ] Move
- [ ] Cairo
- [ ] HTML/CSS
- [ ] GLSL
- [ ] HLSL
- [ ] WGSL
- [ ] Framework/platform-specific adapters for major web, server, JVM, .NET, mobile, desktop, game-engine, database and smart-contract ecosystems
- [ ] Generic syntax/black-box/differential/fuzz/contract/semantic fallbacks for languages without mature native tooling

## Certification
- [x] Configurable risk-tier policy engine
- [ ] Mandatory thresholds for functionality, symbols, tests, coverage, mutation, fuzz, security, concurrency, placeholders, UI, performance, resilience, dependency health and formal proof where required
- [x] Critical failures cannot be suppressed by ordinary agent actions
- [x] Every PASS links to reproducible evidence rather than a bare boolean

## Self-verification
- [ ] VerificationForge runs its own specification, graphs, mutation, fuzz, security, concurrency, fault-injection and certification systems against itself
- [ ] Releases eventually require self-certification

## Production-capable definition
- [x] Multiple unrelated languages verify without core modification
- [x] Mixed-language repositories verify correctly
- [x] Specifications create obligations before code
- [x] Agents build through controlled mutation interfaces
- [x] RequirementGraph, CodeGraph and EvidenceGraph operate together
- [x] Change-impact analysis safely avoids unnecessary full-suite work
- [ ] Security, mutation, fuzz, concurrency, UI, stress and fault-injection verification work end to end
- [x] Critical placeholders and fake-success implementations block certification
- [x] Every certification decision is auditable and reproducible
- [x] MIT core remains clean
- [ ] VerificationForge successfully certifies itself

## Verified implementation notes

The checked items above are backed by merged code and CI rather than roadmap intent alone. Rust, Python and Go now have native first-class adapters; the Go adapter performs native module detection, symbol inventory, build/type/vet/test/dependency/coverage/race verification, optional govulncheck integration, Go-specific advanced harness fallback, and placeholder/fake-authorization blocking. CI verifies a real Go module without any repository harness files and asserts a single native Go detection. Mixed-language verification, specification-to-obligation generation, graph primitives and evidence-gap queries, content-addressed snapshot/impact planning, resource-aware scheduling, risk-tier policy, evidence-backed PASS semantics, and the controlled development firewall are implemented in the workspace. The integrated verification graph validates requirement-to-symbol links and binds evidence to the exact linked implementation symbol and check; a requirement is only proven when every linked implementation symbol has reproducible passing evidence, while bare PASS values and failures remain non-proving records. Controlled-operation provenance telemetry records agent identity, requirement scope, files, symbols, exact commands, outcomes, evidence, fix attempts, regression tests and timing without exposing a mutable bypass around the firewall. The staged artifact provenance API enforces agent -> requirement -> patch -> verification -> commit -> build -> artifact ordering and gives each final chain a deterministic content address with artifact, requirement and commit traceability. The recoverable run supervisor persists task state and checkpoints atomically and distinguishes heartbeat loss (hang), continued-heartbeat/no-progress stalls, and dependency-cycle deadlocks. A separate adversarial-review contract can create additional verification obligations but intentionally has no PASS, acceptance or certification capability. The default repository-wide authenticity specialist runs at every verification level and blocks high-confidence unfinished/fake implementation patterns independently of language adapters; CI proves that a Go project with a successful build and passing tests is still rejected when its authorization decision is hardcoded, while VerificationForge's own embedded test-fixture source is not misclassified. The agent-facing development runtime owns the tracked controlled session, requires a non-empty requirement before build work, exposes no mutable inner-session escape, and routes repository mutation, development commands, tests, commits and certification requests through the firewall and telemetry; tests prove direct .git file mutation, evidence-free commits and commits with active engine blockers are rejected. The strict content-addressed PatchGate composes repository snapshots, changed-path and dependency-cone impact analysis, parse/format/build/type/lint checks, secret and authenticity specialists, and impact-targeted tests; Unsupported required phases and bare PASS values fail closed. Rust supplies native parse/format and Cargo-package-targeted test execution with safe full-workspace fallback when impact cannot be mapped. CI exercises the Patch gate with real temporary Rust packages and proves both that a clean mapped patch is accepted and that a patch whose build and targeted tests pass is still rejected when it introduces a hardcoded credential. The compositional CheckpointGate requires PatchGate acceptance first, then affected integration and property verification, repository security, dependency verification, and explicit UI/API applicability outcomes. Native Rust maps affected paths to Cargo packages, requires real integration and property coverage for affected Rust packages, permits non-applicable skips only through explicit adapter outcomes, and fails closed when an affected UI/API surface lacks a checkpoint harness. CI proves a real Rust checkpoint with integration/property coverage is accepted and separately proves that ordinary PatchGate and integration tests can pass while CheckpointGate still rejects the change when property verification disappears. Generic fallback profiles remain available for many other ecosystems and require real per-language harness evidence rather than fabricating PASS. Items remain unchecked when only part of the compound requirement exists; complete per-operation resource observability, shared/distributed cache, remote isolation backends, comprehensive fake-implementation semantics, and the remaining commit/certification adversarial suites are still incomplete.

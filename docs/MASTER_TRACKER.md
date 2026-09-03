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
- [ ] Patch gate: parse, format, build/type/lint, secrets, placeholders, impact analysis and targeted tests
- [ ] Checkpoint gate: affected integration/property/security/dependency/UI/API verification
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
- [ ] Go
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
- [ ] Agents build through controlled mutation interfaces
- [x] RequirementGraph, CodeGraph and EvidenceGraph operate together
- [x] Change-impact analysis safely avoids unnecessary full-suite work
- [ ] Security, mutation, fuzz, concurrency, UI, stress and fault-injection verification work end to end
- [ ] Critical placeholders and fake-success implementations block certification
- [x] Every certification decision is auditable and reproducible
- [x] MIT core remains clean
- [ ] VerificationForge successfully certifies itself

## Verified implementation notes

The checked items above are backed by merged code and CI rather than roadmap intent alone. Rust/Python mixed-language verification, specification-to-obligation generation, graph primitives and evidence-gap queries, content-addressed snapshot/impact planning, resource-aware scheduling, risk-tier policy, evidence-backed PASS semantics, and the controlled development firewall are implemented in the workspace. The integrated verification graph validates requirement-to-symbol links and binds evidence to the exact linked implementation symbol and check; a requirement is only proven when every linked implementation symbol has reproducible passing evidence, while bare PASS values and failures remain non-proving records. Controlled-operation provenance telemetry records agent identity, requirement scope, files, symbols, exact commands, outcomes, evidence, fix attempts, regression tests and timing without exposing a mutable bypass around the firewall. The staged artifact provenance API enforces agent -> requirement -> patch -> verification -> commit -> build -> artifact ordering and gives each final chain a deterministic content address with artifact, requirement and commit traceability. The recoverable run supervisor persists task state and checkpoints atomically and distinguishes heartbeat loss (hang), continued-heartbeat/no-progress stalls, and dependency-cycle deadlocks. A separate adversarial-review contract can create additional verification obligations but intentionally has no PASS, acceptance or certification capability. A real Go repository also verifies through the generic fallback adapter and per-language argv harness without core-engine modification, while missing harnesses fail closed. Items remain unchecked when only part of the compound requirement exists; for example, fallback profiles are not claimed as native first-class language adapters, complete per-operation resource observability is not yet implemented, and shared/distributed cache and remote isolation backends remain incomplete.

# VerificationForge Master Tracker

This is the canonical capability roadmap. It intentionally describes required capabilities rather than naming external products or projects.

## Foundation
- [ ] Public MIT governance, contribution, security, and architecture documentation
- [ ] Generic LanguageAdapter, ToolchainAdapter, ExecutionAdapter and specialist verification adapter interfaces
- [ ] Automatic language, framework, build-system, package-manager, test-system, UI, API, database, smart-contract, shader and infrastructure detection
- [ ] Mixed-language repository support

## Before-code verification
- [ ] Executable requirements, features, functions, interfaces, UI controls, inputs/outputs, preconditions, postconditions, invariants, error behavior, security/authorization rules, persistence, performance/resource limits, concurrency, state machines, compatibility, accessibility and reliability rules
- [ ] Convert specifications into verification obligations before implementation exists
- [ ] Design-level state exploration, reachability, invariant checking, distributed/concurrent modeling, architecture policy checks and threat modeling

## Graph model
- [ ] RequirementGraph for intended behavior and requirement relationships
- [ ] Universal CodeGraph for repositories, packages, modules, files, types, functions, calls, variables, imports, control/data flow, dependencies, APIs, UI controls, databases, processes, network/filesystem/native/security boundaries and concurrency primitives
- [ ] EvidenceGraph linking requirement -> implementation -> verification evidence -> artifact
- [ ] Queries for orphaned requirements, unrequested implementation, weakly proven code and stale evidence

## Scheduling and execution
- [ ] Content-addressed inputs/results
- [ ] Fine-grained changed-symbol and dependency-cone impact analysis
- [ ] Local/shared/distributed caches with safe invalidation
- [ ] Local, sandbox, container, VM, remote-runner and distributed execution backends
- [ ] Resource-aware scheduling
- [ ] Durable checkpoints, heartbeats and hang/stall/deadlock detection

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
- [ ] Controlled read/write/patch/delete/rename/dependency/command/test/commit/certification operations
- [ ] Track agent identity, requirement, files, symbols, commands, results, fix attempts and regression tests
- [ ] Agents cannot self-declare PASS
- [ ] Adversarial semantic reviewers create verification obligations but cannot grant certification

## Interchange, provenance and observability
- [ ] Standard machine-readable import/export for findings, tests, coverage, component/dependency inventories, vulnerabilities, provenance, API/event/RPC contracts, traces, metrics and logs
- [ ] Provenance chain: agent -> requirement -> patch -> verification -> commit -> build -> artifact
- [ ] Per-operation timestamps, duration, progress, inputs/outputs, resource use, checkpoints and heartbeat

## Language and ecosystem expansion
- [ ] Rust
- [ ] Python
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
- [ ] Configurable risk-tier policy engine
- [ ] Mandatory thresholds for functionality, symbols, tests, coverage, mutation, fuzz, security, concurrency, placeholders, UI, performance, resilience, dependency health and formal proof where required
- [ ] Critical failures cannot be suppressed by ordinary agent actions
- [ ] Every PASS links to reproducible evidence rather than a bare boolean

## Self-verification
- [ ] VerificationForge runs its own specification, graphs, mutation, fuzz, security, concurrency, fault-injection and certification systems against itself
- [ ] Releases eventually require self-certification

## Production-capable definition
- [ ] Multiple unrelated languages verify without core modification
- [ ] Mixed-language repositories verify correctly
- [ ] Specifications create obligations before code
- [ ] Agents build through controlled mutation interfaces
- [ ] RequirementGraph, CodeGraph and EvidenceGraph operate together
- [ ] Change-impact analysis safely avoids unnecessary full-suite work
- [ ] Security, mutation, fuzz, concurrency, UI, stress and fault-injection verification work end to end
- [ ] Critical placeholders and fake-success implementations block certification
- [ ] Every certification decision is auditable and reproducible
- [ ] MIT core remains clean
- [ ] VerificationForge successfully certifies itself
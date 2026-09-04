# VerificationForge

<!-- VERIFICATIONFORGE_BOOTSTRAP_VERSION=1 -->

VerificationForge is a public, MIT-licensed, language-agnostic software verification runtime designed to act as a development firewall for humans and coding agents.

Its core rule is simple: **a PASS is not trusted unless it is backed by reproducible evidence**. VerificationForge converts requirements into verification obligations, detects what changed, verifies the affected behavior through progressively deeper gates, and blocks certification when required evidence is missing, unsupported, stale, nondeterministic, or contradicted by a critical finding.

## Current status

VerificationForge has a working Rust orchestration core, generic adapter interfaces, mixed-language verification, requirement/code/evidence graphs, content-addressed change-impact planning, resource-aware scheduling, controlled agent operations, strict Patch/Checkpoint/Commit/Certification gates, provenance, checkpoints, and evidence-backed certification semantics.

Repository self-certification is implemented on the current v1 finish branch. The self-certification path runs VerificationForge against its own repository with repository-owned mutation, fuzz/property, concurrency, stress, fault-injection, resource-leak, security/history, sandbox-containment, dependency, reproducibility, and repository-stability workloads. These workloads are real and fail closed, but they do **not** mean that every language or ecosystem already has deep native support for every certification phase.

The canonical source of truth for completion state is [`docs/MASTER_TRACKER.md`](docs/MASTER_TRACKER.md). The tracker is intentionally conservative: implemented code is not marked complete until the relevant evidence and CI coverage justify the claim.

## Architecture

- **Rust orchestration core** with dependency-injected language, toolchain, execution, and specialist-verification adapters.
- **Generic adapters** keep language-specific behavior outside the verification engine.
- **RequirementGraph** represents intended behavior and requirement relationships.
- **Universal CodeGraph** represents repositories, packages, modules, symbols, calls, data/dependency relationships, APIs, UI controls, databases, processes, filesystem/network/native/security boundaries, and concurrency primitives.
- **EvidenceGraph** links requirements to implementation symbols, verification evidence, and artifacts.
- **Content-addressed scheduling** binds work to exact repository inputs and supports fine-grained change-impact analysis.
- **Resource-aware execution** prevents verification plans from ignoring declared CPU, memory, and execution constraints.
- **Recoverable checkpoints and heartbeats** support auditability plus hang, stall, and deadlock detection.
- **Controlled development firewall** tracks agent identity, requirement scope, files, symbols, commands, results, fix attempts, regression tests, commits, and certification requests.
- **Deterministic evidence controls acceptance**; agents and semantic reviewers may create findings or obligations but cannot self-declare PASS.

## Verification gates

VerificationForge uses progressively deeper gates:

1. **PatchGate** — repository snapshot, impact analysis, parse/format/build/type/lint, hardcoded-secret and authenticity checks, and impact-targeted tests.
2. **CheckpointGate** — requires PatchGate acceptance, then affected integration/property/security/dependency checks and explicit UI/API applicability outcomes.
3. **CommitGate** — requires CheckpointGate acceptance, complete normal tests and coverage for detected languages, deterministic mutation/fuzz sampling, repository security evidence, and content-address stability.
4. **CertificationGate** — requires CommitGate acceptance, then declared full-mutation, extended-fuzz, concurrency, stress, fault-injection, resource-leak, UI-when-applicable, dependency/security/history, sandbox, reproducibility, and repository-stability evidence.

Required phases fail closed when their harness is missing, their evidence is incomplete, a declared workload is not fully accounted for, or a result is only a bare boolean without reproducible evidence.

## Implemented verification capabilities

Implemented core capabilities include:

- executable specification-to-obligation generation;
- mixed-language repository detection and verification;
- RequirementGraph, Universal CodeGraph, and EvidenceGraph integration;
- orphaned-requirement, weak-proof, stale-evidence, and implementation-coverage queries;
- content-addressed snapshots, deterministic work selection, and dependency-cone impact analysis;
- local memory/file-backed caching primitives;
- resource-aware scheduling and recoverable run supervision;
- strict Patch, Checkpoint, Commit, and Certification gates;
- deterministic mutation/fuzz harness protocols;
- repository-wide authenticity/fake-implementation checks;
- hardcoded-secret scanning, suspicious-trigger checks, and Git-history secret scanning;
- dependency/toolchain verification paths where adapters provide them;
- provenance from agent -> requirement -> patch -> verification -> commit -> build -> artifact;
- fail-closed handling for unsupported required verification;
- repository self-certification workloads for mutation, fuzz, concurrency, stress, fault injection, resource leakage, sandbox containment, reproducibility, and security/history checks.

## Language and source-family support

The core is language-agnostic; languages are adapters rather than engine assumptions.

### Tracker-verified first-class families

The canonical tracker currently marks these families complete:

- Rust and Python
- C, C++, and C#
- Assembly
- Java, Kotlin, and Scala
- Go
- JavaScript and TypeScript
- PHP
- Bash and PowerShell
- HTML
- CSS, SCSS, Sass, Less, and Stylus
- Markdown and MDX
- web templates and single-file-component source families

The web ecosystem specialist also inventories major JavaScript runtimes, package managers, UI frameworks, full-stack frameworks, server/API frameworks, build systems, monorepo tooling, test stacks, styling ecosystems, and deployment markers.

### Additional native adapters under Popular Language Family qualification

The repository also contains native adapters and real-toolchain fixture coverage for:

- Swift and Objective-C
- Dart
- Ruby, Lua, and Perl
- R and Julia
- Haskell and OCaml
- F#
- Elixir and Erlang
- Zig, Nim, and D
- Fortran and COBOL
- SQL
- HCL/Terraform
- Groovy and Clojure
- Visual Basic .NET
- Object Pascal/Delphi
- MATLAB/Octave
- Tcl
- Nix
- Gleam
- Ada

These are intentionally listed separately because adapter presence is not the same as tracker-certified completion. Their dedicated CI lane is the qualification boundary.

## Self-certification

The current v1 finish branch includes a strict `self_certify` runner and a dedicated GitHub Actions workflow.

The repository-owned self-certification workloads include:

- deterministic source mutation with zero-survivor accounting for the declared mutant set;
- seeded fuzz/property workloads;
- deterministic concurrency scheduling workloads;
- stress workloads;
- fault injection;
- resource-leak checks;
- current-tree security scanning;
- Git-history credential scanning with narrowly fingerprinted synthetic-fixture exceptions;
- kernel-enforced Bubblewrap filesystem containment on supported Linux CI runners;
- dependency verification;
- reproducibility checks;
- final repository-stability verification.

Self-certification is a real verification path, not a release-policy claim. The tracker still separately tracks whether all releases are required to self-certify.

## What is not complete yet

VerificationForge is deliberately not described as finished where the implementation is still partial. Major remaining areas include:

- automatic detection across every framework, build system, package manager, test system, UI, API, database, smart-contract, shader, and infrastructure ecosystem;
- shared/distributed caches and generic container/VM/remote/distributed execution backends;
- full generated-test synthesis from specifications, signatures, invariants, state machines, boundaries, and historical bugs;
- broad native coverage-guided fuzzing, shrinking, differential testing, and long-running soak campaigns across all adapters;
- deep race/deadlock/livelock/atomicity/cancellation/order/starvation verification across ecosystems;
- full static data-flow/taint analysis and broad authentication, authorization, injection, traversal, deserialization, crypto, permissions, network-exposure, supply-chain, vulnerability, and license verification;
- complete UI exploration and HTTP/event/RPC/streaming/WebSocket/CLI/IPC compatibility verification;
- formal/extreme tiers such as symbolic execution, constraint solving, model checking, proof harnesses, and counterexample generation;
- smart-contract adapters for Solidity, Vyper, Move, and Cairo;
- shader adapters for GLSL, HLSL, and WGSL;
- mandatory universal certification thresholds across functionality, coverage, mutation, fuzz, security, concurrency, UI, performance, resilience, dependencies, and formal proof.

## Workspace

The workspace is organized around a language-independent core plus native adapter families. Key components include:

- `verificationforge-core` — contracts, result types, graph primitives, adapter interfaces, evidence and policy types.
- `verificationforge-runtime` — registry, project detection, planning, execution, scheduling, gates, specialists, provenance, supervision, and certification.
- native adapter crates for Rust, Python, Go, C-family, JVM-family, JavaScript-family, script-family, web-family, Assembly, and additional language families.
- `verificationforge-cli` — command-line composition root and repository verification entry point.
- `docs/MASTER_TRACKER.md` — canonical capability roadmap and completion record.

## Build and test

```powershell
cargo fmt --all -- --check
cargo check --workspace --all-targets --locked
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace --all-targets --locked
cargo run -p verificationforge-cli -- .
```

## Repository self-certification

On a supported Linux environment with the required toolchains and Bubblewrap available:

```bash
cargo build -p verificationforge-cli --bin self_certify --locked
./target/debug/self_certify .
```

The GitHub Actions self-certification lane installs and runs the repository-specific prerequisites automatically.

## Design principles

- **Fail closed.** Unsupported required verification is not a PASS.
- **Evidence over assertions.** A boolean success flag is insufficient certification evidence.
- **Exact inputs matter.** Verification decisions are tied to content-addressed repository state.
- **Languages are plugins.** Adding a language should not require modifying the verification engine.
- **Agents cannot certify themselves.** Agent output may create work or evidence, but hardened gate logic controls acceptance.
- **Do not overclaim.** `docs/MASTER_TRACKER.md` is authoritative when implementation depth differs across capabilities or ecosystems.

## License

MIT. See [`LICENSE`](LICENSE).

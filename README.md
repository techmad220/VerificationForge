# VerificationForge

<!-- VERIFICATIONFORGE_BOOTSTRAP_VERSION=1 -->

VerificationForge is a public MIT-licensed, language-agnostic software verification runtime designed to act as a development firewall for humans and coding agents.

The core idea is simple: define executable requirements before implementation, route changes through controlled verification, determine exactly what changed, attack the affected behavior with multiple verification techniques, and only certify work when every PASS is backed by evidence.

## Locked architecture

- Rust orchestration core with dependency-injected adapters.
- Generic language and toolchain interfaces; languages are plugins, not core assumptions.
- Executable specifications and verification obligations can exist before source code.
- RequirementGraph tracks intended behavior.
- CodeGraph tracks implementation structure, calls, data flow, dependencies, UI/API/database/process/security boundaries.
- EvidenceGraph connects requirement -> implementation -> tests/checks -> artifact.
- Content-addressed scheduling and change-impact analysis minimize unnecessary reruns.
- Progressive gates run fast checks per patch and deeper mutation, fuzz, concurrency, stress, fault-injection, UI, security, and formal checks at higher certification levels.
- Placeholder, stub, fake-success, hardcoded-secret, suspicious-trigger, race/deadlock, security, and dead-UI findings can block certification.
- External analyzers are integrated through adapters/process boundaries so the MIT core remains clean.
- Every verification operation emits durable checkpoints and telemetry for auditability and hang detection.
- Agents may propose semantic findings but deterministic evidence controls certification.
- VerificationForge will eventually verify and certify itself.

## Language scope

The adapter model targets compiled, interpreted, scripting, systems, JVM/.NET, web, mobile, data, shell, smart-contract, shader, and legacy ecosystems. Initial adapters prove the abstraction with Rust and Python; the roadmap expands across C, C++, C#, Java, Kotlin, Scala, Go, JavaScript, TypeScript, Swift, Objective-C, Dart, PHP, Ruby, Lua, Perl, R, Julia, Haskell, OCaml, F#, Elixir, Erlang, Zig, Nim, D, Fortran, COBOL, Bash, PowerShell, SQL dialects, Solidity, Vyper, Move, Cairo, HTML/CSS, GLSL, HLSL, WGSL, and additional ecosystems through the same interface.

## Workspace

- `verificationforge-core`: contracts, result types, graph primitives, adapter interfaces.
- `verificationforge-runtime`: adapter registry, project detection, verification planning and execution.
- `verificationforge-adapter-rust`: initial Rust language adapter.
- `verificationforge-adapter-python`: initial Python language adapter.
- `verificationforge-cli`: command-line composition root.
- `docs/MASTER_TRACKER.md`: canonical implementation roadmap.

## Build

```powershell
cargo fmt --all -- --check
cargo check --workspace
cargo test --workspace
cargo run -p verificationforge-cli -- .
```

## License

MIT. See `LICENSE`.
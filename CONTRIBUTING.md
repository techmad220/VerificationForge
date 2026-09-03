# Contributing to VerificationForge

VerificationForge is an MIT-licensed verification runtime. Contributions must preserve its language-agnostic core and evidence-first certification model.

## Development requirements

- Use stable Rust and keep the workspace warning-free.
- Do not add language-specific behavior to the verification engine when it belongs in an adapter.
- Do not introduce fake PASS states, placeholders, TODO implementations, disabled validation, or hardcoded test-only success paths.
- Every new verification capability must produce reproducible evidence or an explicit unsupported/failure result.
- Security-sensitive changes must fail closed.
- Keep external analyzers behind adapter/process boundaries so their licenses do not contaminate the MIT core.

## Required local verification

Run before opening a pull request:

```bash
cargo fmt --all -- --check
cargo check --workspace --all-targets --locked
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace --all-targets --locked
cargo run -p verificationforge-cli -- . --level patch --risk low
```

The final command must report `VERIFICATIONFORGE_BARE_PASSES=0` and `VERIFICATIONFORGE_ACCEPTED=true` for a clean repository.

## Architecture rules

1. Core contracts live in `verificationforge-core`.
2. Runtime orchestration belongs in `verificationforge-runtime`.
3. Language integrations implement `LanguageAdapter` and related adapter contracts.
4. Specialist verification engines implement `SpecialistVerificationAdapter` or remain behind a process/service adapter.
5. Execution must flow through `ExecutionAdapter`; do not build shell command strings where argv can remain structured.
6. Agent-driven repository changes must use the controlled development boundary rather than mutating `.git` or escaping the repository root.
7. Certification decisions are policy- and evidence-driven. An agent or reviewer may create findings or obligations but cannot self-declare certification.

## Pull requests

Keep each pull request cohesive. Include the requirement or tracker item being advanced, the verification performed, and any known unsupported cases. CI is mandatory; do not merge a red verification run.

## Tests

Add regression tests for every bug fix and focused tests for every new policy boundary. Prefer deterministic fixtures. Tests must exercise failure paths as well as success paths.

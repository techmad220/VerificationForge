# Security Policy

## Supported versions

VerificationForge is currently developed on the `main` branch. Security fixes are applied to `main` first. Until versioned releases are published, older commits are not maintained as separate supported release lines.

## Reporting a vulnerability

Do not publish exploitable details in a public issue. Use GitHub's private vulnerability reporting for this repository when available. If private reporting is unavailable, contact the repository owner privately through an account-associated channel and provide enough information to reproduce the issue.

Include:

- affected commit or version;
- threat model and impact;
- minimal reproduction steps;
- whether repository boundary escape, command execution, evidence forgery, certification bypass, secret exposure, or dependency/supply-chain compromise is involved;
- any proposed mitigation.

## Security invariants

VerificationForge treats these as critical boundaries:

- repository-scoped file operations must reject absolute paths, traversal, symlink escapes, and direct `.git` mutation;
- commands must preserve executable and argv separation through `ExecutionAdapter`;
- certification requires policy approval and reproducible evidence;
- blocking findings cannot be converted to PASS by an ordinary agent action;
- security checks fail closed when required evidence is missing;
- external tools remain isolated behind adapters/process boundaries.

A regression in these invariants is considered security-sensitive even when no immediate exploit has been demonstrated.

## Disclosure

After a fix is available and users have a reasonable upgrade path, maintainers may publish a concise advisory describing affected versions, impact, remediation, and credit where appropriate.

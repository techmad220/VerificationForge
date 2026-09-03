# VerificationForge Governance

VerificationForge uses maintainer-led governance with evidence-backed technical decisions.

## Maintainer authority

Repository maintainers are responsible for scope, releases, security response, merge policy, and architectural compatibility. Maintainer authority does not override verification policy: a change that fails required deterministic gates is not considered certified simply because a maintainer approves it.

## Decision principles

Technical decisions prioritize, in order:

1. correctness and reproducible evidence;
2. security and fail-closed behavior;
3. language-agnostic architecture and adapter isolation;
4. deterministic, auditable behavior;
5. practical performance and resource efficiency;
6. backward compatibility where it does not compromise the above.

## Changes

Normal changes are proposed through pull requests. Significant architecture changes should explain the affected contracts, compatibility impact, verification evidence, and migration path. New external verification engines should be integrated through adapters or process/service boundaries unless there is a compelling reason to change core contracts.

## Releases

A release candidate must pass the repository's required CI and the applicable VerificationForge certification policy. As self-verification matures, release policy will be tightened until self-certification is mandatory.

## Security

Security-sensitive fixes may use a private disclosure path and may be merged with reduced public discussion when disclosure before remediation would increase risk. Required deterministic verification still applies.

## Project scope

The MIT core remains a general verification runtime. Product-specific, proprietary, or incompatibly licensed engines belong outside the core and communicate through stable extension boundaries.

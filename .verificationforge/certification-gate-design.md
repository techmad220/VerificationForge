# CertificationGate evidence protocol

CertificationGate is a fail-closed composition over CommitGate. Repository-level certification harnesses are exact argv files under `.verificationforge/` and must consume the content-addressed `{seed}` and declared `{iterations}` placeholders.

Required harnesses:

- `certification-full-mutation.argv`: must execute the complete declared mutant set and emit `VF_CERT_FULL_MUTATION_TOTAL=<n>` with `n >= 1` and `VF_CERT_FULL_MUTATION_SURVIVED=0`.
- `certification-extended-fuzz.argv`: must execute at least the requested iterations and emit `VF_CERT_FUZZ_ITERATIONS=<n>`.
- `certification-concurrency.argv`: required only when the UniversalCodeGraph contains concurrency primitives; must emit `VF_CERT_CONCURRENCY_CASES=<n>` with `n >= 1`.
- `certification-stress.argv`: must emit `VF_CERT_STRESS_ITERATIONS=<n>` meeting the requested workload.
- `certification-fault-injection.argv`: must emit `VF_CERT_FAULT_CASES=<n>` with `n >= 1`.
- `certification-resource-leaks.argv`: must emit `VF_CERT_RESOURCE_LEAKS=0`.
- `certification-ui.argv`: required only when the UniversalCodeGraph contains UI controls; must emit `VF_CERT_UI_CONTROLS=<n>` with `n >= 1` and `VF_CERT_UI_FAILURES=0`.
- `certification-sandbox.argv`: must exercise the repository's sandbox/containment contract and emit `VF_CERT_SANDBOX_ESCAPE=0`.
- `certification-reproducibility.argv`: executed twice with identical content-addressed inputs; both executions must succeed, produce byte-identical stdout/stderr, and emit `VF_CERT_REPRODUCIBLE=1`.

In addition, CertificationGate requires dependency checks for every detected language, repository security specialist evidence, Git-history security scanning, and a final repository content-address stability proof. Missing harnesses, missing evidence metrics, unsupported required checks, surviving mutants, sandbox escapes, historical hardcoded credentials, or non-reproducible output block certification.

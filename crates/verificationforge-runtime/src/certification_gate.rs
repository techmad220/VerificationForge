use std::path::Path;

use verificationforge_core::{
    CheckKind, CheckResult, CheckStatus, CodeNodeKind, ExecutionResult, UniversalCodeGraph,
};

use crate::{CommitGate, CommitGateReport, ContentAddress, RepositorySnapshot, VerificationEngine};

const EXTENDED_FUZZ_ITERATIONS: usize = 16_384;
const STRESS_ITERATIONS: usize = 4_096;
const FAULT_INJECTION_ITERATIONS: usize = 256;
const RESOURCE_LEAK_ITERATIONS: usize = 1_024;
const CONCURRENCY_ITERATIONS: usize = 2_048;
const UI_ITERATIONS: usize = 256;
const SANDBOX_ITERATIONS: usize = 64;
const REPRODUCIBILITY_ITERATIONS: usize = 2;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum CertificationGatePhase {
    FullMutation,
    ExtendedFuzz,
    Concurrency,
    Stress,
    FaultInjection,
    ResourceLeaks,
    UiExploration,
    Dependencies,
    Security,
    HistorySecurity,
    Sandbox,
    Reproducibility,
    RepositoryStability,
}

impl CertificationGatePhase {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::FullMutation => "full-mutation",
            Self::ExtendedFuzz => "extended-fuzz",
            Self::Concurrency => "concurrency",
            Self::Stress => "stress",
            Self::FaultInjection => "fault-injection",
            Self::ResourceLeaks => "resource-leaks",
            Self::UiExploration => "ui",
            Self::Dependencies => "dependencies",
            Self::Security => "security",
            Self::HistorySecurity => "history-security",
            Self::Sandbox => "sandbox",
            Self::Reproducibility => "reproducibility",
            Self::RepositoryStability => "repository-stability",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CertificationWorkPlan {
    pub phase: CertificationGatePhase,
    pub seed: ContentAddress,
    pub iterations: usize,
}

#[derive(Debug, Clone)]
pub struct CertificationGateEntry {
    pub phase: CertificationGatePhase,
    pub adapter_id: String,
    pub language: String,
    pub result: CheckResult,
}

#[derive(Debug, Clone)]
pub struct CertificationGateReport {
    pub commit: CommitGateReport,
    pub repository_address: Option<ContentAddress>,
    pub work_plans: Vec<CertificationWorkPlan>,
    pub entries: Vec<CertificationGateEntry>,
    pub accepted: bool,
}

pub struct CertificationGate;

impl CertificationGate {
    pub fn verify(
        engine: &VerificationEngine,
        repo: &Path,
        baseline: &RepositorySnapshot,
        graph: &UniversalCodeGraph,
    ) -> Result<CertificationGateReport, String> {
        let commit = CommitGate::verify(engine, repo, baseline, graph)?;
        if !commit.accepted {
            return Ok(CertificationGateReport {
                commit,
                repository_address: None,
                work_plans: Vec::new(),
                entries: Vec::new(),
                accepted: false,
            });
        }

        let before = RepositorySnapshot::capture(repo)?;
        let repository_address = before
            .address
            .clone()
            .ok_or_else(|| "certification snapshot is missing its content address".to_owned())?;

        let mut entries = Vec::new();
        let mut work_plans = Vec::new();

        for (phase, iterations) in [
            (CertificationGatePhase::FullMutation, 1),
            (
                CertificationGatePhase::ExtendedFuzz,
                EXTENDED_FUZZ_ITERATIONS,
            ),
            (CertificationGatePhase::Stress, STRESS_ITERATIONS),
            (
                CertificationGatePhase::FaultInjection,
                FAULT_INJECTION_ITERATIONS,
            ),
            (
                CertificationGatePhase::ResourceLeaks,
                RESOURCE_LEAK_ITERATIONS,
            ),
            (CertificationGatePhase::Sandbox, SANDBOX_ITERATIONS),
        ] {
            let plan = work_plan(&repository_address, phase, iterations);
            let result = run_certification_harness(engine, repo, &plan);
            work_plans.push(plan);
            entries.push(runtime_entry(phase, result));
        }

        let has_concurrency = graph
            .nodes
            .values()
            .any(|node| node.kind == CodeNodeKind::ConcurrencyPrimitive);
        if has_concurrency {
            let plan = work_plan(
                &repository_address,
                CertificationGatePhase::Concurrency,
                CONCURRENCY_ITERATIONS,
            );
            let result = run_certification_harness(engine, repo, &plan);
            work_plans.push(plan);
            entries.push(runtime_entry(CertificationGatePhase::Concurrency, result));
        } else {
            entries.push(runtime_entry(
                CertificationGatePhase::Concurrency,
                CheckResult::skipped(
                    "certification:concurrency",
                    "UniversalCodeGraph contains no concurrency primitives; race/concurrency exploration is not applicable",
                ),
            ));
        }

        let has_ui = graph
            .nodes
            .values()
            .any(|node| node.kind == CodeNodeKind::UiControl);
        if has_ui {
            let plan = work_plan(
                &repository_address,
                CertificationGatePhase::UiExploration,
                UI_ITERATIONS,
            );
            let result = run_certification_harness(engine, repo, &plan);
            work_plans.push(plan);
            entries.push(runtime_entry(CertificationGatePhase::UiExploration, result));
        } else {
            entries.push(runtime_entry(
                CertificationGatePhase::UiExploration,
                CheckResult::skipped(
                    "certification:ui",
                    "UniversalCodeGraph contains no UI controls; full UI exploration is not applicable",
                ),
            ));
        }

        for detection in &commit.checkpoint.patch.detections {
            let Some(adapter) = engine.registry.adapter(&detection.adapter_id) else {
                entries.push(CertificationGateEntry {
                    phase: CertificationGatePhase::Dependencies,
                    adapter_id: detection.adapter_id.clone(),
                    language: detection.language.clone(),
                    result: CheckResult::fail(
                        "certification:adapter-resolution",
                        "VF_ADAPTER_MISSING",
                        format!(
                            "detected adapter {} is no longer registered",
                            detection.adapter_id
                        ),
                    ),
                });
                continue;
            };
            entries.push(CertificationGateEntry {
                phase: CertificationGatePhase::Dependencies,
                adapter_id: detection.adapter_id.clone(),
                language: detection.language.clone(),
                result: adapter.run_check(CheckKind::Dependencies, repo, engine.execution.as_ref()),
            });
        }

        for specialist in &engine.registry.specialists {
            if specialist.supports(CheckKind::Security) {
                entries.push(CertificationGateEntry {
                    phase: CertificationGatePhase::Security,
                    adapter_id: specialist.id().into(),
                    language: "repository".into(),
                    result: specialist.run_check(
                        CheckKind::Security,
                        repo,
                        engine.execution.as_ref(),
                    ),
                });
            }
        }
        if !entries
            .iter()
            .any(|entry| entry.phase == CertificationGatePhase::Security)
        {
            entries.push(runtime_entry(
                CertificationGatePhase::Security,
                CheckResult::fail(
                    "certification:security",
                    "VF_CERT_SECURITY_MISSING",
                    "certification requires at least one repository security specialist",
                ),
            ));
        }

        entries.push(runtime_entry(
            CertificationGatePhase::HistorySecurity,
            run_history_security(engine, repo),
        ));

        let reproducibility_plan = work_plan(
            &repository_address,
            CertificationGatePhase::Reproducibility,
            REPRODUCIBILITY_ITERATIONS,
        );
        let reproducibility = run_reproducibility_harness(engine, repo, &reproducibility_plan);
        work_plans.push(reproducibility_plan);
        entries.push(runtime_entry(
            CertificationGatePhase::Reproducibility,
            reproducibility,
        ));

        let after = RepositorySnapshot::capture(repo)?;
        let stability = if after.address.as_ref() == Some(&repository_address) {
            CheckResult::pass_with_evidence(
                "certification:repository-stability",
                format!(
                    "repository content address remained stable during certification address={}",
                    repository_address.0
                ),
            )
        } else {
            CheckResult::fail(
                "certification:repository-stability",
                "VF_CERT_REPOSITORY_MUTATED",
                format!(
                    "repository changed while certification was running before={} after={}",
                    repository_address.0,
                    after
                        .address
                        .as_ref()
                        .map(|address| address.0.as_str())
                        .unwrap_or("<missing>")
                ),
            )
        };
        entries.push(runtime_entry(
            CertificationGatePhase::RepositoryStability,
            stability,
        ));

        let accepted = entries.iter().all(certification_entry_accepts);
        Ok(CertificationGateReport {
            commit,
            repository_address: Some(repository_address),
            work_plans,
            entries,
            accepted,
        })
    }
}

fn runtime_entry(phase: CertificationGatePhase, result: CheckResult) -> CertificationGateEntry {
    CertificationGateEntry {
        phase,
        adapter_id: "runtime".into(),
        language: "repository".into(),
        result,
    }
}

fn work_plan(
    repository_address: &ContentAddress,
    phase: CertificationGatePhase,
    iterations: usize,
) -> CertificationWorkPlan {
    CertificationWorkPlan {
        phase,
        seed: ContentAddress::combine([
            &b"verificationforge-certification-v1"[..],
            repository_address.0.as_bytes(),
            phase.as_str().as_bytes(),
        ]),
        iterations,
    }
}

fn run_certification_harness(
    engine: &VerificationEngine,
    repo: &Path,
    plan: &CertificationWorkPlan,
) -> CheckResult {
    let check_name = format!("certification:{}", plan.phase.as_str());
    let relative = format!(
        ".verificationforge/certification-{}.argv",
        plan.phase.as_str()
    );
    let rendered = match render_harness(repo, &relative, plan) {
        Ok(rendered) => rendered,
        Err(result) => return result,
    };
    let program = &rendered[0];
    let args = &rendered[1..];
    match engine.execution.execute(program, args, repo) {
        Ok(output) if output.success() => {
            validate_phase_output(&check_name, &relative, plan, output)
        }
        Ok(output) => CheckResult::fail(
            check_name,
            "VF_CERT_HARNESS_FAILED",
            format!(
                "harness {relative} seed={} iterations={} command={} {} exited with code {}: {}",
                plan.seed.0,
                plan.iterations,
                program,
                args.join(" "),
                output.exit_code,
                command_detail(&output)
            ),
        ),
        Err(error) => CheckResult::fail(
            check_name,
            "VF_CERT_HARNESS_EXECUTION_FAILED",
            format!("cannot execute {relative}: {error}"),
        ),
    }
}

fn render_harness(
    repo: &Path,
    relative: &str,
    plan: &CertificationWorkPlan,
) -> Result<Vec<String>, CheckResult> {
    let check_name = format!("certification:{}", plan.phase.as_str());
    let path = repo.join(relative);
    if !path.is_file() {
        return Err(CheckResult::unsupported(
            check_name,
            format!(
                "required certification harness is missing: {relative}; it must consume {{seed}} and {{iterations}}"
            ),
        ));
    }
    let content = std::fs::read_to_string(&path).map_err(|error| {
        CheckResult::fail(
            check_name.clone(),
            "VF_CERT_HARNESS_READ_FAILED",
            format!("cannot read {relative}: {error}"),
        )
    })?;
    let raw = content
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty() && !line.starts_with('#'))
        .map(str::to_owned)
        .collect::<Vec<_>>();
    if raw.is_empty() {
        return Err(CheckResult::fail(
            check_name,
            "VF_CERT_HARNESS_EMPTY",
            format!("{relative} contains no executable command"),
        ));
    }
    for required in ["{seed}", "{iterations}"] {
        if !raw.iter().any(|value| value.contains(required)) {
            return Err(CheckResult::fail(
                check_name,
                "VF_CERT_HARNESS_NONDETERMINISTIC",
                format!(
                    "{relative} must consume deterministic placeholder {required}; required placeholders are {{seed}} and {{iterations}}"
                ),
            ));
        }
    }
    let iterations = plan.iterations.to_string();
    Ok(raw
        .iter()
        .map(|value| {
            value
                .replace("{seed}", &plan.seed.0)
                .replace("{iterations}", &iterations)
        })
        .collect())
}

fn validate_phase_output(
    check_name: &str,
    relative: &str,
    plan: &CertificationWorkPlan,
    output: ExecutionResult,
) -> CheckResult {
    let required = match plan.phase {
        CertificationGatePhase::FullMutation => vec![
            RequiredMetric::Minimum("VF_CERT_FULL_MUTATION_TOTAL", 1),
            RequiredMetric::Exact("VF_CERT_FULL_MUTATION_SURVIVED", 0),
        ],
        CertificationGatePhase::ExtendedFuzz => vec![RequiredMetric::Minimum(
            "VF_CERT_FUZZ_ITERATIONS",
            plan.iterations,
        )],
        CertificationGatePhase::Concurrency => {
            vec![RequiredMetric::Minimum("VF_CERT_CONCURRENCY_CASES", 1)]
        }
        CertificationGatePhase::Stress => vec![RequiredMetric::Minimum(
            "VF_CERT_STRESS_ITERATIONS",
            plan.iterations,
        )],
        CertificationGatePhase::FaultInjection => {
            vec![RequiredMetric::Minimum("VF_CERT_FAULT_CASES", 1)]
        }
        CertificationGatePhase::ResourceLeaks => {
            vec![RequiredMetric::Exact("VF_CERT_RESOURCE_LEAKS", 0)]
        }
        CertificationGatePhase::UiExploration => vec![
            RequiredMetric::Minimum("VF_CERT_UI_CONTROLS", 1),
            RequiredMetric::Exact("VF_CERT_UI_FAILURES", 0),
        ],
        CertificationGatePhase::Sandbox => {
            vec![RequiredMetric::Exact("VF_CERT_SANDBOX_ESCAPE", 0)]
        }
        CertificationGatePhase::Reproducibility
        | CertificationGatePhase::Dependencies
        | CertificationGatePhase::Security
        | CertificationGatePhase::HistorySecurity
        | CertificationGatePhase::RepositoryStability => Vec::new(),
    };

    for metric in required {
        if let Err(message) = metric.validate(&output.stdout) {
            return CheckResult::fail(
                check_name,
                "VF_CERT_EVIDENCE_PROTOCOL",
                format!("{relative}: {message}"),
            );
        }
    }

    CheckResult::pass_with_evidence(
        check_name,
        format!(
            "harness={relative} seed={} iterations={} exit=0 metrics={}",
            plan.seed.0,
            plan.iterations,
            output
                .stdout
                .lines()
                .filter(|line| line.trim().starts_with("VF_CERT_"))
                .collect::<Vec<_>>()
                .join(";")
        ),
    )
}

#[derive(Debug, Clone, Copy)]
enum RequiredMetric {
    Exact(&'static str, usize),
    Minimum(&'static str, usize),
}

impl RequiredMetric {
    fn validate(self, stdout: &str) -> Result<(), String> {
        let (key, expected, exact) = match self {
            Self::Exact(key, expected) => (key, expected, true),
            Self::Minimum(key, expected) => (key, expected, false),
        };
        let value = metric_value(stdout, key)
            .ok_or_else(|| format!("missing required evidence metric {key}=<integer>"))?;
        if exact && value != expected {
            return Err(format!("{key} must equal {expected}, got {value}"));
        }
        if !exact && value < expected {
            return Err(format!("{key} must be at least {expected}, got {value}"));
        }
        Ok(())
    }
}

fn metric_value(stdout: &str, key: &str) -> Option<usize> {
    stdout.lines().find_map(|line| {
        let line = line.trim();
        let value = line.strip_prefix(key)?.strip_prefix('=')?;
        value.trim().parse::<usize>().ok()
    })
}

fn run_reproducibility_harness(
    engine: &VerificationEngine,
    repo: &Path,
    plan: &CertificationWorkPlan,
) -> CheckResult {
    let check_name = "certification:reproducibility";
    let relative = ".verificationforge/certification-reproducibility.argv";
    let rendered = match render_harness(repo, relative, plan) {
        Ok(rendered) => rendered,
        Err(result) => return result,
    };
    let program = &rendered[0];
    let args = &rendered[1..];
    let first = match engine.execution.execute(program, args, repo) {
        Ok(output) => output,
        Err(error) => {
            return CheckResult::fail(
                check_name,
                "VF_CERT_REPRO_EXECUTION_FAILED",
                format!("first reproducibility execution failed: {error}"),
            );
        }
    };
    let second = match engine.execution.execute(program, args, repo) {
        Ok(output) => output,
        Err(error) => {
            return CheckResult::fail(
                check_name,
                "VF_CERT_REPRO_EXECUTION_FAILED",
                format!("second reproducibility execution failed: {error}"),
            );
        }
    };
    if !first.success() || !second.success() {
        return CheckResult::fail(
            check_name,
            "VF_CERT_REPRO_FAILED",
            format!(
                "reproducibility harness must succeed twice; first={} second={} first-detail={} second-detail={}",
                first.exit_code,
                second.exit_code,
                command_detail(&first),
                command_detail(&second)
            ),
        );
    }
    if first.stdout != second.stdout || first.stderr != second.stderr {
        return CheckResult::fail(
            check_name,
            "VF_CERT_NONREPRODUCIBLE",
            "identical content-addressed reproducibility executions produced different output",
        );
    }
    if metric_value(&first.stdout, "VF_CERT_REPRODUCIBLE") != Some(1) {
        return CheckResult::fail(
            check_name,
            "VF_CERT_EVIDENCE_PROTOCOL",
            "reproducibility harness must emit VF_CERT_REPRODUCIBLE=1",
        );
    }
    CheckResult::pass_with_evidence(
        check_name,
        format!(
            "harness={relative} seed={} identical-runs=2 output={}",
            plan.seed.0,
            first.stdout.trim().chars().take(1000).collect::<String>()
        ),
    )
}

fn run_history_security(engine: &VerificationEngine, repo: &Path) -> CheckResult {
    let check_name = "certification:history-security";
    let rev_parse = vec!["rev-parse".to_owned(), "--is-inside-work-tree".to_owned()];
    match engine.execution.execute("git", &rev_parse, repo) {
        Ok(output) if output.success() && output.stdout.trim() == "true" => {}
        Ok(output) => {
            return CheckResult::unsupported(
                check_name,
                format!(
                    "Git history is required for certification history scanning: {}",
                    command_detail(&output)
                ),
            );
        }
        Err(error) => {
            return CheckResult::unsupported(
                check_name,
                format!("Git history is required for certification history scanning: {error}"),
            );
        }
    }

    let args = vec![
        "log".to_owned(),
        "--all".to_owned(),
        "--format=commit:%H".to_owned(),
        "-p".to_owned(),
        "--no-ext-diff".to_owned(),
        "--no-color".to_owned(),
        "--".to_owned(),
        ".".to_owned(),
    ];
    let output = match engine.execution.execute("git", &args, repo) {
        Ok(output) if output.success() => output,
        Ok(output) => {
            return CheckResult::fail(
                check_name,
                "VF_CERT_HISTORY_SCAN_FAILED",
                format!("git history scan failed: {}", command_detail(&output)),
            );
        }
        Err(error) => {
            return CheckResult::fail(check_name, "VF_CERT_HISTORY_SCAN_FAILED", error);
        }
    };

    let mut commits = 0usize;
    let mut additions = 0usize;
    for line in output.stdout.lines() {
        if line.starts_with("commit:") {
            commits += 1;
            continue;
        }
        if !line.starts_with('+') || line.starts_with("+++") {
            continue;
        }
        additions += 1;
        let normalized = line[1..]
            .chars()
            .filter(|character| !character.is_whitespace())
            .collect::<String>()
            .to_ascii_lowercase();
        if looks_like_hardcoded_secret(&normalized) {
            return CheckResult::fail(
                check_name,
                "VF_CERT_HISTORY_SECRET",
                "repository history contains a high-confidence hardcoded credential assignment",
            );
        }
    }

    CheckResult::pass_with_evidence(
        check_name,
        format!("git history security scan commits={commits} added-lines={additions} secrets=0"),
    )
}

fn looks_like_hardcoded_secret(line: &str) -> bool {
    let sensitive = [
        "password=\"",
        "passwd=\"",
        "api_key=\"",
        "apikey=\"",
        "access_token=\"",
        "secret_key=\"",
        "client_secret=\"",
    ];
    sensitive.iter().any(|marker| {
        line.find(marker).is_some_and(|index| {
            let value = &line[index + marker.len()..];
            value
                .split('"')
                .next()
                .is_some_and(|candidate| candidate.len() >= 8)
        })
    })
}

fn command_detail(output: &ExecutionResult) -> String {
    let detail = if output.stderr.trim().is_empty() {
        output.stdout.trim()
    } else {
        output.stderr.trim()
    };
    detail.chars().take(4000).collect()
}

fn certification_entry_accepts(entry: &CertificationGateEntry) -> bool {
    match entry.result.status {
        CheckStatus::Pass => {
            entry.result.has_reproducible_evidence() && !entry.result.has_blocking_finding()
        }
        CheckStatus::Skipped => matches!(
            entry.phase,
            CertificationGatePhase::Concurrency | CertificationGatePhase::UiExploration
        ),
        CheckStatus::Fail | CheckStatus::Unsupported => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::path::PathBuf;
    use std::sync::Arc;
    use std::time::{SystemTime, UNIX_EPOCH};

    use verificationforge_core::{
        CodeNode, ExecutionAdapter, ImpactScope, LanguageAdapter, LanguageDetection, SymbolId,
    };

    use crate::AdapterRegistry;

    struct DemoAdapter;

    impl LanguageAdapter for DemoAdapter {
        fn id(&self) -> &'static str {
            "demo"
        }

        fn detect(&self, _repo: &Path) -> Option<LanguageDetection> {
            Some(LanguageDetection {
                adapter_id: "demo".into(),
                language: "Demo".into(),
                confidence_percent: 100,
            })
        }

        fn run_check(
            &self,
            check: CheckKind,
            _repo: &Path,
            _execution: &dyn ExecutionAdapter,
        ) -> CheckResult {
            if check == CheckKind::TypeCheck {
                return CheckResult::skipped("demo:type-check", "build includes type checking");
            }
            CheckResult::pass_with_evidence(
                format!("demo:{}", check.as_str()),
                format!("demo {} evidence", check.as_str()),
            )
        }

        fn run_parse_check(&self, _repo: &Path, _execution: &dyn ExecutionAdapter) -> CheckResult {
            CheckResult::pass_with_evidence("demo:parse", "parse evidence")
        }

        fn run_format_check(&self, _repo: &Path, _execution: &dyn ExecutionAdapter) -> CheckResult {
            CheckResult::pass_with_evidence("demo:format", "format evidence")
        }

        fn run_targeted_tests(
            &self,
            _repo: &Path,
            _execution: &dyn ExecutionAdapter,
            _scope: &ImpactScope,
        ) -> CheckResult {
            CheckResult::pass_with_evidence("demo:targeted-test", "targeted evidence")
        }

        fn run_integration_tests(
            &self,
            _repo: &Path,
            _execution: &dyn ExecutionAdapter,
            _scope: &ImpactScope,
        ) -> CheckResult {
            CheckResult::pass_with_evidence("demo:checkpoint-integration", "integration evidence")
        }

        fn run_property_tests(
            &self,
            _repo: &Path,
            _execution: &dyn ExecutionAdapter,
            _scope: &ImpactScope,
        ) -> CheckResult {
            CheckResult::pass_with_evidence("demo:checkpoint-property", "property evidence")
        }

        fn run_ui_verification(
            &self,
            _repo: &Path,
            _execution: &dyn ExecutionAdapter,
            _scope: &ImpactScope,
        ) -> CheckResult {
            CheckResult::skipped("demo:checkpoint-ui", "no UI")
        }

        fn run_api_verification(
            &self,
            _repo: &Path,
            _execution: &dyn ExecutionAdapter,
            _scope: &ImpactScope,
        ) -> CheckResult {
            CheckResult::skipped("demo:checkpoint-api", "no API")
        }
    }

    struct RecordingExecution;

    impl ExecutionAdapter for RecordingExecution {
        fn id(&self) -> &'static str {
            "recording"
        }

        fn execute(
            &self,
            program: &str,
            args: &[String],
            _cwd: &Path,
        ) -> Result<ExecutionResult, String> {
            if program == "git" && args.first().is_some_and(|arg| arg == "rev-parse") {
                return Ok(ExecutionResult {
                    exit_code: 0,
                    stdout: "true\n".into(),
                    stderr: String::new(),
                });
            }
            if program == "git" && args.first().is_some_and(|arg| arg == "log") {
                return Ok(ExecutionResult {
                    exit_code: 0,
                    stdout: "commit:abc\n+pub fn clean() {}\n".into(),
                    stderr: String::new(),
                });
            }
            let phase = args.first().map(String::as_str).unwrap_or_default();
            let stdout = match phase {
                "full-mutation" => {
                    "VF_CERT_FULL_MUTATION_TOTAL=7\nVF_CERT_FULL_MUTATION_SURVIVED=0\n"
                }
                "extended-fuzz" => "VF_CERT_FUZZ_ITERATIONS=16384\n",
                "concurrency" => "VF_CERT_CONCURRENCY_CASES=2048\n",
                "stress" => "VF_CERT_STRESS_ITERATIONS=4096\n",
                "fault-injection" => "VF_CERT_FAULT_CASES=32\n",
                "resource-leaks" => "VF_CERT_RESOURCE_LEAKS=0\n",
                "ui" => "VF_CERT_UI_CONTROLS=4\nVF_CERT_UI_FAILURES=0\n",
                "sandbox" => "VF_CERT_SANDBOX_ESCAPE=0\n",
                "reproducibility" => "VF_CERT_REPRODUCIBLE=1\nartifact=stable\n",
                _ => "ok\n",
            };
            Ok(ExecutionResult {
                exit_code: 0,
                stdout: stdout.into(),
                stderr: String::new(),
            })
        }
    }

    fn temp_dir(name: &str) -> PathBuf {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock before epoch")
            .as_nanos();
        std::env::temp_dir().join(format!("verificationforge-cert-{name}-{nonce}"))
    }

    fn write_harness(repo: &Path, name: &str) {
        fs::write(
            repo.join(format!(".verificationforge/certification-{name}.argv")),
            format!("cert-tool\n{name}\n{{seed}}\n{{iterations}}\n"),
        )
        .expect("write certification harness");
    }

    fn fixture(
        with_ui: bool,
        with_concurrency: bool,
    ) -> (
        PathBuf,
        RepositorySnapshot,
        UniversalCodeGraph,
        VerificationEngine,
    ) {
        let repo = temp_dir("repo");
        fs::create_dir_all(repo.join(".verificationforge")).expect("create harness directory");
        fs::write(repo.join("service.demo"), "before").expect("write baseline");
        for name in [
            "commit-mutation",
            "commit-fuzz",
            "certification-full-mutation",
            "certification-extended-fuzz",
            "certification-stress",
            "certification-fault-injection",
            "certification-resource-leaks",
            "certification-sandbox",
            "certification-reproducibility",
        ] {
            let content = if let Some(phase) = name.strip_prefix("commit-") {
                format!(
                    "cert-tool\n{phase}\n{{seed}}\n{{selections}}\n{{iterations}}\n"
                )
            } else {
                let phase = name.trim_start_matches("certification-");
                format!("cert-tool\n{phase}\n{{seed}}\n{{iterations}}\n")
            };
            fs::write(
                repo.join(format!(".verificationforge/{name}.argv")),
                content,
            )
            .expect("write gate harness");
        }
        if with_ui {
            write_harness(&repo, "ui");
        }
        if with_concurrency {
            write_harness(&repo, "concurrency");
        }
        let baseline = RepositorySnapshot::capture(&repo).expect("capture baseline");
        fs::write(repo.join("service.demo"), "after").expect("write current");

        let mut graph = UniversalCodeGraph::default();
        graph.add_node(CodeNode {
            id: SymbolId("demo:file:service".into()),
            kind: CodeNodeKind::File,
            language: Some("Demo".into()),
            path: Some("service.demo".into()),
            display_name: "service".into(),
        });
        if with_ui {
            graph.add_node(CodeNode {
                id: SymbolId("demo:ui:button".into()),
                kind: CodeNodeKind::UiControl,
                language: Some("Demo".into()),
                path: Some("service.demo".into()),
                display_name: "button".into(),
            });
        }
        if with_concurrency {
            graph.add_node(CodeNode {
                id: SymbolId("demo:concurrency:worker".into()),
                kind: CodeNodeKind::ConcurrencyPrimitive,
                language: Some("Demo".into()),
                path: Some("service.demo".into()),
                display_name: "worker".into(),
            });
        }

        let mut registry = AdapterRegistry::default();
        registry.register(Arc::new(DemoAdapter));
        let engine = VerificationEngine::new(registry, Arc::new(RecordingExecution));
        (repo, baseline, graph, engine)
    }

    #[test]
    fn certification_composes_commit_and_requires_deep_adversarial_phases() {
        let (repo, baseline, graph, engine) = fixture(true, true);
        let report = CertificationGate::verify(&engine, &repo, &baseline, &graph)
            .expect("certification should run");
        assert!(report.commit.accepted);
        assert!(report.accepted);
        for phase in [
            CertificationGatePhase::FullMutation,
            CertificationGatePhase::ExtendedFuzz,
            CertificationGatePhase::Concurrency,
            CertificationGatePhase::Stress,
            CertificationGatePhase::FaultInjection,
            CertificationGatePhase::ResourceLeaks,
            CertificationGatePhase::UiExploration,
            CertificationGatePhase::Dependencies,
            CertificationGatePhase::Security,
            CertificationGatePhase::HistorySecurity,
            CertificationGatePhase::Sandbox,
            CertificationGatePhase::Reproducibility,
            CertificationGatePhase::RepositoryStability,
        ] {
            assert!(report.entries.iter().any(|entry| {
                entry.phase == phase
                    && (entry.result.status == CheckStatus::Pass
                        || entry.result.status == CheckStatus::Skipped)
            }));
        }
        fs::remove_dir_all(repo).ok();
    }

    #[test]
    fn absent_ui_and_concurrency_are_explicit_non_applicable_outcomes() {
        let (repo, baseline, graph, engine) = fixture(false, false);
        let report = CertificationGate::verify(&engine, &repo, &baseline, &graph)
            .expect("certification should run");
        assert!(report.accepted);
        assert!(report.entries.iter().any(|entry| {
            entry.phase == CertificationGatePhase::UiExploration
                && entry.result.status == CheckStatus::Skipped
        }));
        assert!(report.entries.iter().any(|entry| {
            entry.phase == CertificationGatePhase::Concurrency
                && entry.result.status == CheckStatus::Skipped
        }));
        fs::remove_dir_all(repo).ok();
    }

    #[test]
    fn missing_required_full_mutation_harness_blocks_certification() {
        let (repo, baseline, graph, engine) = fixture(false, false);
        fs::remove_file(repo.join(".verificationforge/certification-full-mutation.argv"))
            .expect("remove full mutation harness");
        let report = CertificationGate::verify(&engine, &repo, &baseline, &graph)
            .expect("certification should run");
        assert!(!report.accepted);
        assert!(report.entries.iter().any(|entry| {
            entry.phase == CertificationGatePhase::FullMutation
                && entry.result.status == CheckStatus::Unsupported
        }));
        fs::remove_dir_all(repo).ok();
    }

    #[test]
    fn history_secret_classifier_blocks_literal_credentials_only() {
        assert!(looks_like_hardcoded_secret(
            "letpassword=\"supersecret123\";"
        ));
        assert!(!looks_like_hardcoded_secret(
            "letpassword=env::var(\"PASSWORD\");"
        ));
    }
}

use std::fs;
use std::path::Path;

use verificationforge_core::{
    CheckKind, CheckResult, CheckStatus, LanguageDetection, UniversalCodeGraph,
};

use crate::{
    CheckpointGate, CheckpointGateReport, ContentAddress, RepositorySnapshot, VerificationEngine,
};

const MUTATION_SELECTIONS: usize = 8;
const MUTATION_ITERATIONS_PER_SELECTION: usize = 1;
const FUZZ_SELECTIONS: usize = 2;
const FUZZ_ITERATIONS_PER_SELECTION: usize = 256;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum CommitGatePhase {
    NormalTests,
    Coverage,
    MutationSample,
    FuzzSample,
    Security,
    RepositoryStability,
}

impl CommitGatePhase {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::NormalTests => "normal-tests",
            Self::Coverage => "coverage",
            Self::MutationSample => "mutation-sample",
            Self::FuzzSample => "fuzz-sample",
            Self::Security => "security",
            Self::RepositoryStability => "repository-stability",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeterministicSamplePlan {
    pub seed: ContentAddress,
    pub selections: usize,
    pub iterations_per_selection: usize,
}

#[derive(Debug, Clone)]
pub struct CommitGateEntry {
    pub phase: CommitGatePhase,
    pub adapter_id: String,
    pub language: String,
    pub result: CheckResult,
}

#[derive(Debug, Clone)]
pub struct CommitGateReport {
    pub checkpoint: CheckpointGateReport,
    pub repository_address: Option<ContentAddress>,
    pub mutation_plan: Option<DeterministicSamplePlan>,
    pub fuzz_plan: Option<DeterministicSamplePlan>,
    pub entries: Vec<CommitGateEntry>,
    pub accepted: bool,
}

pub struct CommitGate;

impl CommitGate {
    pub fn verify(
        engine: &VerificationEngine,
        repo: &Path,
        baseline: &RepositorySnapshot,
        graph: &UniversalCodeGraph,
    ) -> Result<CommitGateReport, String> {
        let checkpoint = CheckpointGate::verify(engine, repo, baseline, graph)?;
        if !checkpoint.accepted {
            return Ok(CommitGateReport {
                checkpoint,
                repository_address: None,
                mutation_plan: None,
                fuzz_plan: None,
                entries: Vec::new(),
                accepted: false,
            });
        }

        let before = RepositorySnapshot::capture(repo)?;
        let repository_address = before
            .address
            .clone()
            .ok_or_else(|| "commit snapshot is missing its content address".to_owned())?;
        let mutation_plan = sample_plan(
            &repository_address,
            CommitGatePhase::MutationSample,
            MUTATION_SELECTIONS,
            MUTATION_ITERATIONS_PER_SELECTION,
        );
        let fuzz_plan = sample_plan(
            &repository_address,
            CommitGatePhase::FuzzSample,
            FUZZ_SELECTIONS,
            FUZZ_ITERATIONS_PER_SELECTION,
        );

        let mut entries = Vec::new();
        for detection in &checkpoint.patch.detections {
            let Some(adapter) = engine.registry.adapter(&detection.adapter_id) else {
                entries.push(CommitGateEntry {
                    phase: CommitGatePhase::NormalTests,
                    adapter_id: detection.adapter_id.clone(),
                    language: detection.language.clone(),
                    result: CheckResult::fail(
                        "commit:adapter-resolution",
                        "VF_ADAPTER_MISSING",
                        format!(
                            "detected adapter {} is no longer registered",
                            detection.adapter_id
                        ),
                    ),
                });
                continue;
            };

            push(
                &mut entries,
                CommitGatePhase::NormalTests,
                detection,
                adapter.run_check(CheckKind::Test, repo, engine.execution.as_ref()),
            );
            push(
                &mut entries,
                CommitGatePhase::Coverage,
                detection,
                adapter.run_check(CheckKind::Coverage, repo, engine.execution.as_ref()),
            );
        }

        entries.push(CommitGateEntry {
            phase: CommitGatePhase::MutationSample,
            adapter_id: "runtime".into(),
            language: "repository".into(),
            result: run_deterministic_sample_harness(
                engine,
                repo,
                CommitGatePhase::MutationSample,
                "commit-mutation",
                &mutation_plan,
            ),
        });
        entries.push(CommitGateEntry {
            phase: CommitGatePhase::FuzzSample,
            adapter_id: "runtime".into(),
            language: "repository".into(),
            result: run_deterministic_sample_harness(
                engine,
                repo,
                CommitGatePhase::FuzzSample,
                "commit-fuzz",
                &fuzz_plan,
            ),
        });

        for specialist in &engine.registry.specialists {
            if specialist.supports(CheckKind::Security) {
                entries.push(CommitGateEntry {
                    phase: CommitGatePhase::Security,
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
            .any(|entry| entry.phase == CommitGatePhase::Security)
        {
            entries.push(CommitGateEntry {
                phase: CommitGatePhase::Security,
                adapter_id: "runtime".into(),
                language: "repository".into(),
                result: CheckResult::fail(
                    "commit:security",
                    "VF_COMMIT_SECURITY_MISSING",
                    "commit verification requires at least one repository security specialist",
                ),
            });
        }

        let after = RepositorySnapshot::capture(repo)?;
        let stability = if after.address.as_ref() == Some(&repository_address) {
            CheckResult::pass_with_evidence(
                "commit:repository-stability",
                format!(
                    "repository content address remained stable during commit verification address={}",
                    repository_address.0
                ),
            )
        } else {
            CheckResult::fail(
                "commit:repository-stability",
                "VF_COMMIT_REPOSITORY_MUTATED",
                format!(
                    "repository changed while commit verification was running before={} after={}",
                    repository_address.0,
                    after
                        .address
                        .as_ref()
                        .map(|address| address.0.as_str())
                        .unwrap_or("<missing>")
                ),
            )
        };
        entries.push(CommitGateEntry {
            phase: CommitGatePhase::RepositoryStability,
            adapter_id: "runtime".into(),
            language: "repository".into(),
            result: stability,
        });

        let accepted = entries.iter().all(commit_entry_accepts);
        Ok(CommitGateReport {
            checkpoint,
            repository_address: Some(repository_address),
            mutation_plan: Some(mutation_plan),
            fuzz_plan: Some(fuzz_plan),
            entries,
            accepted,
        })
    }
}

fn sample_plan(
    repository_address: &ContentAddress,
    phase: CommitGatePhase,
    selections: usize,
    iterations_per_selection: usize,
) -> DeterministicSamplePlan {
    let seed = ContentAddress::combine([
        &b"verificationforge-commit-sample-v1"[..],
        repository_address.0.as_bytes(),
        phase.as_str().as_bytes(),
    ]);
    DeterministicSamplePlan {
        seed,
        selections,
        iterations_per_selection,
    }
}

fn run_deterministic_sample_harness(
    engine: &VerificationEngine,
    repo: &Path,
    phase: CommitGatePhase,
    harness_name: &str,
    plan: &DeterministicSamplePlan,
) -> CheckResult {
    let check_name = format!("commit:{}", phase.as_str());
    let relative = format!(".verificationforge/{harness_name}.argv");
    let path = repo.join(&relative);
    if !path.is_file() {
        return CheckResult::unsupported(
            check_name,
            format!(
                "deterministic {} requires {relative}; the harness must consume {{seed}}, {{selections}}, and {{iterations}}",
                phase.as_str()
            ),
        );
    }

    let content = match fs::read_to_string(&path) {
        Ok(content) => content,
        Err(error) => {
            return CheckResult::fail(
                check_name,
                "VF_COMMIT_HARNESS_READ_FAILED",
                format!("cannot read {relative}: {error}"),
            );
        }
    };
    let raw = content
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty() && !line.starts_with('#'))
        .map(str::to_owned)
        .collect::<Vec<_>>();
    if raw.is_empty() {
        return CheckResult::fail(
            check_name,
            "VF_COMMIT_HARNESS_EMPTY",
            format!("{relative} contains no executable command"),
        );
    }

    for required in ["{seed}", "{selections}", "{iterations}"] {
        if !raw.iter().any(|value| value.contains(required)) {
            return CheckResult::fail(
                check_name,
                "VF_COMMIT_SAMPLE_NONDETERMINISTIC",
                format!(
                    "{relative} must consume deterministic placeholder {required}; required placeholders are {{seed}}, {{selections}}, and {{iterations}}"
                ),
            );
        }
    }

    let selections = plan.selections.to_string();
    let iterations = plan.iterations_per_selection.to_string();
    let rendered = raw
        .iter()
        .map(|value| {
            value
                .replace("{seed}", &plan.seed.0)
                .replace("{selections}", &selections)
                .replace("{iterations}", &iterations)
        })
        .collect::<Vec<_>>();
    let program = &rendered[0];
    let args = &rendered[1..];

    match engine.execution.execute(program, args, repo) {
        Ok(output) if output.success() => CheckResult::pass_with_evidence(
            check_name,
            format!(
                "harness={relative} seed={} selections={} iterations-per-selection={} command={} {} exit=0",
                plan.seed.0,
                plan.selections,
                plan.iterations_per_selection,
                program,
                args.join(" ")
            ),
        ),
        Ok(output) => CheckResult::fail(
            check_name,
            "VF_COMMIT_SAMPLE_FAILED",
            format!(
                "harness {relative} seed={} selections={} iterations-per-selection={} command={} {} exited with code {}: {}",
                plan.seed.0,
                plan.selections,
                plan.iterations_per_selection,
                program,
                args.join(" "),
                output.exit_code,
                command_detail(&output)
            ),
        ),
        Err(error) => CheckResult::fail(
            check_name,
            "VF_COMMIT_SAMPLE_EXECUTION_FAILED",
            format!("cannot execute {relative}: {error}"),
        ),
    }
}

fn command_detail(output: &verificationforge_core::ExecutionResult) -> String {
    let detail = if output.stderr.trim().is_empty() {
        output.stdout.trim()
    } else {
        output.stderr.trim()
    };
    detail.chars().take(4000).collect()
}

fn push(
    entries: &mut Vec<CommitGateEntry>,
    phase: CommitGatePhase,
    detection: &LanguageDetection,
    result: CheckResult,
) {
    entries.push(CommitGateEntry {
        phase,
        adapter_id: detection.adapter_id.clone(),
        language: detection.language.clone(),
        result,
    });
}

fn commit_entry_accepts(entry: &CommitGateEntry) -> bool {
    entry.result.status == CheckStatus::Pass
        && entry.result.has_reproducible_evidence()
        && !entry.result.has_blocking_finding()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::path::PathBuf;
    use std::sync::{Arc, Mutex};
    use std::time::{SystemTime, UNIX_EPOCH};

    use verificationforge_core::{
        CodeNode, CodeNodeKind, ExecutionAdapter, ExecutionResult, ImpactScope, LanguageAdapter,
        SymbolId,
    };

    use crate::AdapterRegistry;

    struct DemoAdapter {
        property_supported: bool,
    }

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
            if self.property_supported {
                CheckResult::pass_with_evidence("demo:checkpoint-property", "property evidence")
            } else {
                CheckResult::unsupported(
                    "demo:checkpoint-property",
                    "property verification unavailable",
                )
            }
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

    #[derive(Default)]
    struct RecordingExecution {
        calls: Mutex<Vec<(String, Vec<String>)>>,
    }

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
            self.calls
                .lock()
                .expect("calls lock poisoned")
                .push((program.into(), args.to_vec()));
            Ok(ExecutionResult {
                exit_code: 0,
                stdout: String::new(),
                stderr: String::new(),
            })
        }
    }

    fn temp_dir(name: &str) -> PathBuf {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock before epoch")
            .as_nanos();
        std::env::temp_dir().join(format!("verificationforge-commit-{name}-{nonce}"))
    }

    fn fixture(
        property_supported: bool,
    ) -> (
        PathBuf,
        RepositorySnapshot,
        UniversalCodeGraph,
        VerificationEngine,
        Arc<RecordingExecution>,
    ) {
        let repo = temp_dir("repo");
        fs::create_dir_all(repo.join(".verificationforge")).expect("create harness directory");
        fs::write(repo.join("service.demo"), "before").expect("write baseline");
        fs::write(
            repo.join(".verificationforge/commit-mutation.argv"),
            "sample-tool\nmutation\n{seed}\n{selections}\n{iterations}\n",
        )
        .expect("write mutation harness");
        fs::write(
            repo.join(".verificationforge/commit-fuzz.argv"),
            "sample-tool\nfuzz\n{seed}\n{selections}\n{iterations}\n",
        )
        .expect("write fuzz harness");
        let baseline = RepositorySnapshot::capture(&repo).expect("capture baseline");
        fs::write(repo.join("service.demo"), "after").expect("write current");

        let mut graph = UniversalCodeGraph::default();
        graph.add_node(CodeNode {
            id: SymbolId("demo:function:service".into()),
            kind: CodeNodeKind::Function,
            language: Some("Demo".into()),
            path: Some("service.demo".into()),
            display_name: "service".into(),
        });

        let execution = Arc::new(RecordingExecution::default());
        let mut registry = AdapterRegistry::default();
        registry.register(Arc::new(DemoAdapter { property_supported }));
        let engine = VerificationEngine::new(registry, execution.clone());
        (repo, baseline, graph, engine, execution)
    }

    #[test]
    fn commit_composes_checkpoint_and_requires_all_deep_phases() {
        let (repo, baseline, graph, engine, _) = fixture(true);
        let report =
            CommitGate::verify(&engine, &repo, &baseline, &graph).expect("commit gate should run");

        assert!(report.checkpoint.accepted);
        assert!(report.accepted);
        for phase in [
            CommitGatePhase::NormalTests,
            CommitGatePhase::Coverage,
            CommitGatePhase::MutationSample,
            CommitGatePhase::FuzzSample,
            CommitGatePhase::Security,
            CommitGatePhase::RepositoryStability,
        ] {
            assert!(
                report.entries.iter().any(|entry| {
                    entry.phase == phase
                        && entry.result.status == CheckStatus::Pass
                        && entry.result.has_reproducible_evidence()
                }),
                "required commit phase {phase:?} must pass with evidence"
            );
        }

        fs::remove_dir_all(repo).ok();
    }

    #[test]
    fn deterministic_sample_plans_are_content_addressed() {
        let (repo, baseline, graph, engine, execution) = fixture(true);
        let first =
            CommitGate::verify(&engine, &repo, &baseline, &graph).expect("first commit gate run");
        let second =
            CommitGate::verify(&engine, &repo, &baseline, &graph).expect("second commit gate run");

        assert_eq!(first.repository_address, second.repository_address);
        assert_eq!(first.mutation_plan, second.mutation_plan);
        assert_eq!(first.fuzz_plan, second.fuzz_plan);

        let first_seed = first
            .mutation_plan
            .as_ref()
            .expect("first mutation plan")
            .seed
            .clone();
        fs::write(repo.join("service.demo"), "after-v2").expect("change repository");
        let third =
            CommitGate::verify(&engine, &repo, &baseline, &graph).expect("third commit gate run");
        assert_ne!(
            first_seed,
            third
                .mutation_plan
                .as_ref()
                .expect("third mutation plan")
                .seed
        );

        let calls = execution.calls.lock().expect("calls lock poisoned");
        assert!(calls.iter().any(|(program, args)| {
            program == "sample-tool"
                && args.first().is_some_and(|value| value == "mutation")
                && args.iter().any(|value| value == &first_seed.0)
        }));

        fs::remove_dir_all(repo).ok();
    }

    #[test]
    fn missing_or_nondeterministic_sampling_harness_blocks_commit() {
        let (repo, baseline, graph, engine, _) = fixture(true);
        fs::remove_file(repo.join(".verificationforge/commit-mutation.argv"))
            .expect("remove mutation harness");
        let missing =
            CommitGate::verify(&engine, &repo, &baseline, &graph).expect("commit gate should run");
        assert!(!missing.accepted);
        assert!(missing.entries.iter().any(|entry| {
            entry.phase == CommitGatePhase::MutationSample
                && entry.result.status == CheckStatus::Unsupported
        }));

        fs::write(
            repo.join(".verificationforge/commit-mutation.argv"),
            "sample-tool\nmutation\n{selections}\n{iterations}\n",
        )
        .expect("write nondeterministic mutation harness");
        let nondeterministic =
            CommitGate::verify(&engine, &repo, &baseline, &graph).expect("commit gate should run");
        assert!(!nondeterministic.accepted);
        assert!(nondeterministic.entries.iter().any(|entry| {
            entry.phase == CommitGatePhase::MutationSample
                && entry.result.status == CheckStatus::Fail
                && entry
                    .result
                    .findings
                    .iter()
                    .any(|finding| finding.code == "VF_COMMIT_SAMPLE_NONDETERMINISTIC")
        }));

        fs::remove_dir_all(repo).ok();
    }

    #[test]
    fn failed_checkpoint_short_circuits_commit_phases() {
        let (repo, baseline, graph, engine, _) = fixture(false);
        let report =
            CommitGate::verify(&engine, &repo, &baseline, &graph).expect("commit gate should run");
        assert!(!report.checkpoint.accepted);
        assert!(!report.accepted);
        assert!(report.entries.is_empty());
        assert!(report.repository_address.is_none());
        assert!(report.mutation_plan.is_none());
        assert!(report.fuzz_plan.is_none());
        fs::remove_dir_all(repo).ok();
    }
}

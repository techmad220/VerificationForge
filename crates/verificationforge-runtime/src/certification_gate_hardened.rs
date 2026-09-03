use std::path::Path;

use verificationforge_core::{CheckResult, CheckStatus, Finding, UniversalCodeGraph};

use crate::{
    certification_gate as legacy, ContentAddress, RepositorySnapshot, VerificationEngine,
};

pub struct CertificationGate;

impl CertificationGate {
    pub fn verify(
        engine: &VerificationEngine,
        repo: &Path,
        baseline: &RepositorySnapshot,
        graph: &UniversalCodeGraph,
    ) -> Result<legacy::CertificationGateReport, String> {
        let mut report = legacy::CertificationGate::verify(engine, repo, baseline, graph)?;
        harden_acceptance(&mut report);
        Ok(report)
    }
}

fn harden_acceptance(report: &mut legacy::CertificationGateReport) {
    if !report.commit.accepted {
        return;
    }

    let plans = report.work_plans.clone();
    let mut blocked = false;
    for entry in &mut report.entries {
        if entry.result.status != CheckStatus::Pass || !requires_declared_workload(entry.phase) {
            continue;
        }
        let plan = plans.iter().find(|plan| plan.phase == entry.phase);
        if let Err(message) = validate_declared_workload(entry.phase, &entry.result, plan) {
            entry.result.status = CheckStatus::Fail;
            entry.result.findings.push(Finding {
                code: "VF_CERT_WORKLOAD_INCOMPLETE".into(),
                message,
                blocking: true,
            });
            blocked = true;
        }
    }

    if blocked {
        report.accepted = false;
    }
}

fn requires_declared_workload(phase: legacy::CertificationGatePhase) -> bool {
    matches!(
        phase,
        legacy::CertificationGatePhase::FullMutation
            | legacy::CertificationGatePhase::ExtendedFuzz
            | legacy::CertificationGatePhase::Concurrency
            | legacy::CertificationGatePhase::Stress
            | legacy::CertificationGatePhase::FaultInjection
            | legacy::CertificationGatePhase::ResourceLeaks
            | legacy::CertificationGatePhase::UiExploration
            | legacy::CertificationGatePhase::Sandbox
    )
}

fn validate_declared_workload(
    phase: legacy::CertificationGatePhase,
    result: &CheckResult,
    plan: Option<&legacy::CertificationWorkPlan>,
) -> Result<(), String> {
    let plan = plan.ok_or_else(|| {
        format!(
            "certification phase {} passed without a content-addressed work plan",
            phase.as_str()
        )
    })?;

    match phase {
        legacy::CertificationGatePhase::FullMutation => {
            let total = required_metric(result, "VF_CERT_FULL_MUTATION_TOTAL")?;
            let discovered = required_metric(result, "VF_CERT_FULL_MUTATION_DISCOVERED")?;
            let executed = required_metric(result, "VF_CERT_FULL_MUTATION_EXECUTED")?;
            let survived = required_metric(result, "VF_CERT_FULL_MUTATION_SURVIVED")?;
            if total == 0 {
                return Err("full mutation reported zero discovered mutants".into());
            }
            if discovered != total {
                return Err(format!(
                    "full mutation total/discovered mismatch: total={total} discovered={discovered}"
                ));
            }
            if executed != discovered {
                return Err(format!(
                    "full mutation did not execute the complete discovered set: discovered={discovered} executed={executed}"
                ));
            }
            if survived != 0 {
                return Err(format!(
                    "full mutation has surviving mutants: survived={survived}"
                ));
            }
        }
        legacy::CertificationGatePhase::ExtendedFuzz => require_at_least(
            result,
            "VF_CERT_FUZZ_ITERATIONS",
            plan.iterations,
        )?,
        legacy::CertificationGatePhase::Concurrency => require_at_least(
            result,
            "VF_CERT_CONCURRENCY_CASES",
            plan.iterations,
        )?,
        legacy::CertificationGatePhase::Stress => require_at_least(
            result,
            "VF_CERT_STRESS_ITERATIONS",
            plan.iterations,
        )?,
        legacy::CertificationGatePhase::FaultInjection => require_at_least(
            result,
            "VF_CERT_FAULT_CASES",
            plan.iterations,
        )?,
        legacy::CertificationGatePhase::ResourceLeaks => {
            require_at_least(result, "VF_CERT_RESOURCE_SAMPLES", plan.iterations)?;
            require_exact(result, "VF_CERT_RESOURCE_LEAKS", 0)?;
        }
        legacy::CertificationGatePhase::UiExploration => {
            require_at_least(result, "VF_CERT_UI_CONTROLS", 1)?;
            require_at_least(result, "VF_CERT_UI_INTERACTIONS", plan.iterations)?;
            require_exact(result, "VF_CERT_UI_FAILURES", 0)?;
        }
        legacy::CertificationGatePhase::Sandbox => {
            require_at_least(result, "VF_CERT_SANDBOX_CASES", plan.iterations)?;
            require_exact(result, "VF_CERT_SANDBOX_ESCAPE", 0)?;
        }
        legacy::CertificationGatePhase::Dependencies
        | legacy::CertificationGatePhase::Security
        | legacy::CertificationGatePhase::HistorySecurity
        | legacy::CertificationGatePhase::Reproducibility
        | legacy::CertificationGatePhase::RepositoryStability => {}
    }
    Ok(())
}

fn require_at_least(result: &CheckResult, key: &str, expected: usize) -> Result<(), String> {
    let actual = required_metric(result, key)?;
    if actual < expected {
        return Err(format!(
            "{key} must cover the declared workload of at least {expected}, got {actual}"
        ));
    }
    Ok(())
}

fn require_exact(result: &CheckResult, key: &str, expected: usize) -> Result<(), String> {
    let actual = required_metric(result, key)?;
    if actual != expected {
        return Err(format!("{key} must equal {expected}, got {actual}"));
    }
    Ok(())
}

fn required_metric(result: &CheckResult, key: &str) -> Result<usize, String> {
    metric_value(result, key).ok_or_else(|| {
        format!(
            "missing required certification evidence metric {key}=<integer> for complete workload proof"
        )
    })
}

fn metric_value(result: &CheckResult, key: &str) -> Option<usize> {
    result.findings.iter().find_map(|finding| {
        finding.message.split(|character: char| {
            character.is_ascii_whitespace() || character == ';'
        })
        .find_map(|token| {
            let token = token.strip_prefix("metrics=").unwrap_or(token);
            let value = token.strip_prefix(key)?.strip_prefix('=')?;
            value.parse::<usize>().ok()
        })
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{CertificationGatePhase, CertificationWorkPlan};

    fn plan(phase: CertificationGatePhase, iterations: usize) -> CertificationWorkPlan {
        CertificationWorkPlan {
            phase,
            seed: ContentAddress("test-seed".into()),
            iterations,
        }
    }

    #[test]
    fn full_mutation_requires_the_complete_discovered_set() {
        let phase = CertificationGatePhase::FullMutation;
        let complete = CheckResult::pass_with_evidence(
            "certification:full-mutation",
            "metrics=VF_CERT_FULL_MUTATION_TOTAL=7;VF_CERT_FULL_MUTATION_DISCOVERED=7;VF_CERT_FULL_MUTATION_EXECUTED=7;VF_CERT_FULL_MUTATION_SURVIVED=0",
        );
        assert!(validate_declared_workload(phase, &complete, Some(&plan(phase, 1))).is_ok());

        let partial = CheckResult::pass_with_evidence(
            "certification:full-mutation",
            "metrics=VF_CERT_FULL_MUTATION_TOTAL=7;VF_CERT_FULL_MUTATION_DISCOVERED=7;VF_CERT_FULL_MUTATION_EXECUTED=6;VF_CERT_FULL_MUTATION_SURVIVED=0",
        );
        assert!(validate_declared_workload(phase, &partial, Some(&plan(phase, 1))).is_err());
    }

    #[test]
    fn declared_iteration_phases_cannot_underreport_work() {
        let cases = [
            (CertificationGatePhase::ExtendedFuzz, "VF_CERT_FUZZ_ITERATIONS"),
            (CertificationGatePhase::Concurrency, "VF_CERT_CONCURRENCY_CASES"),
            (CertificationGatePhase::Stress, "VF_CERT_STRESS_ITERATIONS"),
            (CertificationGatePhase::FaultInjection, "VF_CERT_FAULT_CASES"),
        ];
        for (phase, key) in cases {
            let result = CheckResult::pass_with_evidence(
                format!("certification:{}", phase.as_str()),
                format!("metrics={key}=9"),
            );
            assert!(validate_declared_workload(phase, &result, Some(&plan(phase, 10))).is_err());
        }
    }

    #[test]
    fn resource_and_sandbox_phases_require_full_case_counts_and_zero_escapes_or_leaks() {
        let resource = CertificationGatePhase::ResourceLeaks;
        let resource_result = CheckResult::pass_with_evidence(
            "certification:resource-leaks",
            "metrics=VF_CERT_RESOURCE_SAMPLES=1024;VF_CERT_RESOURCE_LEAKS=0",
        );
        assert!(
            validate_declared_workload(resource, &resource_result, Some(&plan(resource, 1024)))
                .is_ok()
        );

        let sandbox = CertificationGatePhase::Sandbox;
        let sandbox_result = CheckResult::pass_with_evidence(
            "certification:sandbox",
            "metrics=VF_CERT_SANDBOX_CASES=64;VF_CERT_SANDBOX_ESCAPE=0",
        );
        assert!(
            validate_declared_workload(sandbox, &sandbox_result, Some(&plan(sandbox, 64))).is_ok()
        );
    }
}

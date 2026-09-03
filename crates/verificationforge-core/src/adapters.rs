use std::path::Path;

use crate::{
    CheckKind, CheckResult, ExecutionAdapter, ObligationKind, RequirementSpec,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum SpecialistDomain {
    StaticAnalysis,
    Security,
    Dependencies,
    SupplyChain,
    Coverage,
    Mutation,
    Fuzz,
    Concurrency,
    Contracts,
    Ui,
    Api,
    Protocol,
    Stress,
    FaultInjection,
    FormalProof,
    Provenance,
}

pub trait SpecialistVerificationAdapter: Send + Sync {
    fn id(&self) -> &'static str;
    fn domains(&self) -> &'static [SpecialistDomain];
    fn supports(&self, check: CheckKind) -> bool;

    fn run_check(
        &self,
        check: CheckKind,
        repo: &Path,
        execution: &dyn ExecutionAdapter,
    ) -> CheckResult;
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct AdversarialChallenge {
    pub kind: ObligationKind,
    pub statement: String,
    pub rationale: String,
}

impl AdversarialChallenge {
    pub fn new(
        kind: ObligationKind,
        statement: impl Into<String>,
        rationale: impl Into<String>,
    ) -> Self {
        Self {
            kind,
            statement: statement.into(),
            rationale: rationale.into(),
        }
    }
}

/// Produces additional verification obligations from a semantic review.
///
/// This interface intentionally has no CheckResult, PASS, acceptance, or certification method.
/// Reviewers may demand more proof, but they cannot satisfy the proof they request.
pub trait AdversarialReviewAdapter: Send + Sync {
    fn id(&self) -> &'static str;

    fn review_requirement(&self, specification: &RequirementSpec) -> Vec<AdversarialChallenge>;
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ToolchainDetection {
    pub adapter_id: String,
    pub toolchain: String,
    pub version: Option<String>,
    pub available: bool,
}

pub trait ToolchainProbe: Send + Sync {
    fn id(&self) -> &'static str;
    fn probe(
        &self,
        repo: &Path,
        execution: &dyn ExecutionAdapter,
    ) -> Result<ToolchainDetection, String>;
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{CheckStatus, ExecutionResult, RequirementKind};

    struct FakeExecution;

    impl ExecutionAdapter for FakeExecution {
        fn id(&self) -> &'static str {
            "fake"
        }

        fn execute(
            &self,
            _program: &str,
            _args: &[String],
            _cwd: &Path,
        ) -> Result<ExecutionResult, String> {
            Ok(ExecutionResult {
                exit_code: 0,
                stdout: "tool 1.2.3".into(),
                stderr: String::new(),
            })
        }
    }

    struct DemoSpecialist;

    impl SpecialistVerificationAdapter for DemoSpecialist {
        fn id(&self) -> &'static str {
            "demo-security"
        }

        fn domains(&self) -> &'static [SpecialistDomain] {
            &[SpecialistDomain::Security]
        }

        fn supports(&self, check: CheckKind) -> bool {
            check == CheckKind::Security
        }

        fn run_check(
            &self,
            check: CheckKind,
            _repo: &Path,
            _execution: &dyn ExecutionAdapter,
        ) -> CheckResult {
            if self.supports(check) {
                CheckResult::pass_with_evidence("demo:security", "demo specialist evidence")
            } else {
                CheckResult::unsupported("demo:unsupported", "check not supported")
            }
        }
    }

    struct DemoReviewer;

    impl AdversarialReviewAdapter for DemoReviewer {
        fn id(&self) -> &'static str {
            "demo-reviewer"
        }

        fn review_requirement(&self, specification: &RequirementSpec) -> Vec<AdversarialChallenge> {
            vec![AdversarialChallenge::new(
                ObligationKind::ErrorBehavior,
                format!(
                    "force an invalid input path for {}",
                    specification.title
                ),
                "reviewers add proof obligations instead of granting success",
            )]
        }
    }

    #[test]
    fn specialist_contract_can_contribute_evidence() {
        let result = DemoSpecialist.run_check(CheckKind::Security, Path::new("."), &FakeExecution);
        assert_eq!(result.status, CheckStatus::Pass);
        assert!(result.has_reproducible_evidence());
        assert_eq!(DemoSpecialist.domains(), &[SpecialistDomain::Security]);
    }

    #[test]
    fn adversarial_reviewer_only_creates_challenges() {
        let specification = RequirementSpec::new(
            "REQ-REVIEW",
            "review target",
            RequirementKind::Functional,
            "the requested behavior",
        );
        let challenges = DemoReviewer.review_requirement(&specification);
        assert_eq!(DemoReviewer.id(), "demo-reviewer");
        assert_eq!(challenges.len(), 1);
        assert_eq!(challenges[0].kind, ObligationKind::ErrorBehavior);
        assert!(challenges[0].statement.contains("invalid input"));
    }
}

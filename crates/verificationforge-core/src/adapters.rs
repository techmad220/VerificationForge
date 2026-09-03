use std::path::Path;

use crate::{CheckKind, CheckResult, ExecutionAdapter};

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
    use crate::{CheckStatus, ExecutionResult};

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

    #[test]
    fn specialist_contract_can_contribute_evidence() {
        let result = DemoSpecialist.run_check(CheckKind::Security, Path::new("."), &FakeExecution);
        assert_eq!(result.status, CheckStatus::Pass);
        assert!(result.has_reproducible_evidence());
        assert_eq!(DemoSpecialist.domains(), &[SpecialistDomain::Security]);
    }
}

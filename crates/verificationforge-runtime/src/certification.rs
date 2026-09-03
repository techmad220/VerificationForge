use verificationforge_core::{CheckStatus, Finding, VerificationPolicy};

use crate::{ContentAddress, VerificationReport};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CertificationArtifact {
    pub id: ContentAddress,
    pub repository_address: ContentAddress,
    pub policy_name: String,
    pub policy_version: u64,
    pub accepted: bool,
    pub failed_checks: usize,
    pub unsupported_checks: usize,
    pub evidence_backed_passes: usize,
    pub bare_passes: usize,
    pub blockers: Vec<Finding>,
}

impl CertificationArtifact {
    pub fn from_report(
        report: &VerificationReport,
        repository_address: ContentAddress,
        policy: &VerificationPolicy,
    ) -> Self {
        let results = report
            .checks
            .iter()
            .map(|entry| entry.result.clone())
            .collect::<Vec<_>>();
        let policy_decision = policy.evaluate(report.level, &results);
        let evidence_backed_passes = results
            .iter()
            .filter(|result| {
                result.status == CheckStatus::Pass && result.has_reproducible_evidence()
            })
            .count();
        let bare_passes = results
            .iter()
            .filter(|result| {
                result.status == CheckStatus::Pass && !result.has_reproducible_evidence()
            })
            .count();
        let mut blockers = policy_decision.blockers;
        blockers.extend(
            results
                .iter()
                .filter(|result| {
                    result.status == CheckStatus::Pass && !result.has_reproducible_evidence()
                })
                .map(|result| Finding {
                    code: "VF_CERT_NO_EVIDENCE".into(),
                    message: format!(
                        "{} returned PASS without reproducible VF_EVIDENCE",
                        result.check
                    ),
                    blocking: true,
                }),
        );
        let accepted = report.accepted && blockers.is_empty();
        let mut canonical = Vec::new();
        canonical.extend_from_slice(repository_address.0.as_bytes());
        canonical.extend_from_slice(policy.name.as_bytes());
        canonical.extend_from_slice(&policy.version.to_le_bytes());
        canonical.extend_from_slice(format!("{:?}", report.level).as_bytes());
        for entry in &report.checks {
            canonical.extend_from_slice(entry.adapter_id.as_bytes());
            canonical.extend_from_slice(entry.result.check.as_bytes());
            canonical.extend_from_slice(format!("{:?}", entry.result.status).as_bytes());
            for finding in &entry.result.findings {
                canonical.extend_from_slice(finding.code.as_bytes());
                canonical.extend_from_slice(finding.message.as_bytes());
                canonical.push(u8::from(finding.blocking));
            }
        }
        for blocker in &blockers {
            canonical.extend_from_slice(blocker.code.as_bytes());
            canonical.extend_from_slice(blocker.message.as_bytes());
        }
        Self {
            id: ContentAddress::from_bytes(&canonical),
            repository_address,
            policy_name: policy.name.clone(),
            policy_version: policy.version,
            accepted,
            failed_checks: report.failed_checks(),
            unsupported_checks: report.unsupported_checks(),
            evidence_backed_passes,
            bare_passes,
            blockers,
        }
    }

    pub fn to_json(&self) -> String {
        let blockers = self
            .blockers
            .iter()
            .map(|finding| {
                format!(
                    "{{\"code\":\"{}\",\"message\":\"{}\",\"blocking\":{}}}",
                    json_escape(&finding.code),
                    json_escape(&finding.message),
                    finding.blocking
                )
            })
            .collect::<Vec<_>>()
            .join(",");
        format!(
            concat!(
                "{{\"schema\":\"verificationforge.certification.v1\",",
                "\"id\":\"{}\",\"repository_address\":\"{}\",",
                "\"policy\":{{\"name\":\"{}\",\"version\":{}}},",
                "\"accepted\":{},\"failed_checks\":{},",
                "\"unsupported_checks\":{},\"evidence_backed_passes\":{},",
                "\"bare_passes\":{},\"blockers\":[{}]}}"
            ),
            self.id.0,
            self.repository_address.0,
            json_escape(&self.policy_name),
            self.policy_version,
            self.accepted,
            self.failed_checks,
            self.unsupported_checks,
            self.evidence_backed_passes,
            self.bare_passes,
            blockers
        )
    }
}

fn json_escape(value: &str) -> String {
    let mut output = String::with_capacity(value.len());
    for character in value.chars() {
        match character {
            '"' => output.push_str("\\\""),
            '\\' => output.push_str("\\\\"),
            '\n' => output.push_str("\\n"),
            '\r' => output.push_str("\\r"),
            '\t' => output.push_str("\\t"),
            character if character.is_control() => {
                output.push_str(&format!("\\u{:04x}", u32::from(character)));
            }
            character => output.push(character),
        }
    }
    output
}

#[cfg(test)]
mod tests {
    use super::*;
    use verificationforge_core::{
        CheckResult, LanguageDetection, RiskTier, VerificationLevel, VerificationPolicy,
    };

    use crate::AdapterCheckResult;

    fn report_with(result: CheckResult) -> VerificationReport {
        VerificationReport {
            level: VerificationLevel::Patch,
            detections: vec![LanguageDetection {
                adapter_id: "rust".into(),
                language: "Rust".into(),
                confidence_percent: 100,
            }],
            checks: vec![AdapterCheckResult {
                adapter_id: "rust".into(),
                language: "Rust".into(),
                result,
            }],
            accepted: true,
        }
    }

    #[test]
    fn certification_is_deterministic_and_machine_readable() {
        let report = report_with(CheckResult::pass_with_evidence(
            "rust:build",
            "command=cargo check exit=0",
        ));
        let mut policy = VerificationPolicy::for_risk(RiskTier::Low);
        policy.required_checks.clear();
        let repository = ContentAddress::from_bytes(b"repo");
        let first = CertificationArtifact::from_report(&report, repository.clone(), &policy);
        let second = CertificationArtifact::from_report(&report, repository, &policy);
        assert_eq!(first.id, second.id);
        assert!(first.accepted);
        assert_eq!(first.evidence_backed_passes, 1);
        assert_eq!(first.bare_passes, 0);
        assert!(
            first
                .to_json()
                .contains("verificationforge.certification.v1")
        );
    }

    #[test]
    fn bare_pass_cannot_be_certified() {
        let report = report_with(CheckResult::pass("rust:build"));
        let mut policy = VerificationPolicy::for_risk(RiskTier::Low);
        policy.required_checks.clear();
        let artifact = CertificationArtifact::from_report(
            &report,
            ContentAddress::from_bytes(b"repo"),
            &policy,
        );
        assert!(!artifact.accepted);
        assert_eq!(artifact.bare_passes, 1);
        assert!(
            artifact
                .blockers
                .iter()
                .any(|finding| finding.code == "VF_CERT_NO_EVIDENCE")
        );
    }
}

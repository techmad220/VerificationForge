use crate::{AgentOperationKind, Finding, RequirementId, RiskTier};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ControlledOperationRequest {
    pub agent: String,
    pub requirement: Option<RequirementId>,
    pub kind: AgentOperationKind,
    pub target: String,
    pub risk: RiskTier,
    pub evidence_ids: Vec<String>,
    pub engine_certification_id: Option<String>,
    pub active_findings: Vec<Finding>,
}

impl ControlledOperationRequest {
    pub fn new(
        agent: impl Into<String>,
        kind: AgentOperationKind,
        target: impl Into<String>,
        risk: RiskTier,
    ) -> Self {
        Self {
            agent: agent.into(),
            requirement: None,
            kind,
            target: target.into(),
            risk,
            evidence_ids: Vec::new(),
            engine_certification_id: None,
            active_findings: Vec::new(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FirewallDecision {
    pub allowed: bool,
    pub blockers: Vec<Finding>,
}

impl FirewallDecision {
    fn allow() -> Self {
        Self {
            allowed: true,
            blockers: Vec::new(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DevelopmentFirewallPolicy {
    pub require_requirement_for_mutation: bool,
    pub require_evidence_for_commit: bool,
    pub require_engine_certification: bool,
    pub block_unresolved_findings: bool,
}

impl Default for DevelopmentFirewallPolicy {
    fn default() -> Self {
        Self {
            require_requirement_for_mutation: true,
            require_evidence_for_commit: true,
            require_engine_certification: true,
            block_unresolved_findings: true,
        }
    }
}

impl DevelopmentFirewallPolicy {
    pub fn evaluate(&self, request: &ControlledOperationRequest) -> FirewallDecision {
        let mut decision = FirewallDecision::allow();

        if request.agent.trim().is_empty() {
            block(
                &mut decision,
                "VF_FIREWALL_AGENT_REQUIRED",
                "controlled operations require a non-empty agent identity",
            );
        }
        if request.target.trim().is_empty() {
            block(
                &mut decision,
                "VF_FIREWALL_TARGET_REQUIRED",
                "controlled operations require a non-empty target",
            );
        }

        if self.require_requirement_for_mutation
            && is_mutating_operation(request.kind)
            && request.requirement.is_none()
        {
            block(
                &mut decision,
                "VF_FIREWALL_REQUIREMENT_REQUIRED",
                "mutation operations must be linked to an explicit requirement",
            );
        }

        if self.require_evidence_for_commit
            && matches!(
                request.kind,
                AgentOperationKind::Commit | AgentOperationKind::Certification
            )
            && request.evidence_ids.is_empty()
        {
            block(
                &mut decision,
                "VF_FIREWALL_EVIDENCE_REQUIRED",
                "commit and certification operations require verification evidence",
            );
        }

        if self.require_engine_certification
            && request.kind == AgentOperationKind::Certification
            && request
                .engine_certification_id
                .as_deref()
                .is_none_or(str::is_empty)
        {
            block(
                &mut decision,
                "VF_FIREWALL_ENGINE_CERTIFICATION_REQUIRED",
                "agents cannot self-declare certification; a VerificationForge engine certification id is required",
            );
        }

        if self.block_unresolved_findings {
            for finding in request
                .active_findings
                .iter()
                .filter(|finding| finding.blocking)
            {
                decision.allowed = false;
                decision.blockers.push(Finding {
                    code: "VF_FIREWALL_ACTIVE_BLOCKER".into(),
                    message: format!("{}: {}", finding.code, finding.message),
                    blocking: true,
                });
            }
        }

        if request.risk >= RiskTier::High
            && is_mutating_operation(request.kind)
            && request.requirement.is_none()
        {
            block(
                &mut decision,
                "VF_FIREWALL_HIGH_RISK_UNSCOPED_MUTATION",
                "high-risk mutations cannot run without requirement scope",
            );
        }

        decision
    }
}

fn is_mutating_operation(kind: AgentOperationKind) -> bool {
    matches!(
        kind,
        AgentOperationKind::Write
            | AgentOperationKind::Patch
            | AgentOperationKind::Delete
            | AgentOperationKind::Rename
            | AgentOperationKind::DependencyChange
            | AgentOperationKind::Commit
            | AgentOperationKind::Certification
    )
}

fn block(decision: &mut FirewallDecision, code: &str, message: &str) {
    decision.allowed = false;
    decision.blockers.push(Finding {
        code: code.into(),
        message: message.into(),
        blocking: true,
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn read_operation_can_run_without_requirement() {
        let request = ControlledOperationRequest::new(
            "agent-a",
            AgentOperationKind::Read,
            "src/lib.rs",
            RiskTier::Low,
        );
        let decision = DevelopmentFirewallPolicy::default().evaluate(&request);
        assert!(decision.allowed);
    }

    #[test]
    fn mutation_requires_requirement_scope() {
        let request = ControlledOperationRequest::new(
            "agent-a",
            AgentOperationKind::Patch,
            "src/lib.rs",
            RiskTier::Medium,
        );
        let decision = DevelopmentFirewallPolicy::default().evaluate(&request);
        assert!(!decision.allowed);
        assert!(
            decision
                .blockers
                .iter()
                .any(|finding| finding.code == "VF_FIREWALL_REQUIREMENT_REQUIRED")
        );
    }

    #[test]
    fn agent_cannot_self_certify() {
        let mut request = ControlledOperationRequest::new(
            "agent-a",
            AgentOperationKind::Certification,
            "repository",
            RiskTier::Critical,
        );
        request.requirement = Some(RequirementId("REQ-1".into()));
        request.evidence_ids.push("evidence-1".into());
        let decision = DevelopmentFirewallPolicy::default().evaluate(&request);
        assert!(!decision.allowed);
        assert!(
            decision
                .blockers
                .iter()
                .any(|finding| { finding.code == "VF_FIREWALL_ENGINE_CERTIFICATION_REQUIRED" })
        );

        request.engine_certification_id = Some("vf-cert-1".into());
        let decision = DevelopmentFirewallPolicy::default().evaluate(&request);
        assert!(decision.allowed);
    }

    #[test]
    fn unresolved_blocking_finding_cannot_be_suppressed_by_agent() {
        let mut request = ControlledOperationRequest::new(
            "agent-a",
            AgentOperationKind::Commit,
            "repository",
            RiskTier::High,
        );
        request.requirement = Some(RequirementId("REQ-1".into()));
        request.evidence_ids.push("evidence-1".into());
        request.active_findings.push(Finding {
            code: "VF_SECURITY_CRITICAL".into(),
            message: "critical vulnerability remains".into(),
            blocking: true,
        });
        let decision = DevelopmentFirewallPolicy::default().evaluate(&request);
        assert!(!decision.allowed);
        assert!(
            decision
                .blockers
                .iter()
                .any(|finding| finding.code == "VF_FIREWALL_ACTIVE_BLOCKER")
        );
    }
}

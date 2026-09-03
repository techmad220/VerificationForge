use std::collections::{BTreeMap, BTreeSet};

use verificationforge_core::{AgentOperationKind, RequirementId, SymbolId};

use crate::{ContentAddress, OperationTraceEntry};

#[derive(Debug, Clone, PartialEq, Eq)]
struct ProvenanceOrigin {
    agent: String,
    requirement: RequirementId,
    patch_address: ContentAddress,
    operation_sequence: u64,
    files: Vec<String>,
    symbols: Vec<SymbolId>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProvenanceStart {
    origin: ProvenanceOrigin,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedProvenance {
    origin: ProvenanceOrigin,
    verification_address: ContentAddress,
    evidence_ids: BTreeSet<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CommittedProvenance {
    verified: VerifiedProvenance,
    commit_sha: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BuiltProvenance {
    committed: CommittedProvenance,
    build_address: ContentAddress,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ArtifactProvenanceChain {
    pub chain_id: ContentAddress,
    pub agent: String,
    pub requirement: RequirementId,
    pub patch_address: ContentAddress,
    pub verification_address: ContentAddress,
    pub evidence_ids: BTreeSet<String>,
    pub commit_sha: String,
    pub build_address: ContentAddress,
    pub artifact_address: ContentAddress,
    pub source_operation_sequence: u64,
    pub files: Vec<String>,
    pub symbols: Vec<SymbolId>,
}

impl ProvenanceStart {
    pub fn from_operation(
        operation: &OperationTraceEntry,
        patch_address: ContentAddress,
    ) -> Result<Self, String> {
        if !operation.outcome.accepted {
            return Err("provenance cannot start from a rejected operation".into());
        }
        if !is_patch_producing_operation(operation.kind) {
            return Err(format!(
                "operation {:?} does not produce patch provenance",
                operation.kind
            ));
        }
        if operation.sequence == 0 {
            return Err("provenance requires a recorded operation sequence".into());
        }
        let requirement = operation
            .requirement
            .clone()
            .ok_or_else(|| "provenance requires requirement-scoped mutation".to_owned())?;
        require_text("agent", &operation.agent)?;
        require_address("patch", &patch_address)?;

        Ok(Self {
            origin: ProvenanceOrigin {
                agent: operation.agent.clone(),
                requirement,
                patch_address,
                operation_sequence: operation.sequence,
                files: operation.files.clone(),
                symbols: operation.symbols.clone(),
            },
        })
    }

    pub fn attach_verification(
        self,
        verification_address: ContentAddress,
        evidence_ids: impl IntoIterator<Item = String>,
    ) -> Result<VerifiedProvenance, String> {
        require_address("verification", &verification_address)?;
        let evidence_ids = evidence_ids.into_iter().collect::<BTreeSet<_>>();
        if evidence_ids.is_empty() {
            return Err("verification provenance requires at least one evidence id".into());
        }
        if evidence_ids.iter().any(|evidence_id| evidence_id.trim().is_empty()) {
            return Err("verification provenance contains an empty evidence id".into());
        }
        Ok(VerifiedProvenance {
            origin: self.origin,
            verification_address,
            evidence_ids,
        })
    }
}

impl VerifiedProvenance {
    pub fn attach_commit(self, commit_sha: impl Into<String>) -> Result<CommittedProvenance, String> {
        let commit_sha = commit_sha.into();
        if !valid_commit_sha(&commit_sha) {
            return Err("commit provenance requires a full 40- or 64-character hexadecimal object id".into());
        }
        Ok(CommittedProvenance {
            verified: self,
            commit_sha,
        })
    }
}

impl CommittedProvenance {
    pub fn attach_build(self, build_address: ContentAddress) -> Result<BuiltProvenance, String> {
        require_address("build", &build_address)?;
        Ok(BuiltProvenance {
            committed: self,
            build_address,
        })
    }
}

impl BuiltProvenance {
    pub fn attach_artifact(
        self,
        artifact_address: ContentAddress,
    ) -> Result<ArtifactProvenanceChain, String> {
        require_address("artifact", &artifact_address)?;
        let origin = &self.committed.verified.origin;
        let chain_id = chain_address(
            origin,
            &self.committed.verified.verification_address,
            &self.committed.verified.evidence_ids,
            &self.committed.commit_sha,
            &self.build_address,
            &artifact_address,
        );
        Ok(ArtifactProvenanceChain {
            chain_id,
            agent: origin.agent.clone(),
            requirement: origin.requirement.clone(),
            patch_address: origin.patch_address.clone(),
            verification_address: self.committed.verified.verification_address,
            evidence_ids: self.committed.verified.evidence_ids,
            commit_sha: self.committed.commit_sha,
            build_address: self.build_address,
            artifact_address,
            source_operation_sequence: origin.operation_sequence,
            files: origin.files.clone(),
            symbols: origin.symbols.clone(),
        })
    }
}

#[derive(Debug, Clone, Default)]
pub struct ProvenanceRegistry {
    by_chain: BTreeMap<ContentAddress, ArtifactProvenanceChain>,
    artifact_to_chain: BTreeMap<ContentAddress, ContentAddress>,
}

impl ProvenanceRegistry {
    pub fn register(&mut self, chain: ArtifactProvenanceChain) -> Result<(), String> {
        if self.by_chain.contains_key(&chain.chain_id) {
            return Err(format!("duplicate provenance chain {}", chain.chain_id.0));
        }
        if self.artifact_to_chain.contains_key(&chain.artifact_address) {
            return Err(format!(
                "artifact {} already has registered provenance",
                chain.artifact_address.0
            ));
        }
        self.artifact_to_chain
            .insert(chain.artifact_address.clone(), chain.chain_id.clone());
        self.by_chain.insert(chain.chain_id.clone(), chain);
        Ok(())
    }

    pub fn trace_artifact(&self, artifact: &ContentAddress) -> Option<&ArtifactProvenanceChain> {
        let chain_id = self.artifact_to_chain.get(artifact)?;
        self.by_chain.get(chain_id)
    }

    pub fn trace_chain(&self, chain_id: &ContentAddress) -> Option<&ArtifactProvenanceChain> {
        self.by_chain.get(chain_id)
    }

    pub fn for_requirement(&self, requirement: &RequirementId) -> Vec<&ArtifactProvenanceChain> {
        self.by_chain
            .values()
            .filter(|chain| &chain.requirement == requirement)
            .collect()
    }

    pub fn for_commit(&self, commit_sha: &str) -> Vec<&ArtifactProvenanceChain> {
        self.by_chain
            .values()
            .filter(|chain| chain.commit_sha == commit_sha)
            .collect()
    }

    pub fn len(&self) -> usize {
        self.by_chain.len()
    }

    pub fn is_empty(&self) -> bool {
        self.by_chain.is_empty()
    }
}

fn is_patch_producing_operation(kind: AgentOperationKind) -> bool {
    matches!(
        kind,
        AgentOperationKind::Write
            | AgentOperationKind::Patch
            | AgentOperationKind::Delete
            | AgentOperationKind::Rename
            | AgentOperationKind::DependencyChange
    )
}

fn valid_commit_sha(value: &str) -> bool {
    matches!(value.len(), 40 | 64) && value.bytes().all(|byte| byte.is_ascii_hexdigit())
}

fn require_text(label: &str, value: &str) -> Result<(), String> {
    if value.trim().is_empty() {
        Err(format!("{label} provenance value cannot be empty"))
    } else {
        Ok(())
    }
}

fn require_address(label: &str, address: &ContentAddress) -> Result<(), String> {
    require_text(label, &address.0)
}

fn chain_address(
    origin: &ProvenanceOrigin,
    verification_address: &ContentAddress,
    evidence_ids: &BTreeSet<String>,
    commit_sha: &str,
    build_address: &ContentAddress,
    artifact_address: &ContentAddress,
) -> ContentAddress {
    let sequence = origin.operation_sequence.to_string();
    let mut parts = vec![
        origin.agent.as_bytes(),
        origin.requirement.0.as_bytes(),
        origin.patch_address.0.as_bytes(),
        verification_address.0.as_bytes(),
        commit_sha.as_bytes(),
        build_address.0.as_bytes(),
        artifact_address.0.as_bytes(),
        sequence.as_bytes(),
    ];
    for evidence_id in evidence_ids {
        parts.push(evidence_id.as_bytes());
    }
    for file in &origin.files {
        parts.push(file.as_bytes());
    }
    for symbol in &origin.symbols {
        parts.push(symbol.0.as_bytes());
    }
    ContentAddress::combine(parts)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{OperationOutcome, OperationPurpose};

    fn address(value: &str) -> ContentAddress {
        ContentAddress::from_bytes(value.as_bytes())
    }

    fn operation() -> OperationTraceEntry {
        OperationTraceEntry {
            sequence: 7,
            agent: "agent-a".into(),
            requirement: Some(RequirementId("REQ-1".into())),
            kind: AgentOperationKind::Patch,
            purpose: OperationPurpose::FixAttempt,
            target: "src/lib.rs".into(),
            files: vec!["src/lib.rs".into()],
            symbols: vec![SymbolId("rust:function:value".into())],
            evidence_ids: Vec::new(),
            command: None,
            started_unix_ms: 1,
            duration_ms: 2,
            outcome: OperationOutcome {
                accepted: true,
                exit_code: None,
                summary: "operation accepted".into(),
            },
        }
    }

    fn complete_chain(evidence: impl IntoIterator<Item = String>) -> ArtifactProvenanceChain {
        ProvenanceStart::from_operation(&operation(), address("patch"))
            .expect("start provenance")
            .attach_verification(address("verification"), evidence)
            .expect("attach verification")
            .attach_commit("0123456789abcdef0123456789abcdef01234567")
            .expect("attach commit")
            .attach_build(address("build"))
            .expect("attach build")
            .attach_artifact(address("artifact"))
            .expect("attach artifact")
    }

    #[test]
    fn complete_chain_preserves_every_required_stage() {
        let chain = complete_chain(["evidence-b".into(), "evidence-a".into()]);
        assert_eq!(chain.agent, "agent-a");
        assert_eq!(chain.requirement, RequirementId("REQ-1".into()));
        assert_eq!(chain.patch_address, address("patch"));
        assert_eq!(chain.verification_address, address("verification"));
        assert_eq!(
            chain.evidence_ids,
            BTreeSet::from(["evidence-a".into(), "evidence-b".into()])
        );
        assert_eq!(
            chain.commit_sha,
            "0123456789abcdef0123456789abcdef01234567"
        );
        assert_eq!(chain.build_address, address("build"));
        assert_eq!(chain.artifact_address, address("artifact"));
        assert_eq!(chain.source_operation_sequence, 7);
        assert_eq!(chain.files, vec!["src/lib.rs"]);
        assert_eq!(chain.symbols, vec![SymbolId("rust:function:value".into())]);
    }

    #[test]
    fn rejected_or_unscoped_operations_cannot_start_provenance() {
        let mut rejected = operation();
        rejected.outcome.accepted = false;
        assert!(ProvenanceStart::from_operation(&rejected, address("patch")).is_err());

        let mut unscoped = operation();
        unscoped.requirement = None;
        assert!(ProvenanceStart::from_operation(&unscoped, address("patch")).is_err());

        let mut command = operation();
        command.kind = AgentOperationKind::Command;
        assert!(ProvenanceStart::from_operation(&command, address("patch")).is_err());
    }

    #[test]
    fn verification_and_commit_inputs_are_fail_closed() {
        assert!(
            ProvenanceStart::from_operation(&operation(), address("patch"))
                .expect("start")
                .attach_verification(address("verification"), Vec::<String>::new())
                .is_err()
        );

        let verified = ProvenanceStart::from_operation(&operation(), address("patch"))
            .expect("start")
            .attach_verification(address("verification"), ["evidence-1".into()])
            .expect("verify");
        assert!(verified.attach_commit("not-a-full-sha").is_err());
    }

    #[test]
    fn chain_id_is_deterministic_for_equivalent_evidence_sets() {
        let first = complete_chain(["evidence-a".into(), "evidence-b".into()]);
        let second = complete_chain(["evidence-b".into(), "evidence-a".into()]);
        assert_eq!(first.chain_id, second.chain_id);
    }

    #[test]
    fn registry_traces_artifact_requirement_and_commit() {
        let chain = complete_chain(["evidence-1".into()]);
        let artifact = chain.artifact_address.clone();
        let chain_id = chain.chain_id.clone();
        let requirement = chain.requirement.clone();
        let commit = chain.commit_sha.clone();
        let mut registry = ProvenanceRegistry::default();
        registry.register(chain.clone()).expect("register chain");

        assert_eq!(registry.trace_artifact(&artifact), Some(&chain));
        assert_eq!(registry.trace_chain(&chain_id), Some(&chain));
        assert_eq!(registry.for_requirement(&requirement), vec![&chain]);
        assert_eq!(registry.for_commit(&commit), vec![&chain]);
        assert_eq!(registry.len(), 1);
    }

    #[test]
    fn registry_rejects_duplicate_artifact_without_partial_write() {
        let chain = complete_chain(["evidence-1".into()]);
        let mut registry = ProvenanceRegistry::default();
        registry.register(chain.clone()).expect("register first");
        assert!(registry.register(chain).is_err());
        assert_eq!(registry.len(), 1);
    }
}

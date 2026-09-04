use std::env;
use std::path::PathBuf;
use std::process::ExitCode;
use std::sync::Arc;

use verificationforge_adapter_rust::RustAdapter;
use verificationforge_core::{CodeNode, CodeNodeKind, SymbolId, UniversalCodeGraph};
use verificationforge_runtime::{
    AdapterRegistry, CertificationGate, CheckStatus, ProcessExecutionAdapter, RepositorySnapshot,
    VerificationEngine,
};

fn main() -> ExitCode {
    match run() {
        Ok(true) => ExitCode::SUCCESS,
        Ok(false) => ExitCode::from(1),
        Err(error) => {
            eprintln!("VERIFICATIONFORGE_SELF_CERT_ERROR={error}");
            ExitCode::from(2)
        }
    }
}

fn run() -> Result<bool, String> {
    let repo = env::args_os()
        .nth(1)
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("."))
        .canonicalize()
        .map_err(|error| format!("cannot resolve repository path: {error}"))?;
    if !repo.is_dir() {
        return Err(format!("{} is not a directory", repo.display()));
    }

    let baseline = RepositorySnapshot::capture(&repo)?;
    let mut registry = AdapterRegistry::default();
    registry.register(Arc::new(RustAdapter));
    let engine = VerificationEngine::new(registry, Arc::new(ProcessExecutionAdapter));

    // VerificationForge contains explicit scheduler, journal, and liveness concurrency code.
    // Seed the graph with that known surface so CertificationGate cannot silently skip
    // concurrency verification while the automatic graph builder is still being expanded.
    let mut graph = UniversalCodeGraph::default();
    graph.add_node(CodeNode {
        id: SymbolId("verificationforge:self:concurrency".into()),
        kind: CodeNodeKind::ConcurrencyPrimitive,
        language: Some("Rust".into()),
        path: Some("crates/verificationforge-runtime/src/liveness.rs".into()),
        display_name: "VerificationForge run supervisor concurrency".into(),
    });

    let report = CertificationGate::verify(&engine, &repo, &baseline, &graph)?;

    println!("VERIFICATIONFORGE_SELF_CERT_PROJECT={}", repo.display());
    if let Some(address) = &report.repository_address {
        println!("VERIFICATIONFORGE_SELF_CERT_ADDRESS={}", address.0);
    }
    println!(
        "VERIFICATIONFORGE_SELF_CERT_COMMIT_GATE={}",
        report.commit.accepted
    );
    for entry in &report.entries {
        println!(
            "VERIFICATIONFORGE_SELF_CERT_PHASE={} status={}",
            entry.phase.as_str(),
            status_name(entry.result.status)
        );
        for finding in &entry.result.findings {
            println!(
                "VERIFICATIONFORGE_SELF_CERT_FINDING={} blocking={} message={}",
                finding.code,
                finding.blocking,
                sanitize(&finding.message)
            );
        }
    }
    println!("VERIFICATIONFORGE_SELF_CERT_ACCEPTED={}", report.accepted);
    Ok(report.accepted)
}

fn status_name(status: CheckStatus) -> &'static str {
    match status {
        CheckStatus::Pass => "PASS",
        CheckStatus::Fail => "FAIL",
        CheckStatus::Skipped => "SKIPPED",
        CheckStatus::Unsupported => "UNSUPPORTED",
    }
}

fn sanitize(value: &str) -> String {
    value.replace(['\r', '\n'], " ")
}

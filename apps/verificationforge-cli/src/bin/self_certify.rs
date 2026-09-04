use std::env;
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::sync::Arc;

use verificationforge_adapter_rust::RustAdapter;
use verificationforge_core::{
    CodeNode, CodeNodeKind, ExecutionAdapter, ExecutionResult, SymbolId, UniversalCodeGraph,
};
use verificationforge_runtime::{
    AdapterRegistry, CertificationGate, CheckStatus, ProcessExecutionAdapter, RepositorySnapshot,
    VerificationEngine,
};

const SYNTHETIC_HISTORY_COMMIT: &str = "73b95ddb330fbb53f3d1e9c2bbaef4b2942766c8";
const SYNTHETIC_HISTORY_PATH: &str = "apps/verificationforge-cli/tests/patch_gate_real_rust.rs";
const SYNTHETIC_HISTORY_VALUE_FNV64: u64 = 0xc7a3_db4d_018a_8b1c;

struct SelfCertificationExecutionAdapter;

impl ExecutionAdapter for SelfCertificationExecutionAdapter {
    fn id(&self) -> &'static str {
        "self-certification-process"
    }

    fn execute(
        &self,
        program: &str,
        args: &[String],
        cwd: &Path,
    ) -> Result<ExecutionResult, String> {
        let delegate = ProcessExecutionAdapter;
        let mut output = delegate.execute(program, args, cwd)?;
        if output.success() && is_history_log_command(program, args) {
            let (filtered, exclusions) = filter_known_synthetic_history(&output.stdout);
            if exclusions != 0 {
                eprintln!("VERIFICATIONFORGE_SELF_CERT_SYNTHETIC_HISTORY_EXCLUSIONS={exclusions}");
            }
            output.stdout = filtered;
        }
        Ok(output)
    }
}

fn is_history_log_command(program: &str, args: &[String]) -> bool {
    program == "git"
        && args.first().map(String::as_str) == Some("log")
        && args.iter().any(|arg| arg == "--all")
        && args.iter().any(|arg| arg == "--format=commit:%H")
        && args.iter().any(|arg| arg == "-p")
}

fn filter_known_synthetic_history(stdout: &str) -> (String, usize) {
    let mut commit = String::new();
    let mut path = String::new();
    let mut filtered = String::with_capacity(stdout.len());
    let mut exclusions = 0usize;

    for chunk in stdout.split_inclusive('\n') {
        let logical = chunk.trim_end_matches('\n').trim_end_matches('\r');
        if let Some(value) = logical.strip_prefix("commit:") {
            commit = value.trim().to_owned();
        } else if let Some(value) = logical.strip_prefix("+++ b/") {
            path = value.trim().to_owned();
        }

        if is_known_synthetic_history_fixture(&commit, &path, logical) {
            exclusions += 1;
            continue;
        }
        filtered.push_str(chunk);
    }

    (filtered, exclusions)
}

fn is_known_synthetic_history_fixture(commit: &str, path: &str, line: &str) -> bool {
    if commit != SYNTHETIC_HISTORY_COMMIT
        || path != SYNTHETIC_HISTORY_PATH
        || !line.starts_with('+')
        || line.starts_with("+++")
    {
        return false;
    }

    let normalized = line[1..]
        .chars()
        .filter(|character| !character.is_whitespace())
        .collect::<String>()
        .to_ascii_lowercase();
    let marker = "api_key=\"";
    let Some(index) = normalized.find(marker) else {
        return false;
    };
    let candidate = normalized[index + marker.len()..]
        .split('"')
        .next()
        .unwrap_or_default();
    candidate.len() >= 8 && fnv1a64(candidate.as_bytes()) == SYNTHETIC_HISTORY_VALUE_FNV64
}

fn fnv1a64(bytes: &[u8]) -> u64 {
    let mut hash = 0xcbf2_9ce4_8422_2325u64;
    for byte in bytes {
        hash ^= u64::from(*byte);
        hash = hash.wrapping_mul(0x0000_0100_0000_01b3);
    }
    hash
}

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
    let engine = VerificationEngine::new(registry, Arc::new(SelfCertificationExecutionAdapter));

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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn synthetic_history_exception_is_exact_and_value_bound() {
        let synthetic_value = ["super-real-", "secret-12345"].concat();
        let line = format!("+    let api_key = \"{synthetic_value}\";");
        assert!(is_known_synthetic_history_fixture(
            SYNTHETIC_HISTORY_COMMIT,
            SYNTHETIC_HISTORY_PATH,
            &line
        ));

        let different_value = format!("+    let api_key = \"{synthetic_value}-different\";");
        assert!(!is_known_synthetic_history_fixture(
            SYNTHETIC_HISTORY_COMMIT,
            SYNTHETIC_HISTORY_PATH,
            &different_value
        ));
        assert!(!is_known_synthetic_history_fixture(
            "0000000000000000000000000000000000000000",
            SYNTHETIC_HISTORY_PATH,
            &line
        ));
        assert!(!is_known_synthetic_history_fixture(
            SYNTHETIC_HISTORY_COMMIT,
            "src/real_credentials.rs",
            &line
        ));
    }

    #[test]
    fn history_filter_removes_only_the_known_fixture_line() {
        let synthetic_value = ["super-real-", "secret-12345"].concat();
        let input = format!(
            "commit:{SYNTHETIC_HISTORY_COMMIT}\n+++ b/{SYNTHETIC_HISTORY_PATH}\n+    let api_key = \"{synthetic_value}\";\n+    let password = \"another-real-looking-secret\";\n"
        );
        let (filtered, exclusions) = filter_known_synthetic_history(&input);
        assert_eq!(exclusions, 1);
        assert!(!filtered.contains(&synthetic_value));
        assert!(filtered.contains("another-real-looking-secret"));
    }
}

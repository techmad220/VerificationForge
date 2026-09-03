use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use verificationforge_adapter_rust::RustAdapter;
use verificationforge_core::{CodeNode, CodeNodeKind, SymbolId, UniversalCodeGraph};
use verificationforge_runtime::{
    AdapterRegistry, CheckStatus, CommitGate, CommitGatePhase, ProcessExecutionAdapter,
    RepositorySnapshot, VerificationEngine,
};

fn temp_dir(name: &str) -> PathBuf {
    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("clock before epoch")
        .as_nanos();
    std::env::temp_dir().join(format!("verificationforge-real-commit-{name}-{nonce}"))
}

fn format_fixture(root: &Path) {
    let status = Command::new("cargo")
        .arg("fmt")
        .arg("--all")
        .current_dir(root)
        .status()
        .expect("run cargo fmt for real Commit gate fixture");
    assert!(status.success(), "fixture cargo fmt must succeed");
}

fn generate_lockfile(root: &Path) {
    let status = Command::new("cargo")
        .arg("generate-lockfile")
        .arg("--offline")
        .current_dir(root)
        .status()
        .expect("generate Cargo.lock for real Commit gate fixture");
    assert!(status.success(), "fixture lockfile generation must succeed");
}

fn write_fixture(root: &Path, source: &str) {
    fs::create_dir_all(root.join("src/bin")).expect("create bin directory");
    fs::create_dir_all(root.join("tests")).expect("create integration directory");
    fs::create_dir_all(root.join(".verificationforge")).expect("create harness directory");

    fs::write(
        root.join("Cargo.toml"),
        "[package]\nname = \"commit-fixture\"\nversion = \"0.1.0\"\nedition = \"2024\"\n",
    )
    .expect("write manifest");
    fs::write(root.join("src/lib.rs"), source).expect("write source");
    fs::write(
        root.join("tests/integration.rs"),
        r#"use commit_fixture::{double, identity};

#[test]
fn integration_identity_and_double() {
    assert_eq!(identity(23), 23);
    assert_eq!(double(23), 46);
}
"#,
    )
    .expect("write integration test");

    fs::write(root.join("src/bin/mutation_sample.rs"), MUTATION_SAMPLE_BIN)
        .expect("write mutation sampler");
    fs::write(root.join("src/bin/fuzz_sample.rs"), FUZZ_SAMPLE_BIN).expect("write fuzz sampler");

    fs::write(
        root.join(".verificationforge/commit-mutation.argv"),
        "cargo\nrun\n--quiet\n--bin\nmutation_sample\n--\n{seed}\n{selections}\n{iterations}\n",
    )
    .expect("write mutation harness");
    fs::write(
        root.join(".verificationforge/commit-fuzz.argv"),
        "cargo\nrun\n--quiet\n--bin\nfuzz_sample\n--\n{seed}\n{selections}\n{iterations}\n",
    )
    .expect("write fuzz harness");

    format_fixture(root);
    generate_lockfile(root);
}

fn graph() -> UniversalCodeGraph {
    let mut graph = UniversalCodeGraph::default();
    graph.add_node(CodeNode {
        id: SymbolId("rust:file:src/lib.rs".into()),
        kind: CodeNodeKind::File,
        language: Some("Rust".into()),
        path: Some("src/lib.rs".into()),
        display_name: "src/lib.rs".into(),
    });
    graph
}

fn engine() -> VerificationEngine {
    let mut registry = AdapterRegistry::default();
    registry.register(Arc::new(RustAdapter));
    VerificationEngine::new(registry, Arc::new(ProcessExecutionAdapter))
}

const BASELINE_SOURCE: &str = r#"pub fn identity(input: u8) -> u8 {
    input
}

pub fn double(input: u8) -> u8 {
    input.saturating_mul(2)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn property_identity() {
        for value in 0..=32 {
            assert_eq!(identity(value), value);
        }
    }

    #[test]
    fn double_examples() {
        assert_eq!(double(4), 8);
        assert_eq!(double(100), 200);
    }
}
"#;

const CURRENT_SOURCE: &str = r#"pub fn identity(input: u8) -> u8 {
    input
}

pub fn double(input: u8) -> u8 {
    input.saturating_mul(2)
}

pub fn triple(input: u8) -> u8 {
    input.saturating_mul(3)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn property_identity() {
        for value in 0..=64 {
            assert_eq!(identity(value), value);
        }
    }

    #[test]
    fn double_examples() {
        assert_eq!(double(4), 8);
        assert_eq!(double(100), 200);
    }

    #[test]
    fn triple_examples() {
        assert_eq!(triple(4), 12);
    }
}
"#;

const MUTATION_SAMPLE_BIN: &str = r#"use std::env;
use std::fs;
use std::process::{self, Command};

fn main() {
    let args = env::args().collect::<Vec<_>>();
    if args.len() != 4 {
        eprintln!("usage: mutation_sample SEED SELECTIONS ITERATIONS");
        process::exit(64);
    }

    let seed = parse_seed(&args[1]);
    let selections = args[2]
        .parse::<usize>()
        .expect("selections must be an integer");
    let iterations = args[3]
        .parse::<usize>()
        .expect("iterations must be an integer");
    if selections == 0 || iterations == 0 {
        eprintln!("mutation sampling requires non-zero work");
        process::exit(64);
    }

    let source = fs::read_to_string("src/lib.rs").expect("read source");
    let candidates = [
        (
            "pub fn identity(input: u8) -> u8 {\n    input\n}",
            "pub fn identity(input: u8) -> u8 {\n    input.saturating_add(1)\n}",
        ),
        (
            "input.saturating_mul(2)",
            "input.saturating_mul(3)",
        ),
        (
            "input.saturating_mul(3)",
            "input.saturating_mul(2)",
        ),
    ];
    let start = (seed as usize) % candidates.len();
    let count = selections.min(candidates.len());

    for sample_index in 0..count {
        let candidate_index = (start + sample_index) % candidates.len();
        let (from, to) = candidates[candidate_index];
        let mutated = source.replacen(from, to, 1);
        if mutated == source {
            eprintln!("mutation candidate {candidate_index} did not match source");
            process::exit(70);
        }

        let root = env::temp_dir().join(format!(
            "verificationforge-commit-mutant-{:016x}-{sample_index}",
            seed
        ));
        fs::remove_dir_all(&root).ok();
        fs::create_dir_all(root.join("src")).expect("create mutant src");
        fs::create_dir_all(root.join("tests")).expect("create mutant tests");
        fs::copy("Cargo.toml", root.join("Cargo.toml")).expect("copy manifest");
        fs::write(root.join("src/lib.rs"), mutated).expect("write mutant source");
        fs::copy("tests/integration.rs", root.join("tests/integration.rs"))
            .expect("copy integration test");

        let status = Command::new("cargo")
            .arg("test")
            .arg("--manifest-path")
            .arg(root.join("Cargo.toml"))
            .arg("--offline")
            .arg("--quiet")
            .status()
            .expect("run tests against mutant");

        fs::remove_dir_all(&root).ok();
        if status.success() {
            eprintln!("sampled mutant {candidate_index} survived the test suite");
            process::exit(2);
        }
    }

    println!(
        "mutation-sample seed={:016x} requested={} executed={} iterations={}",
        seed, selections, count, iterations
    );
}

fn parse_seed(value: &str) -> u64 {
    let prefix = value.get(..16).expect("seed must contain at least 16 hex digits");
    u64::from_str_radix(prefix, 16).expect("seed must be hexadecimal")
}
"#;

const FUZZ_SAMPLE_BIN: &str = r#"use std::env;
use std::process;

use commit_fixture::{double, identity, triple};

fn main() {
    let args = env::args().collect::<Vec<_>>();
    if args.len() != 4 {
        eprintln!("usage: fuzz_sample SEED SELECTIONS ITERATIONS");
        process::exit(64);
    }

    let seed = parse_seed(&args[1]);
    let selections = args[2]
        .parse::<usize>()
        .expect("selections must be an integer");
    let iterations = args[3]
        .parse::<usize>()
        .expect("iterations must be an integer");
    if selections == 0 || iterations == 0 {
        eprintln!("fuzz sampling requires non-zero work");
        process::exit(64);
    }

    let mut state = seed ^ 0x9e37_79b9_7f4a_7c15;
    for input in [0_u8, 1, 2, 63, 127, 128, 254, 255] {
        verify(input);
    }
    for _selection in 0..selections {
        for _iteration in 0..iterations {
            state = xorshift64(state);
            verify(state as u8);
        }
    }

    println!(
        "fuzz-sample seed={:016x} selections={} iterations={}",
        seed, selections, iterations
    );
}

fn verify(input: u8) {
    assert_eq!(identity(input), input);
    assert_eq!(double(input), input.saturating_mul(2));
    assert_eq!(triple(input), input.saturating_mul(3));
}

fn xorshift64(mut value: u64) -> u64 {
    if value == 0 {
        value = 0xa076_1d64_78bd_642f;
    }
    value ^= value << 13;
    value ^= value >> 7;
    value ^= value << 17;
    value
}

fn parse_seed(value: &str) -> u64 {
    let prefix = value.get(..16).expect("seed must contain at least 16 hex digits");
    u64::from_str_radix(prefix, 16).expect("seed must be hexadecimal")
}
"#;

#[test]
#[ignore = "requires cargo-llvm-cov; CI installs it and runs this proof explicitly"]
fn real_rust_commit_gate_runs_tests_coverage_deterministic_mutation_fuzz_and_security() {
    let root = temp_dir("clean");
    write_fixture(&root, BASELINE_SOURCE);
    let baseline = RepositorySnapshot::capture(&root).expect("capture baseline");
    fs::write(root.join("src/lib.rs"), CURRENT_SOURCE).expect("write commit change");
    format_fixture(&root);

    let report =
        CommitGate::verify(&engine(), &root, &baseline, &graph()).expect("Commit gate should run");

    assert!(
        report.checkpoint.patch.accepted,
        "PatchGate prerequisite failed: {:#?}",
        report.checkpoint.patch.entries
    );
    assert!(
        report.checkpoint.accepted,
        "CheckpointGate prerequisite failed: {:#?}",
        report.checkpoint.entries
    );
    assert!(
        report.accepted,
        "CommitGate rejected clean fixture: {:#?}",
        report.entries
    );

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
            "required Commit phase {phase:?} must pass with reproducible evidence"
        );
    }

    let mutation = report.mutation_plan.expect("mutation plan");
    let fuzz = report.fuzz_plan.expect("fuzz plan");
    assert_eq!(mutation.selections, 8);
    assert_eq!(mutation.iterations_per_selection, 1);
    assert_eq!(fuzz.selections, 2);
    assert_eq!(fuzz.iterations_per_selection, 256);
    assert_ne!(mutation.seed, fuzz.seed);

    fs::remove_dir_all(root).ok();
}

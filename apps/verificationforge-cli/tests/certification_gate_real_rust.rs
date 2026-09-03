use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use verificationforge_adapter_rust::RustAdapter;
use verificationforge_core::{CodeNode, CodeNodeKind, SymbolId, UniversalCodeGraph};
use verificationforge_runtime::{
    AdapterRegistry, CertificationGate, CertificationGatePhase, CheckStatus,
    ProcessExecutionAdapter, RepositorySnapshot, VerificationEngine,
};

fn temp_dir(name: &str) -> PathBuf {
    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("clock before epoch")
        .as_nanos();
    std::env::temp_dir().join(format!("verificationforge-real-cert-{name}-{nonce}"))
}

fn run(root: &Path, program: &str, args: &[&str]) {
    let status = Command::new(program)
        .args(args)
        .current_dir(root)
        .status()
        .unwrap_or_else(|error| panic!("run {program} {args:?}: {error}"));
    assert!(status.success(), "{program} {args:?} must succeed");
}

fn format_fixture(root: &Path) {
    run(root, "cargo", &["fmt", "--all"]);
}

fn generate_lockfile(root: &Path) {
    run(root, "cargo", &["generate-lockfile", "--offline"]);
}

fn init_git(root: &Path) {
    run(root, "git", &["init", "-q"]);
    run(
        root,
        "git",
        &["config", "user.name", "VerificationForge CI"],
    );
    run(
        root,
        "git",
        &["config", "user.email", "verificationforge@example.invalid"],
    );
}

fn commit_all(root: &Path, message: &str) {
    run(root, "git", &["add", "-A"]);
    run(root, "git", &["commit", "-q", "-m", message]);
}

fn write_fixture(root: &Path, source: &str) {
    fs::create_dir_all(root.join("src/bin")).expect("create bin directory");
    fs::create_dir_all(root.join("tests")).expect("create integration directory");
    fs::create_dir_all(root.join(".verificationforge")).expect("create harness directory");

    fs::write(
        root.join("Cargo.toml"),
        "[package]\nname = \"cert-fixture\"\nversion = \"0.1.0\"\nedition = \"2024\"\n",
    )
    .expect("write manifest");
    fs::write(root.join("src/lib.rs"), source).expect("write source");
    fs::write(
        root.join("tests/integration.rs"),
        r#"use cert_fixture::{double, identity, store_value};

#[test]
fn integration_core_behavior() {
    assert_eq!(identity(23), 23);
    assert_eq!(double(23), 46);
    assert_eq!(store_value(23, false), Ok(23));
    assert!(store_value(23, true).is_err());
}
"#,
    )
    .expect("write integration test");
    fs::write(
        root.join("src/bin/certification_harness.rs"),
        CERTIFICATION_HARNESS,
    )
    .expect("write certification harness binary");

    write_argv(
        root,
        "commit-mutation",
        &["commit-mutation", "{seed}", "{selections}", "{iterations}"],
    );
    write_argv(
        root,
        "commit-fuzz",
        &["commit-fuzz", "{seed}", "{selections}", "{iterations}"],
    );
    for phase in [
        "full-mutation",
        "extended-fuzz",
        "concurrency",
        "stress",
        "fault-injection",
        "resource-leaks",
        "sandbox",
        "reproducibility",
    ] {
        write_argv(
            root,
            &format!("certification-{phase}"),
            &[phase, "{seed}", "{iterations}"],
        );
    }

    format_fixture(root);
    generate_lockfile(root);
}

fn write_argv(root: &Path, name: &str, trailing: &[&str]) {
    let mut lines = vec![
        "cargo",
        "run",
        "--quiet",
        "--bin",
        "certification_harness",
        "--",
    ];
    lines.extend_from_slice(trailing);
    fs::write(
        root.join(format!(".verificationforge/{name}.argv")),
        format!("{}\n", lines.join("\n")),
    )
    .expect("write argv harness");
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
    graph.add_node(CodeNode {
        id: SymbolId("rust:concurrency:counter".into()),
        kind: CodeNodeKind::ConcurrencyPrimitive,
        language: Some("Rust".into()),
        path: Some("src/lib.rs".into()),
        display_name: "concurrent_accumulate".into(),
    });
    graph
}

fn engine() -> VerificationEngine {
    let mut registry = AdapterRegistry::default();
    registry.register(Arc::new(RustAdapter));
    VerificationEngine::new(registry, Arc::new(ProcessExecutionAdapter))
}

fn clean_fixture(name: &str) -> (PathBuf, RepositorySnapshot) {
    let root = temp_dir(name);
    write_fixture(&root, BASELINE_SOURCE);
    init_git(&root);
    commit_all(&root, "baseline");
    let baseline = RepositorySnapshot::capture(&root).expect("capture baseline");
    fs::write(root.join("src/lib.rs"), CURRENT_SOURCE).expect("write current source");
    format_fixture(&root);
    commit_all(&root, "current implementation");
    (root, baseline)
}

const BASELINE_SOURCE: &str = r#"use std::fs;
use std::io;
use std::path::{Component, Path};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::thread;

pub fn identity(input: u8) -> u8 {
    input
}

pub fn double(input: u8) -> u8 {
    input.saturating_mul(2)
}

pub fn store_value(input: u8, inject_failure: bool) -> Result<u8, &'static str> {
    if inject_failure {
        Err("injected failure")
    } else {
        Ok(input)
    }
}

pub fn concurrent_accumulate(workers: usize, operations_per_worker: usize) -> usize {
    let counter = Arc::new(AtomicUsize::new(0));
    let mut handles = Vec::with_capacity(workers);
    for _ in 0..workers {
        let counter = Arc::clone(&counter);
        handles.push(thread::spawn(move || {
            for _ in 0..operations_per_worker {
                counter.fetch_add(1, Ordering::SeqCst);
            }
        }));
    }
    for handle in handles {
        handle.join().expect("worker must not panic");
    }
    counter.load(Ordering::SeqCst)
}

pub fn sandbox_write(root: &Path, relative: &Path, content: &[u8]) -> io::Result<()> {
    if relative.is_absolute()
        || relative.components().any(|component| {
            matches!(
                component,
                Component::ParentDir | Component::RootDir | Component::Prefix(_)
            )
        })
    {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "path escapes sandbox",
        ));
    }
    let destination = root.join(relative);
    if let Some(parent) = destination.parent() {
        fs::create_dir_all(parent)?;
    }
    fs::write(destination, content)
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
    fn injected_failure_is_observable() {
        assert_eq!(store_value(7, false), Ok(7));
        assert!(store_value(7, true).is_err());
    }

    #[test]
    fn concurrent_counter_reaches_expected_total() {
        assert_eq!(concurrent_accumulate(4, 128), 512);
    }
}
"#;

const CURRENT_SOURCE: &str = r#"use std::fs;
use std::io;
use std::path::{Component, Path};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::thread;

pub fn identity(input: u8) -> u8 {
    input
}

pub fn double(input: u8) -> u8 {
    input.saturating_mul(2)
}

pub fn triple(input: u8) -> u8 {
    input.saturating_mul(3)
}

pub fn store_value(input: u8, inject_failure: bool) -> Result<u8, &'static str> {
    if inject_failure {
        Err("injected failure")
    } else {
        Ok(input)
    }
}

pub fn concurrent_accumulate(workers: usize, operations_per_worker: usize) -> usize {
    let counter = Arc::new(AtomicUsize::new(0));
    let mut handles = Vec::with_capacity(workers);
    for _ in 0..workers {
        let counter = Arc::clone(&counter);
        handles.push(thread::spawn(move || {
            for _ in 0..operations_per_worker {
                counter.fetch_add(1, Ordering::SeqCst);
            }
        }));
    }
    for handle in handles {
        handle.join().expect("worker must not panic");
    }
    counter.load(Ordering::SeqCst)
}

pub fn sandbox_write(root: &Path, relative: &Path, content: &[u8]) -> io::Result<()> {
    if relative.is_absolute()
        || relative.components().any(|component| {
            matches!(
                component,
                Component::ParentDir | Component::RootDir | Component::Prefix(_)
            )
        })
    {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "path escapes sandbox",
        ));
    }
    let destination = root.join(relative);
    if let Some(parent) = destination.parent() {
        fs::create_dir_all(parent)?;
    }
    fs::write(destination, content)
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
        assert_eq!(triple(100), 255);
    }

    #[test]
    fn injected_failure_is_observable() {
        assert_eq!(store_value(7, false), Ok(7));
        assert!(store_value(7, true).is_err());
    }

    #[test]
    fn concurrent_counter_reaches_expected_total() {
        assert_eq!(concurrent_accumulate(4, 128), 512);
    }
}
"#;

const CERTIFICATION_HARNESS: &str = r#"use std::env;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::{self, Command};

use cert_fixture::{
    concurrent_accumulate, double, identity, sandbox_write, store_value, triple,
};

fn main() {
    let args = env::args().collect::<Vec<_>>();
    if args.len() < 4 {
        eprintln!("usage: certification_harness PHASE SEED ...");
        process::exit(64);
    }
    let phase = args[1].as_str();
    let seed = parse_seed(&args[2]);
    match phase {
        "commit-mutation" => {
            require_len(&args, 5);
            let selections = parse_usize(&args[3], "selections");
            let iterations = parse_usize(&args[4], "iterations");
            if selections == 0 || iterations == 0 {
                fail("commit mutation requires non-zero selections and iterations");
            }
            let (_, executed, survived) = run_mutations(seed, Some(selections));
            if survived != 0 {
                fail("a sampled mutant survived");
            }
            println!(
                "commit-mutation seed={seed:016x} selections={selections} executed={executed} iterations={iterations}"
            );
        }
        "commit-fuzz" => {
            require_len(&args, 5);
            let selections = parse_usize(&args[3], "selections");
            let iterations = parse_usize(&args[4], "iterations");
            let total = selections.saturating_mul(iterations);
            if total == 0 {
                fail("commit fuzz requires non-zero work");
            }
            deterministic_fuzz(seed, total);
            println!(
                "commit-fuzz seed={seed:016x} selections={selections} iterations={iterations}"
            );
        }
        "full-mutation" => {
            require_len(&args, 4);
            let iterations = parse_usize(&args[3], "iterations");
            if iterations == 0 {
                fail("full mutation requires non-zero work");
            }
            let (discovered, executed, survived) = run_mutations(seed, None);
            println!("VF_CERT_FULL_MUTATION_TOTAL={discovered}");
            println!("VF_CERT_FULL_MUTATION_DISCOVERED={discovered}");
            println!("VF_CERT_FULL_MUTATION_EXECUTED={executed}");
            println!("VF_CERT_FULL_MUTATION_SURVIVED={survived}");
            if discovered == 0 || executed != discovered || survived != 0 {
                process::exit(2);
            }
        }
        "extended-fuzz" => {
            require_len(&args, 4);
            let iterations = parse_usize(&args[3], "iterations");
            deterministic_fuzz(seed, iterations);
            println!("VF_CERT_FUZZ_ITERATIONS={iterations}");
        }
        "concurrency" => {
            require_len(&args, 4);
            let iterations = parse_usize(&args[3], "iterations");
            let workers = 8usize;
            let per_worker = iterations.div_ceil(workers);
            let cases = workers.saturating_mul(per_worker);
            assert_eq!(concurrent_accumulate(workers, per_worker), cases);
            println!("VF_CERT_CONCURRENCY_CASES={cases}");
        }
        "stress" => {
            require_len(&args, 4);
            let iterations = parse_usize(&args[3], "iterations");
            for index in 0..iterations {
                let value = (index & 0xff) as u8;
                assert_eq!(identity(value), value);
                assert_eq!(double(value), value.saturating_mul(2));
                assert_eq!(triple(value), value.saturating_mul(3));
            }
            println!("VF_CERT_STRESS_ITERATIONS={iterations}");
        }
        "fault-injection" => {
            require_len(&args, 4);
            let iterations = parse_usize(&args[3], "iterations");
            for index in 0..iterations {
                let value = (index & 0xff) as u8;
                let inject_failure = index % 2 == 0;
                let result = store_value(value, inject_failure);
                if inject_failure {
                    assert!(result.is_err());
                } else {
                    assert_eq!(result, Ok(value));
                }
            }
            println!("VF_CERT_FAULT_CASES={iterations}");
        }
        "resource-leaks" => {
            require_len(&args, 4);
            let iterations = parse_usize(&args[3], "iterations");
            let before = descriptor_count();
            for _ in 0..iterations {
                let file = fs::File::open("Cargo.toml").expect("open manifest");
                drop(file);
            }
            let after = descriptor_count();
            let leaks = after.saturating_sub(before);
            println!("VF_CERT_RESOURCE_SAMPLES={iterations}");
            println!("VF_CERT_RESOURCE_LEAKS={leaks}");
            if leaks != 0 {
                process::exit(2);
            }
        }
        "sandbox" => {
            require_len(&args, 4);
            let iterations = parse_usize(&args[3], "iterations");
            run_sandbox(seed, iterations);
            println!("VF_CERT_SANDBOX_CASES={iterations}");
            println!("VF_CERT_SANDBOX_ESCAPE=0");
        }
        "reproducibility" => {
            require_len(&args, 4);
            let iterations = parse_usize(&args[3], "iterations");
            let source = fs::read("src/lib.rs").expect("read source");
            let lock = fs::read("Cargo.lock").expect("read lockfile");
            let mut hash = 0xcbf2_9ce4_8422_2325u64;
            for byte in seed
                .to_le_bytes()
                .into_iter()
                .chain(iterations.to_le_bytes())
                .chain(source)
                .chain(lock)
            {
                hash ^= u64::from(byte);
                hash = hash.wrapping_mul(0x0000_0100_0000_01b3);
            }
            println!("VF_CERT_REPRODUCIBLE=1");
            println!("artifact={hash:016x}");
        }
        other => fail(&format!("unknown phase {other}")),
    }
}

fn deterministic_fuzz(seed: u64, iterations: usize) {
    if iterations == 0 {
        fail("fuzz requires non-zero iterations");
    }
    let mut state = seed ^ 0x9e37_79b9_7f4a_7c15;
    for input in [0_u8, 1, 2, 63, 127, 128, 254, 255] {
        verify(input);
    }
    for _ in 0..iterations {
        state = xorshift64(state);
        verify(state as u8);
    }
}

fn verify(input: u8) {
    assert_eq!(identity(input), input);
    assert_eq!(double(input), input.saturating_mul(2));
    assert_eq!(triple(input), input.saturating_mul(3));
}

fn run_mutations(seed: u64, limit: Option<usize>) -> (usize, usize, usize) {
    let source = fs::read_to_string("src/lib.rs").expect("read source");
    let candidates = [
        (
            "pub fn identity(input: u8) -> u8 {\n    input\n}",
            "pub fn identity(input: u8) -> u8 {\n    input.saturating_add(1)\n}",
        ),
        ("input.saturating_mul(2)", "input.saturating_mul(3)"),
        ("input.saturating_mul(3)", "input.saturating_mul(2)"),
    ];
    let discovered = candidates.len();
    let count = limit.unwrap_or(discovered).min(discovered);
    let start = (seed as usize) % discovered;
    let mut survived = 0usize;

    for sample_index in 0..count {
        let candidate_index = (start + sample_index) % discovered;
        let (from, to) = candidates[candidate_index];
        let mutated = source.replacen(from, to, 1);
        if mutated == source {
            fail(&format!("mutation candidate {candidate_index} did not match source"));
        }
        let root = mutation_root(seed, sample_index);
        fs::remove_dir_all(&root).ok();
        fs::create_dir_all(root.join("src")).expect("create mutant source directory");
        fs::create_dir_all(root.join("tests")).expect("create mutant tests directory");
        fs::copy("Cargo.toml", root.join("Cargo.toml")).expect("copy manifest");
        fs::copy("Cargo.lock", root.join("Cargo.lock")).expect("copy lockfile");
        fs::write(root.join("src/lib.rs"), mutated).expect("write mutant source");
        fs::copy("tests/integration.rs", root.join("tests/integration.rs"))
            .expect("copy integration tests");

        let status = Command::new("cargo")
            .arg("test")
            .arg("--manifest-path")
            .arg(root.join("Cargo.toml"))
            .arg("--locked")
            .arg("--offline")
            .arg("--quiet")
            .status()
            .expect("run mutant tests");
        fs::remove_dir_all(&root).ok();
        if status.success() {
            survived += 1;
        }
    }
    (discovered, count, survived)
}

fn mutation_root(seed: u64, index: usize) -> PathBuf {
    env::temp_dir().join(format!(
        "verificationforge-cert-mutant-{}-{seed:016x}-{index}",
        process::id()
    ))
}

fn run_sandbox(seed: u64, iterations: usize) {
    if iterations == 0 {
        fail("sandbox requires non-zero iterations");
    }
    let root = env::temp_dir().join(format!(
        "verificationforge-cert-sandbox-{}-{seed:016x}",
        process::id()
    ));
    fs::remove_dir_all(&root).ok();
    fs::create_dir_all(&root).expect("create sandbox root");
    let outside = root
        .parent()
        .expect("sandbox has parent")
        .join(format!("verificationforge-cert-escape-{}", process::id()));
    fs::remove_file(&outside).ok();

    for index in 0..iterations {
        if index % 4 == 0 {
            let relative = PathBuf::from(format!("safe/{index}.txt"));
            sandbox_write(&root, &relative, b"safe").expect("safe sandbox write");
            assert!(root.join(relative).is_file());
        } else {
            let attack = if index % 2 == 0 {
                PathBuf::from("../../escape.txt")
            } else {
                PathBuf::from("../escape.txt")
            };
            assert!(sandbox_write(&root, &attack, b"escape").is_err());
        }
    }
    assert!(!outside.exists());
    fs::remove_dir_all(root).ok();
}

fn descriptor_count() -> usize {
    fs::read_dir("/proc/self/fd")
        .expect("Linux /proc/self/fd is required by this CI proof")
        .count()
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
    let prefix = value.get(..16).expect("seed must contain 16 hex digits");
    u64::from_str_radix(prefix, 16).expect("seed must be hexadecimal")
}

fn parse_usize(value: &str, name: &str) -> usize {
    value
        .parse::<usize>()
        .unwrap_or_else(|_| panic!("{name} must be an integer"))
}

fn require_len(args: &[String], expected: usize) {
    if args.len() != expected {
        fail(&format!("expected {expected} arguments, got {}", args.len()));
    }
}

fn fail(message: &str) -> ! {
    eprintln!("{message}");
    process::exit(64)
}
"#;

#[test]
#[ignore = "requires cargo-llvm-cov; CI installs it and runs this proof explicitly"]
fn real_rust_certification_gate_runs_full_adversarial_suite() {
    let (root, baseline) = clean_fixture("clean");
    let report = CertificationGate::verify(&engine(), &root, &baseline, &graph())
        .expect("Certification gate should run");

    assert!(report.commit.accepted, "CommitGate prerequisite failed");
    assert!(
        report.accepted,
        "CertificationGate rejected clean fixture: {:#?}",
        report.entries
    );

    for phase in [
        CertificationGatePhase::FullMutation,
        CertificationGatePhase::ExtendedFuzz,
        CertificationGatePhase::Concurrency,
        CertificationGatePhase::Stress,
        CertificationGatePhase::FaultInjection,
        CertificationGatePhase::ResourceLeaks,
        CertificationGatePhase::Dependencies,
        CertificationGatePhase::Security,
        CertificationGatePhase::HistorySecurity,
        CertificationGatePhase::Sandbox,
        CertificationGatePhase::Reproducibility,
        CertificationGatePhase::RepositoryStability,
    ] {
        assert!(
            report.entries.iter().any(|entry| {
                entry.phase == phase
                    && entry.result.status == CheckStatus::Pass
                    && entry.result.has_reproducible_evidence()
            }),
            "required Certification phase {phase:?} must pass with reproducible evidence"
        );
    }
    assert!(report.entries.iter().any(|entry| {
        entry.phase == CertificationGatePhase::UiExploration
            && entry.result.status == CheckStatus::Skipped
    }));

    fs::remove_dir_all(root).ok();
}

#[test]
#[ignore = "requires cargo-llvm-cov; CI installs it and runs this proof explicitly"]
fn real_rust_certification_rejects_removed_historical_secret() {
    let root = temp_dir("history-secret");
    write_fixture(&root, BASELINE_SOURCE);
    init_git(&root);
    commit_all(&root, "baseline");

    fs::write(root.join("legacy.txt"), "password=\"supersecret123\"\n")
        .expect("write historical secret");
    commit_all(&root, "legacy credential mistake");
    fs::remove_file(root.join("legacy.txt")).expect("remove historical secret");
    commit_all(&root, "remove legacy credential");

    let baseline = RepositorySnapshot::capture(&root).expect("capture clean baseline");
    fs::write(root.join("src/lib.rs"), CURRENT_SOURCE).expect("write current source");
    format_fixture(&root);
    commit_all(&root, "current implementation");

    let report = CertificationGate::verify(&engine(), &root, &baseline, &graph())
        .expect("Certification gate should run");
    assert!(report.commit.accepted, "CommitGate prerequisite failed");
    assert!(
        !report.accepted,
        "historical secret must block certification"
    );
    assert!(report.entries.iter().any(|entry| {
        entry.phase == CertificationGatePhase::HistorySecurity
            && entry.result.status == CheckStatus::Fail
            && entry
                .result
                .findings
                .iter()
                .any(|finding| finding.code == "VF_CERT_HISTORY_SECRET")
    }));

    fs::remove_dir_all(root).ok();
}

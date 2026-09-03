use std::fs;
use std::path::PathBuf;
use std::process::ExitCode;
use std::sync::Arc;

use verificationforge_adapter_c_family::{CAdapter, CSharpAdapter, CppAdapter};
use verificationforge_adapter_fallback::builtin_fallback_adapters;
use verificationforge_adapter_go::GoAdapter;
use verificationforge_adapter_js_family::{JavaScriptAdapter, TypeScriptAdapter};
use verificationforge_adapter_jvm_family::{JavaAdapter, KotlinAdapter, ScalaAdapter};
use verificationforge_adapter_python::PythonAdapter;
use verificationforge_adapter_rust::RustAdapter;
use verificationforge_runtime::{
    AdapterRegistry, CheckStatus, ProcessExecutionAdapter, RepositoryConfig, RiskTier,
    VerificationEngine, VerificationLevel, VerificationSession,
};

struct CliConfig {
    path: PathBuf,
    level: VerificationLevel,
    risk: Option<RiskTier>,
    journal_dir: Option<PathBuf>,
    certification_json: Option<PathBuf>,
}

fn main() -> ExitCode {
    match run() {
        Ok(true) => ExitCode::SUCCESS,
        Ok(false) => ExitCode::from(1),
        Err(error) => {
            eprintln!("VERIFICATIONFORGE_ERROR={error}");
            ExitCode::from(2)
        }
    }
}

fn run() -> Result<bool, String> {
    let config = parse_args()?;
    let canonical = config
        .path
        .canonicalize()
        .map_err(|error| format!("cannot resolve {}: {error}", config.path.display()))?;
    if !canonical.is_dir() {
        return Err(format!("{} is not a directory", canonical.display()));
    }

    let mut repository_config = RepositoryConfig::load(&canonical)?;
    if let Some(risk) = config.risk {
        repository_config.risk = Some(risk);
    }
    let policy = repository_config.policy(default_risk(config.level));

    let mut registry = AdapterRegistry::default();
    registry.register(Arc::new(RustAdapter));
    registry.register(Arc::new(PythonAdapter));
    registry.register(Arc::new(GoAdapter));
    registry.register(Arc::new(JavaScriptAdapter));
    registry.register(Arc::new(TypeScriptAdapter));
    registry.register(Arc::new(CAdapter));
    registry.register(Arc::new(CppAdapter));
    registry.register(Arc::new(CSharpAdapter));
    registry.register(Arc::new(JavaAdapter));
    registry.register(Arc::new(KotlinAdapter));
    registry.register(Arc::new(ScalaAdapter));
    for adapter in builtin_fallback_adapters() {
        registry.register(adapter);
    }

    let engine = VerificationEngine::new(registry, Arc::new(ProcessExecutionAdapter));
    let session = match &config.journal_dir {
        Some(root) => {
            VerificationSession::run_journaled(&engine, &canonical, config.level, &policy, root)?
        }
        None => VerificationSession::run(&engine, &canonical, config.level, &policy)?,
    };
    let report = &session.report;

    if let Some(path) = &config.certification_json {
        if let Some(parent) = path
            .parent()
            .filter(|parent| !parent.as_os_str().is_empty())
        {
            fs::create_dir_all(parent).map_err(|error| {
                format!(
                    "cannot create certification directory {}: {error}",
                    parent.display()
                )
            })?;
        }
        fs::write(path, session.certification.to_json()).map_err(|error| {
            format!(
                "cannot write certification artifact {}: {error}",
                path.display()
            )
        })?;
    }

    println!("VERIFICATIONFORGE_PROJECT={}", canonical.display());
    println!("VERIFICATIONFORGE_LEVEL={:?}", config.level);
    println!("VERIFICATIONFORGE_RISK={:?}", policy.risk);
    println!(
        "VERIFICATIONFORGE_POLICY_MINIMUM_LEVEL={:?}",
        policy.minimum_level
    );
    if let Some(address) = &session.snapshot.address {
        println!("VERIFICATIONFORGE_REPOSITORY_ADDRESS={}", address.0);
    }
    for detection in &report.detections {
        println!(
            "VERIFICATIONFORGE_LANGUAGE={} adapter={} confidence={}%",
            detection.language, detection.adapter_id, detection.confidence_percent
        );
    }

    for entry in &report.checks {
        println!(
            "VERIFICATIONFORGE_CHECK={} language={} status={}",
            entry.result.check,
            entry.language,
            status_name(entry.result.status)
        );
        for finding in &entry.result.findings {
            println!(
                "VERIFICATIONFORGE_FINDING={} blocking={} message={}",
                finding.code,
                finding.blocking,
                sanitize(&finding.message)
            );
        }
    }

    for blocker in &session.certification.blockers {
        println!(
            "VERIFICATIONFORGE_POLICY_BLOCKER={} message={}",
            blocker.code,
            sanitize(&blocker.message)
        );
    }

    println!("VERIFICATIONFORGE_FAILED_CHECKS={}", report.failed_checks());
    println!(
        "VERIFICATIONFORGE_UNSUPPORTED_CHECKS={}",
        report.unsupported_checks()
    );
    println!(
        "VERIFICATIONFORGE_EVIDENCE_BACKED_PASSES={}",
        session.certification.evidence_backed_passes
    );
    println!(
        "VERIFICATIONFORGE_BARE_PASSES={}",
        session.certification.bare_passes
    );
    println!(
        "VERIFICATIONFORGE_CERTIFICATION_ID={}",
        session.certification.id.0
    );
    if let Some(path) = &session.journal_path {
        println!("VERIFICATIONFORGE_JOURNAL={}", path.display());
    }
    if let Some(path) = &config.certification_json {
        println!("VERIFICATIONFORGE_CERTIFICATION_JSON={}", path.display());
    }
    println!(
        "VERIFICATIONFORGE_ACCEPTED={}",
        session.certification.accepted
    );

    Ok(session.certification.accepted)
}

fn parse_args() -> Result<CliConfig, String> {
    let mut args = std::env::args_os().skip(1).peekable();
    let mut path = None;
    let mut level = VerificationLevel::Patch;
    let mut risk = None;
    let mut journal_dir = Some(std::env::temp_dir().join("verificationforge-runs"));
    let mut certification_json = None;

    while let Some(arg) = args.next() {
        let text = arg.to_string_lossy();
        if text == "--help" || text == "-h" {
            return Err(usage().into());
        }
        if text == "--level" {
            let value = args
                .next()
                .ok_or_else(|| "--level requires a value".to_owned())?;
            level = value.to_string_lossy().parse::<VerificationLevel>()?;
            continue;
        }
        if let Some(value) = text.strip_prefix("--level=") {
            level = value.parse::<VerificationLevel>()?;
            continue;
        }
        if text == "--risk" {
            let value = args
                .next()
                .ok_or_else(|| "--risk requires a value".to_owned())?;
            risk = Some(parse_risk(&value.to_string_lossy())?);
            continue;
        }
        if let Some(value) = text.strip_prefix("--risk=") {
            risk = Some(parse_risk(value)?);
            continue;
        }
        if text == "--journal-dir" {
            journal_dir = Some(PathBuf::from(
                args.next()
                    .ok_or_else(|| "--journal-dir requires a path".to_owned())?,
            ));
            continue;
        }
        if let Some(value) = text.strip_prefix("--journal-dir=") {
            journal_dir = Some(PathBuf::from(value));
            continue;
        }
        if text == "--no-journal" {
            journal_dir = None;
            continue;
        }
        if text == "--certification-json" {
            certification_json =
                Some(PathBuf::from(args.next().ok_or_else(|| {
                    "--certification-json requires a path".to_owned()
                })?));
            continue;
        }
        if let Some(value) = text.strip_prefix("--certification-json=") {
            certification_json = Some(PathBuf::from(value));
            continue;
        }
        if text.starts_with('-') {
            return Err(format!("unknown option: {text}"));
        }
        if path.is_some() {
            return Err(format!("unexpected extra path argument: {text}"));
        }
        path = Some(PathBuf::from(arg));
    }

    Ok(CliConfig {
        path: path.unwrap_or_else(|| PathBuf::from(".")),
        level,
        risk,
        journal_dir,
        certification_json,
    })
}

fn default_risk(level: VerificationLevel) -> RiskTier {
    match level {
        VerificationLevel::Patch => RiskTier::Low,
        VerificationLevel::Checkpoint => RiskTier::Medium,
        VerificationLevel::Commit => RiskTier::High,
        VerificationLevel::Certification | VerificationLevel::Formal => RiskTier::Critical,
    }
}

fn parse_risk(value: &str) -> Result<RiskTier, String> {
    match value.to_ascii_lowercase().as_str() {
        "low" => Ok(RiskTier::Low),
        "medium" => Ok(RiskTier::Medium),
        "high" => Ok(RiskTier::High),
        "critical" => Ok(RiskTier::Critical),
        other => Err(format!("unknown risk tier: {other}")),
    }
}

fn usage() -> &'static str {
    "usage: verificationforge-cli [PATH] [--level patch|checkpoint|commit|certification|formal] [--risk low|medium|high|critical] [--journal-dir PATH|--no-journal] [--certification-json PATH]"
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

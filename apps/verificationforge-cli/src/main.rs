use std::path::PathBuf;
use std::process::ExitCode;
use std::sync::Arc;
use verificationforge_adapter_python::PythonAdapter;
use verificationforge_adapter_rust::RustAdapter;
use verificationforge_runtime::{
    AdapterRegistry, CheckStatus, ProcessExecutionAdapter, VerificationEngine, VerificationLevel,
};

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
    let (path, level) = parse_args()?;
    let canonical = path
        .canonicalize()
        .map_err(|error| format!("cannot resolve {}: {error}", path.display()))?;
    if !canonical.is_dir() {
        return Err(format!("{} is not a directory", canonical.display()));
    }

    let mut registry = AdapterRegistry::default();
    registry.register(Arc::new(RustAdapter));
    registry.register(Arc::new(PythonAdapter));

    let engine = VerificationEngine::new(registry, Arc::new(ProcessExecutionAdapter));
    let report = engine.verify(&canonical, level);

    println!("VERIFICATIONFORGE_PROJECT={}", canonical.display());
    println!("VERIFICATIONFORGE_LEVEL={level:?}");
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

    println!("VERIFICATIONFORGE_FAILED_CHECKS={}", report.failed_checks());
    println!(
        "VERIFICATIONFORGE_UNSUPPORTED_CHECKS={}",
        report.unsupported_checks()
    );
    println!("VERIFICATIONFORGE_ACCEPTED={}", report.accepted);

    Ok(report.accepted)
}

fn parse_args() -> Result<(PathBuf, VerificationLevel), String> {
    let mut args = std::env::args_os().skip(1).peekable();
    let mut path = None;
    let mut level = VerificationLevel::Patch;

    while let Some(arg) = args.next() {
        let text = arg.to_string_lossy();
        if text == "--help" || text == "-h" {
            return Err("usage: verificationforge-cli [PATH] [--level patch|checkpoint|commit|certification|formal]".into());
        }
        if text == "--level" {
            let value = args
                .next()
                .ok_or_else(|| "--level requires a value".to_owned())?;
            level = value
                .to_string_lossy()
                .parse::<VerificationLevel>()?;
            continue;
        }
        if let Some(value) = text.strip_prefix("--level=") {
            level = value.parse::<VerificationLevel>()?;
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

    Ok((path.unwrap_or_else(|| PathBuf::from(".")), level))
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

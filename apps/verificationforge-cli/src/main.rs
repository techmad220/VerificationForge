use std::path::PathBuf;
use std::sync::Arc;
use verificationforge_adapter_python::PythonAdapter;
use verificationforge_adapter_rust::RustAdapter;
use verificationforge_runtime::AdapterRegistry;

fn main() {
    let path = std::env::args_os()
        .nth(1)
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("."));
    let canonical = path.canonicalize().unwrap_or(path);

    let mut registry = AdapterRegistry::default();
    registry.register(Arc::new(RustAdapter));
    registry.register(Arc::new(PythonAdapter));

    println!("VERIFICATIONFORGE_PROJECT={}", canonical.display());
    let detections = registry.detect(&canonical);
    if detections.is_empty() {
        println!("VERIFICATIONFORGE_LANGUAGES=none");
    } else {
        for detection in detections {
            println!(
                "VERIFICATIONFORGE_LANGUAGE={} confidence={}%",
                detection.language, detection.confidence_percent
            );
        }
    }
}

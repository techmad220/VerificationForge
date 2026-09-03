# Native JVM Family Adapter

VerificationForge treats Java, Kotlin, and Scala as independent first-class language adapters sharing JVM-family execution helpers. Native adapters register before generic fallbacks, so the fallback profiles remain available without duplicate detections.

## Native responsibilities

- independent source detection and symbol inventory per language
- compile-backed parse and type checks
- deterministic built-in whitespace format policy
- warning-as-error lint where the native compiler supports it
- direct executable tests for source-only repositories
- Maven, Gradle, and sbt integration when repository build systems are present
- dependency-tree verification where the native build system is available
- placeholder and high-confidence fake-authorization detection
- explicit applicability for integration/property/UI/API/concurrency surfaces
- fail-closed repository harnesses for advanced checks that cannot be proven generically

## CI proof

The JVM family workflow pins a Java 21 toolchain, Kotlin compiler 2.4.10, and Scala CLI 1.16.0. Each language is verified against a real zero-dependency source/test fixture through the public VerificationForge CLI. Roadmap entries must remain unchecked until those fixtures and the existing VerificationForge CI suite pass on the exact implementation head.

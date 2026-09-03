use std::collections::BTreeSet;
use std::fs;
use std::path::{Path, PathBuf};

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ProjectInventory {
    pub languages: BTreeSet<String>,
    pub frameworks: BTreeSet<String>,
    pub build_systems: BTreeSet<String>,
    pub package_managers: BTreeSet<String>,
    pub test_systems: BTreeSet<String>,
    pub ui_technologies: BTreeSet<String>,
    pub api_technologies: BTreeSet<String>,
    pub database_technologies: BTreeSet<String>,
    pub smart_contract_technologies: BTreeSet<String>,
    pub shader_technologies: BTreeSet<String>,
    pub infrastructure_technologies: BTreeSet<String>,
}

impl ProjectInventory {
    pub fn detect(repo: &Path) -> Self {
        let mut inventory = Self::default();
        let files = repository_files(repo);

        for path in &files {
            let relative = path.strip_prefix(repo).unwrap_or(path);
            let relative_text = relative.to_string_lossy().replace('\\', "/");
            let file_name = path
                .file_name()
                .and_then(|value| value.to_str())
                .unwrap_or_default();
            let extension = path
                .extension()
                .and_then(|value| value.to_str())
                .unwrap_or_default()
                .to_ascii_lowercase();

            match extension.as_str() {
                "rs" => {
                    inventory.languages.insert("Rust".into());
                }
                "py" | "pyi" => {
                    inventory.languages.insert("Python".into());
                }
                "html" | "htm" => {
                    inventory.ui_technologies.insert("HTML".into());
                }
                "css" | "scss" | "sass" => {
                    inventory.ui_technologies.insert("CSS".into());
                }
                "js" | "jsx" => {
                    inventory.ui_technologies.insert("JavaScript".into());
                }
                "ts" | "tsx" => {
                    inventory.ui_technologies.insert("TypeScript".into());
                }
                "sql" => {
                    inventory.database_technologies.insert("SQL".into());
                }
                "sol" => {
                    inventory.smart_contract_technologies.insert("Solidity".into());
                }
                "vy" => {
                    inventory.smart_contract_technologies.insert("Vyper".into());
                }
                "move" => {
                    inventory.smart_contract_technologies.insert("Move".into());
                }
                "cairo" => {
                    inventory.smart_contract_technologies.insert("Cairo".into());
                }
                "glsl" | "vert" | "frag" => {
                    inventory.shader_technologies.insert("GLSL".into());
                }
                "hlsl" => {
                    inventory.shader_technologies.insert("HLSL".into());
                }
                "wgsl" => {
                    inventory.shader_technologies.insert("WGSL".into());
                }
                "tf" => {
                    inventory.infrastructure_technologies.insert("Terraform".into());
                }
                _ => {}
            }

            match file_name {
                "Cargo.toml" => {
                    inventory.languages.insert("Rust".into());
                    inventory.build_systems.insert("Cargo".into());
                    inventory.package_managers.insert("Cargo".into());
                    inventory.test_systems.insert("cargo-test".into());
                }
                "pyproject.toml" => {
                    inventory.languages.insert("Python".into());
                    inventory.build_systems.insert("pyproject".into());
                    inventory.package_managers.insert("pip".into());
                }
                "setup.py" | "setup.cfg" => {
                    inventory.languages.insert("Python".into());
                    inventory.build_systems.insert("setuptools".into());
                    inventory.package_managers.insert("pip".into());
                }
                "requirements.txt" | "requirements-dev.txt" => {
                    inventory.languages.insert("Python".into());
                    inventory.package_managers.insert("pip".into());
                }
                "poetry.lock" => {
                    inventory.languages.insert("Python".into());
                    inventory.package_managers.insert("Poetry".into());
                }
                "uv.lock" => {
                    inventory.languages.insert("Python".into());
                    inventory.package_managers.insert("uv".into());
                }
                "pytest.ini" | "conftest.py" => {
                    inventory.test_systems.insert("pytest".into());
                }
                "Dockerfile" | "Containerfile" => {
                    inventory.infrastructure_technologies.insert("Container".into());
                }
                "docker-compose.yml" | "docker-compose.yaml" | "compose.yml" | "compose.yaml" => {
                    inventory.infrastructure_technologies.insert("Docker Compose".into());
                }
                "openapi.json" | "openapi.yaml" | "openapi.yml" | "swagger.json"
                | "swagger.yaml" | "swagger.yml" => {
                    inventory.api_technologies.insert("OpenAPI".into());
                }
                _ => {}
            }

            if relative_text.starts_with("migrations/")
                || relative_text.contains("/migrations/")
            {
                inventory.database_technologies.insert("Migrations".into());
            }

            if matches!(extension.as_str(), "yaml" | "yml") {
                if let Ok(content) = fs::read_to_string(path)
                    && content.contains("apiVersion:")
                    && content.contains("kind:")
                {
                    inventory
                        .infrastructure_technologies
                        .insert("Kubernetes".into());
                }
            }
        }

        scan_text_markers(repo, &files, &mut inventory);
        inventory
    }

    pub fn is_mixed_language(&self) -> bool {
        self.languages.len() > 1
    }
}

fn scan_text_markers(repo: &Path, files: &[PathBuf], inventory: &mut ProjectInventory) {
    for path in files {
        let extension = path
            .extension()
            .and_then(|value| value.to_str())
            .unwrap_or_default()
            .to_ascii_lowercase();
        if !matches!(extension.as_str(), "rs" | "py" | "toml" | "txt") {
            continue;
        }
        let Ok(content) = fs::read_to_string(path) else {
            continue;
        };
        let lower = content.to_ascii_lowercase();

        for (marker, framework) in [
            ("axum::", "Axum"),
            ("actix_web", "Actix Web"),
            ("rocket::", "Rocket"),
            ("django", "Django"),
            ("fastapi", "FastAPI"),
            ("flask", "Flask"),
        ] {
            if lower.contains(&marker.to_ascii_lowercase()) {
                inventory.frameworks.insert(framework.into());
            }
        }

        for (marker, api) in [
            ("axum::", "HTTP"),
            ("actix_web", "HTTP"),
            ("fastapi", "HTTP"),
            ("flask", "HTTP"),
            ("tonic::", "gRPC"),
            ("grpc", "gRPC"),
            ("websocket", "WebSocket"),
        ] {
            if lower.contains(&marker.to_ascii_lowercase()) {
                inventory.api_technologies.insert(api.into());
            }
        }

        for (marker, database) in [
            ("sqlx::", "SQLx"),
            ("diesel::", "Diesel"),
            ("rusqlite", "SQLite"),
            ("sqlalchemy", "SQLAlchemy"),
            ("django.db", "Django ORM"),
            ("psycopg", "PostgreSQL"),
        ] {
            if lower.contains(&marker.to_ascii_lowercase()) {
                inventory.database_technologies.insert(database.into());
            }
        }

        if lower.contains("pytest") {
            inventory.test_systems.insert("pytest".into());
        }
        if extension == "py" && lower.contains("unittest") {
            inventory.test_systems.insert("unittest".into());
        }
    }

    if repo.join("src").is_dir() && inventory.languages.contains("Rust") {
        inventory.build_systems.insert("Cargo".into());
    }
}

fn repository_files(repo: &Path) -> Vec<PathBuf> {
    let mut files = Vec::new();
    visit(repo, 0, &mut files);
    files
}

fn visit(path: &Path, depth: usize, files: &mut Vec<PathBuf>) {
    if depth > 32 {
        return;
    }
    let Ok(entries) = fs::read_dir(path) else {
        return;
    };
    for entry in entries.flatten() {
        let child = entry.path();
        let Ok(kind) = entry.file_type() else {
            continue;
        };
        if kind.is_symlink() {
            continue;
        }
        if kind.is_dir() {
            let name = entry.file_name();
            let name = name.to_string_lossy();
            if matches!(
                name.as_ref(),
                ".git" | "target" | "node_modules" | "vendor" | ".venv" | "venv" | "dist"
            ) {
                continue;
            }
            visit(&child, depth + 1, files);
        } else if kind.is_file() {
            files.push(child);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::{SystemTime, UNIX_EPOCH};

    fn temp_dir() -> PathBuf {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock before epoch")
            .as_nanos();
        std::env::temp_dir().join(format!("verificationforge-project-{nonce}"))
    }

    #[test]
    fn detects_mixed_rust_python_repository_and_ecosystems() {
        let root = temp_dir();
        fs::create_dir_all(root.join("src")).expect("create src");
        fs::create_dir_all(root.join("migrations")).expect("create migrations");
        fs::write(root.join("Cargo.toml"), "[package]\nname='demo'\nversion='0.1.0'\n")
            .expect("write Cargo.toml");
        fs::write(root.join("src/lib.rs"), "use axum::Router; use sqlx::Pool;\n")
            .expect("write rust");
        fs::write(root.join("pyproject.toml"), "[project]\nname='demo_py'\n")
            .expect("write pyproject");
        fs::write(root.join("service.py"), "from fastapi import FastAPI\nimport pytest\n")
            .expect("write python");
        fs::write(root.join("migrations/001.sql"), "select 1;\n").expect("write sql");
        fs::write(root.join("openapi.yaml"), "openapi: 3.1.0\n").expect("write api");
        fs::write(root.join("Dockerfile"), "FROM scratch\n").expect("write container");

        let inventory = ProjectInventory::detect(&root);
        assert!(inventory.is_mixed_language());
        assert!(inventory.languages.contains("Rust"));
        assert!(inventory.languages.contains("Python"));
        assert!(inventory.frameworks.contains("Axum"));
        assert!(inventory.frameworks.contains("FastAPI"));
        assert!(inventory.api_technologies.contains("OpenAPI"));
        assert!(inventory.database_technologies.contains("Migrations"));
        assert!(inventory.infrastructure_technologies.contains("Container"));
        fs::remove_dir_all(root).ok();
    }

    #[test]
    fn ignores_build_and_virtual_environment_directories() {
        let root = temp_dir();
        fs::create_dir_all(root.join("target/generated")).expect("create target");
        fs::create_dir_all(root.join(".venv/lib")).expect("create venv");
        fs::write(root.join("target/generated/fake.py"), "print('fake')\n").expect("write target");
        fs::write(root.join(".venv/lib/fake.rs"), "fn fake() {}\n").expect("write venv");
        let inventory = ProjectInventory::detect(&root);
        assert!(inventory.languages.is_empty());
        fs::remove_dir_all(root).ok();
    }
}

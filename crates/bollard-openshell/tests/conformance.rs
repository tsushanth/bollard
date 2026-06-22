// SPDX-License-Identifier: Apache-2.0
//
// Conformance: the YAML bollard-openshell emits is accepted by OpenShell's real
// parser (openshell_policy::parse_sandbox_policy), not just a lookalike.
//
// Gated on BOLLARD_OPENSHELL_VALIDATOR (path to the built `openshell-validate`
// binary), since that needs a local OpenShell checkout. Default `cargo test`
// skips it. To run:
//
//   cargo build --manifest-path tools/openshell-validate/Cargo.toml
//   BOLLARD_OPENSHELL_VALIDATOR=tools/openshell-validate/target/debug/openshell-validate \
//     cargo test -p bollard-openshell --test conformance

use std::io::Write;
use std::process::{Command, Stdio};

#[test]
fn translated_policy_is_accepted_by_openshell() {
    let Ok(raw) = std::env::var("BOLLARD_OPENSHELL_VALIDATOR") else {
        eprintln!("skipping: set BOLLARD_OPENSHELL_VALIDATOR to the openshell-validate binary");
        return;
    };
    // Resolve a relative path against the workspace root (tests run with cwd at
    // the crate dir), so the documented workspace-relative command just works.
    let validator = {
        let p = std::path::PathBuf::from(&raw);
        if p.is_absolute() {
            p
        } else {
            std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../..").join(p)
        }
    };

    let bp = bollard_openshell::BollardPolicy {
        allow_hosts: vec!["example.com".into(), "api.github.com".into()],
        conditional_hosts: vec!["example.org".into()],
        untrusted_labels: vec!["untrusted-web".into()],
        sensitive_labels: vec!["private".into()],
    };
    let yaml = serde_yaml::to_string(&bollard_openshell::to_openshell(&bp)).unwrap();

    let mut child = Command::new(&validator)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn validator");
    child.stdin.take().unwrap().write_all(yaml.as_bytes()).unwrap();
    let out = child.wait_with_output().expect("wait validator");

    assert!(
        out.status.success(),
        "OpenShell rejected the translated policy:\n{}",
        String::from_utf8_lossy(&out.stderr)
    );
}

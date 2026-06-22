// SPDX-License-Identifier: Apache-2.0
//
// Reads a sandbox-policy YAML on stdin and runs it through OpenShell's real
// parser (openshell_policy::parse_sandbox_policy). Exits 0 if OpenShell accepts
// it, 1 otherwise. Used by the bollard-openshell conformance test to prove the
// translator emits policy OpenShell actually accepts — not just our lookalike.

use std::io::Read;

fn main() {
    let mut yaml = String::new();
    std::io::stdin().read_to_string(&mut yaml).expect("read stdin");

    match openshell_policy::parse_sandbox_policy(&yaml) {
        Ok(policy) => {
            eprintln!(
                "OK: accepted by openshell-policy; {} network_policies",
                policy.network_policies.len()
            );
            std::process::exit(0);
        }
        Err(e) => {
            eprintln!("REJECTED by openshell-policy: {e:?}");
            std::process::exit(1);
        }
    }
}

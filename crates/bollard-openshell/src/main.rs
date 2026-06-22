// SPDX-License-Identifier: Apache-2.0
//
// bollard-openshell — translate a Bollard policy to an OpenShell sandbox policy
// and print, to stderr, the Bollard controls OpenShell cannot express.
//
//   bollard-openshell policy/default.yaml > openshell-policy.yaml

use std::io::Read;

fn main() {
    let input = match std::env::args().nth(1) {
        Some(path) => std::fs::read_to_string(&path).unwrap_or_else(|e| {
            eprintln!("error: cannot read {path}: {e}");
            std::process::exit(1);
        }),
        None => {
            let mut s = String::new();
            std::io::stdin().read_to_string(&mut s).expect("read stdin");
            s
        }
    };

    let bp = bollard_openshell::BollardPolicy::from_yaml(&input).unwrap_or_else(|e| {
        eprintln!("error: invalid Bollard policy: {e}");
        std::process::exit(1);
    });

    let os = bollard_openshell::to_openshell(&bp);
    print!("{}", serde_yaml::to_string(&os).expect("serialize"));

    let gaps = bollard_openshell::provenance_gap(&bp);
    if !gaps.is_empty() {
        eprintln!("\n# Not expressible in OpenShell policy — Bollard enforces these on top:");
        for g in gaps {
            eprintln!("#  - {g}");
        }
    }
}

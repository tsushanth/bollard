// SPDX-License-Identifier: Apache-2.0
//! Bollard ⇄ NVIDIA OpenShell adapter.
//!
//! OpenShell already enforces sandbox egress with a per-connection proxy in a
//! network namespace, but its policy keys decisions on the **caller** (binary
//! path + sha256 + process ancestors) and the destination host/port — never on
//! the **provenance of the data** in the request. Its inference router
//! (`openshell-router`) selects a backend by protocol match only, with no
//! sensitivity input. (Schema: `crates/openshell-policy/src/lib.rs`; egress
//! decision: `crates/openshell-supervisor-network/src/proxy.rs` →
//! `evaluate_opa_tcp`; route selection: `crates/openshell-router/src/lib.rs`
//! `proxy_with_candidates`.)
//!
//! This crate does two honest things:
//!   1. `to_openshell` — emit a Bollard policy's coarse host allowlist as a
//!      valid OpenShell `network_policies` block, so a Bollard user can deploy
//!      the host layer natively on OpenShell.
//!   2. `provenance_gap` — enumerate the Bollard controls that have **no**
//!      OpenShell equivalent, i.e. exactly what Bollard adds on top.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

// ---------------------------------------------------------------------------
// Bollard policy (the public schema shared with the broker).
// ---------------------------------------------------------------------------

#[derive(Debug, Default, Deserialize)]
pub struct BollardPolicy {
    #[serde(default)]
    pub allow_hosts: Vec<String>,
    #[serde(default)]
    pub conditional_hosts: Vec<String>,
    #[serde(default)]
    pub untrusted_labels: Vec<String>,
    #[serde(default)]
    pub sensitive_labels: Vec<String>,
}

impl BollardPolicy {
    pub fn from_yaml(yaml: &str) -> Result<BollardPolicy, serde_yaml::Error> {
        serde_yaml::from_str(yaml)
    }
}

// ---------------------------------------------------------------------------
// OpenShell policy schema (mirrors crates/openshell-policy/src/lib.rs; only the
// fields we emit). Field names must match exactly — OpenShell parses with
// `#[serde(deny_unknown_fields)]`.
// ---------------------------------------------------------------------------

#[derive(Debug, Default, Serialize, Deserialize)]
pub struct OpenShellPolicy {
    pub version: u32,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub network_policies: BTreeMap<String, NetworkPolicyRule>,
}

#[derive(Debug, Default, Serialize, Deserialize)]
pub struct NetworkPolicyRule {
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub name: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub endpoints: Vec<NetworkEndpoint>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub binaries: Vec<NetworkBinary>,
}

#[derive(Debug, Default, Serialize, Deserialize)]
pub struct NetworkEndpoint {
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub host: String,
    #[serde(default, skip_serializing_if = "is_zero")]
    pub port: u16,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub protocol: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub tls: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub enforcement: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub access: String,
}

#[derive(Debug, Default, Serialize, Deserialize)]
pub struct NetworkBinary {
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub path: String,
}

#[allow(clippy::trivially_copy_pass_by_ref)]
fn is_zero(v: &u16) -> bool {
    *v == 0
}

// ---------------------------------------------------------------------------
// Translation.
// ---------------------------------------------------------------------------

fn endpoint(host: &str) -> NetworkEndpoint {
    NetworkEndpoint {
        host: host.to_string(),
        port: 443,
        protocol: "rest".into(),
        tls: "terminate".into(),
        enforcement: "enforce".into(),
        access: "read-write".into(),
    }
}

/// Emit a Bollard policy's host allowlist as an OpenShell `network_policies`
/// block. Trusted and conditional hosts both become allowed endpoints — the
/// `conditional` distinction (allowed only while the context is clean) is lost,
/// because OpenShell has no provenance dimension. That loss is the point; see
/// [`provenance_gap`].
pub fn to_openshell(bp: &BollardPolicy) -> OpenShellPolicy {
    let mut endpoints: Vec<NetworkEndpoint> = Vec::new();
    for host in bp.allow_hosts.iter().chain(bp.conditional_hosts.iter()) {
        endpoints.push(endpoint(host));
    }
    let mut network_policies = BTreeMap::new();
    if !endpoints.is_empty() {
        network_policies.insert(
            "bollard-egress".to_string(),
            NetworkPolicyRule { name: "bollard_egress".into(), endpoints, binaries: Vec::new() },
        );
    }
    OpenShellPolicy { version: 1, network_policies }
}

/// The Bollard controls that OpenShell's policy model cannot express. These are
/// precisely the capabilities Bollard adds on top of an OpenShell deployment.
pub fn provenance_gap(bp: &BollardPolicy) -> Vec<String> {
    let mut gaps = Vec::new();
    if !bp.conditional_hosts.is_empty() {
        gaps.push(format!(
            "conditional egress to {:?}: OpenShell has no taint condition — it allows or denies a host \
             regardless of whether the request's data came from an untrusted or private source",
            bp.conditional_hosts
        ));
    }
    if !bp.untrusted_labels.is_empty() && !bp.sensitive_labels.is_empty() {
        gaps.push(
            "the lethal-trifecta rule (deny egress once a context holds both untrusted and sensitive \
             data): OpenShell keys decisions on caller binary identity, not data provenance"
                .to_string(),
        );
    }
    if !bp.sensitive_labels.is_empty() {
        gaps.push(
            "sensitivity-based inference routing: openshell-router selects a backend by protocol match \
             only (proxy_with_candidates), with no per-request sensitivity input"
                .to_string(),
        );
        gaps.push(
            "content-based DLP egress blocking: OpenShell does not block a request whose body carries a \
             registered secret value when the destination host is allowed"
                .to_string(),
        );
    }
    gaps
}

#[cfg(test)]
mod tests {
    use super::*;

    fn policy() -> BollardPolicy {
        BollardPolicy {
            allow_hosts: vec!["example.com".into()],
            conditional_hosts: vec!["example.org".into()],
            untrusted_labels: vec!["untrusted-web".into()],
            sensitive_labels: vec!["private".into()],
        }
    }

    #[test]
    fn emits_one_endpoint_per_host_on_443() {
        let os = to_openshell(&policy());
        let rule = os.network_policies.get("bollard-egress").unwrap();
        let hosts: Vec<&str> = rule.endpoints.iter().map(|e| e.host.as_str()).collect();
        assert_eq!(hosts, ["example.com", "example.org"]);
        assert!(rule.endpoints.iter().all(|e| e.port == 443 && e.enforcement == "enforce"));
    }

    #[test]
    fn output_is_valid_openshell_yaml_that_round_trips() {
        let yaml = serde_yaml::to_string(&to_openshell(&policy())).unwrap();
        assert!(yaml.contains("version: 1"));
        assert!(yaml.contains("host: example.com"));
        // OpenShell parses with deny_unknown_fields, so only known keys may appear.
        for key in ["untrusted", "sensitive", "conditional", "label"] {
            assert!(!yaml.contains(key), "leaked a Bollard-only field into OpenShell yaml: {key}");
        }
        let back: OpenShellPolicy = serde_yaml::from_str(&yaml).unwrap();
        assert_eq!(back.version, 1);
    }

    #[test]
    fn gap_lists_what_openshell_cannot_express() {
        let gaps = provenance_gap(&policy());
        // conditional egress + trifecta + inference routing + DLP
        assert_eq!(gaps.len(), 4);
        let empty = provenance_gap(&BollardPolicy::default());
        assert!(empty.is_empty());
    }
}

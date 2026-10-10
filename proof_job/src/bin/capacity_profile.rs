//! Finalizes a reviewed proof-capacity draft by computing its content-bound profile id and then
//! running the same closed-schema validation the operator uses at startup.

use std::{env, fs, process};

use serde::Deserialize;
use zylith_proof_job::{
    PROOF_CAPACITY_SCHEMA_VERSION, ProofCapacityProfile, ProofCapacityVector, ProofReleaseIdentity,
    ProofResourceUsage, ProofShapeLimits, ProofStatementKind,
};

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Draft {
    statement_kind: ProofStatementKind,
    identity: ProofReleaseIdentity,
    vector_family: String,
    safety_margin_bps: u16,
    capacity: ProofResourceUsage,
    limits: ProofShapeLimits,
    vectors: Vec<ProofCapacityVector>,
}

fn run(path: &str) -> Result<String, String> {
    let raw = fs::read_to_string(path).map_err(|error| format!("{path}: {error}"))?;
    let draft: Draft =
        serde_json::from_str(&raw).map_err(|error| format!("capacity draft: {error}"))?;
    let mut profile = ProofCapacityProfile {
        schema_version: PROOF_CAPACITY_SCHEMA_VERSION,
        profile_id: String::new(),
        statement_kind: draft.statement_kind,
        identity: draft.identity,
        vector_family: draft.vector_family,
        safety_margin_bps: draft.safety_margin_bps,
        capacity: draft.capacity,
        limits: draft.limits,
        vectors: draft.vectors,
    };
    profile.profile_id = profile.expected_profile_id()?;
    profile.validate()?;
    serde_json::to_string_pretty(&profile).map_err(|error| error.to_string())
}

fn main() {
    let args = env::args().collect::<Vec<_>>();
    if args.len() != 2 {
        eprintln!("usage: capacity_profile <reviewed-draft.json>");
        process::exit(2);
    }
    match run(&args[1]) {
        Ok(profile) => println!("{profile}"),
        Err(error) => {
            eprintln!("{error}");
            process::exit(1);
        }
    }
}

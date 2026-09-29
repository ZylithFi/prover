//! provider-neutral proof-job types shared by the control plane and disposable workers.

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

pub const PROOF_JOB_SCHEMA_VERSION: u32 = 1;
pub const PROOF_VALIDITY_HEADROOM_BLOCKS: u64 = 5;
const JOB_ID_DOMAIN: &str = "zylith/proof-job/id/v1:";
const ARTIFACT_HASH_DOMAIN: &str = "zylith/proof-job/artifact/v1:";
const RESULT_HASH_DOMAIN: &str = "zylith/proof-job/result/v1:";

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ProofStatementKind {
    Transition,
    Withdrawal,
    ResidualRecovery,
    Benchmark,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProofJobDescriptor {
    pub schema_version: u32,
    pub job_id: String,
    pub statement_kind: ProofStatementKind,
    pub transition_id: String,
    pub epoch_id: Option<u64>,
    pub protocol_version: String,
    pub config_version: String,
    pub prover_build_id: String,
    pub chain_id: String,
    pub exchange_address: String,
    pub proof_program_address: String,
    pub program_entrypoint: String,
    pub proof_version: String,
    pub program_variant: String,
    pub virtual_program_hash: String,
    pub starknet_os_output_version: String,
    pub starknet_os_config_hash: String,
    pub base_block_number: u64,
    pub base_block_hash: String,
    pub input_state_root: Option<String>,
    pub expected_output_state_root: Option<String>,
    pub statement_commitment: String,
    pub expected_message: Option<String>,
    pub witness_hash: String,
    pub request_hash: String,
    pub request_bytes: u64,
    pub created_at_unix_ms: u64,
}

#[derive(Serialize)]
struct LogicalJob<'a> {
    schema_version: u32,
    statement_kind: &'a ProofStatementKind,
    transition_id: &'a str,
    epoch_id: Option<u64>,
    protocol_version: &'a str,
    config_version: &'a str,
    prover_build_id: &'a str,
    chain_id: &'a str,
    exchange_address: &'a str,
    proof_program_address: &'a str,
    program_entrypoint: &'a str,
    proof_version: &'a str,
    program_variant: &'a str,
    virtual_program_hash: &'a str,
    starknet_os_output_version: &'a str,
    starknet_os_config_hash: &'a str,
    input_state_root: &'a Option<String>,
    expected_output_state_root: &'a Option<String>,
    statement_commitment: &'a str,
    expected_message: &'a Option<String>,
    witness_hash: &'a str,
}

impl ProofJobDescriptor {
    pub fn expected_job_id(&self) -> Result<String, String> {
        tagged_commitment_sha256(
            JOB_ID_DOMAIN,
            &LogicalJob {
                schema_version: self.schema_version,
                statement_kind: &self.statement_kind,
                transition_id: &self.transition_id,
                epoch_id: self.epoch_id,
                protocol_version: &self.protocol_version,
                config_version: &self.config_version,
                prover_build_id: &self.prover_build_id,
                chain_id: &self.chain_id,
                exchange_address: &self.exchange_address,
                proof_program_address: &self.proof_program_address,
                program_entrypoint: &self.program_entrypoint,
                proof_version: &self.proof_version,
                program_variant: &self.program_variant,
                virtual_program_hash: &self.virtual_program_hash,
                starknet_os_output_version: &self.starknet_os_output_version,
                starknet_os_config_hash: &self.starknet_os_config_hash,
                input_state_root: &self.input_state_root,
                expected_output_state_root: &self.expected_output_state_root,
                statement_commitment: &self.statement_commitment,
                expected_message: &self.expected_message,
                witness_hash: &self.witness_hash,
            },
        )
        .map_err(|error| error.to_string())
    }

    pub fn validate(&self) -> Result<(), String> {
        if self.schema_version != PROOF_JOB_SCHEMA_VERSION {
            return Err("unsupported proof-job schema version".into());
        }
        for (label, value) in [
            ("job id", self.job_id.as_str()),
            ("transition id", self.transition_id.as_str()),
            ("protocol version", self.protocol_version.as_str()),
            ("config version", self.config_version.as_str()),
            ("prover build id", self.prover_build_id.as_str()),
            ("chain id", self.chain_id.as_str()),
            ("exchange address", self.exchange_address.as_str()),
            ("proof program", self.proof_program_address.as_str()),
            ("program entrypoint", self.program_entrypoint.as_str()),
            ("proof version", self.proof_version.as_str()),
            ("program variant", self.program_variant.as_str()),
            ("virtual program hash", self.virtual_program_hash.as_str()),
            (
                "os output version",
                self.starknet_os_output_version.as_str(),
            ),
            ("os config hash", self.starknet_os_config_hash.as_str()),
            ("base block hash", self.base_block_hash.as_str()),
            ("statement commitment", self.statement_commitment.as_str()),
            ("witness hash", self.witness_hash.as_str()),
            ("request hash", self.request_hash.as_str()),
        ] {
            if value.trim().is_empty() || value.len() > 256 {
                return Err(format!("{label} is invalid"));
            }
        }
        for (label, value) in [
            ("input state root", self.input_state_root.as_deref()),
            (
                "expected output state root",
                self.expected_output_state_root.as_deref(),
            ),
            ("expected message", self.expected_message.as_deref()),
        ] {
            if value.is_some_and(|value| value.trim().is_empty() || value.len() > 256) {
                return Err(format!("{label} is invalid"));
            }
        }
        for (label, value) in [
            ("job id", self.job_id.as_str()),
            ("witness hash", self.witness_hash.as_str()),
            ("request hash", self.request_hash.as_str()),
        ] {
            if !is_hash(value) {
                return Err(format!("{label} is not a sha256 hash"));
            }
        }
        if self.request_bytes == 0 {
            return Err("proof request is empty".into());
        }
        if self.job_id != self.expected_job_id()? {
            return Err("proof job id does not match its logical inputs".into());
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct EnqueueProofJob {
    pub descriptor: ProofJobDescriptor,
    pub request: serde_json::Value,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ProofJobState {
    Pending,
    Claimed,
    Proving,
    Complete,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProofPayload {
    pub proof: String,
    pub proof_facts: Vec<String>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProofJobStatus {
    pub descriptor: ProofJobDescriptor,
    pub state: ProofJobState,
    pub attempts: u32,
    pub lease_expires_at_unix_ms: Option<u64>,
    pub result: Option<ProofPayload>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct WorkerCapabilities {
    pub prover_build_id: String,
    pub proof_version: String,
    pub program_variant: String,
    pub virtual_program_hash: String,
    pub starknet_os_output_version: String,
    pub starknet_os_config_hash: String,
}

impl WorkerCapabilities {
    pub fn supports(&self, descriptor: &ProofJobDescriptor) -> bool {
        self.prover_build_id == descriptor.prover_build_id
            && self.proof_version == descriptor.proof_version
            && self.program_variant == descriptor.program_variant
            && self.virtual_program_hash == descriptor.virtual_program_hash
            && self.starknet_os_output_version == descriptor.starknet_os_output_version
            && self.starknet_os_config_hash == descriptor.starknet_os_config_hash
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RegisterProofWorker {
    pub worker_id: String,
    pub capabilities: WorkerCapabilities,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct WorkerSessionConfig {
    pub schema_version: u32,
    pub worker_id: String,
    pub capabilities: WorkerCapabilities,
    pub session_expires_at_unix_ms: u64,
    pub lease_duration_ms: u64,
    pub max_request_bytes: u64,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RegisterProofWorkerResponse {
    pub token: String,
    pub config: WorkerSessionConfig,
    pub config_mac: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProofWorkerRegistrationGrant {
    pub token: String,
    pub expires_at_unix_ms: u64,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProofJobClaim {
    pub descriptor: ProofJobDescriptor,
    pub lease_id: String,
    pub lease_expires_at_unix_ms: u64,
    pub artifact_path: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProofJobLeaseRequest {
    pub lease_id: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct CompleteProofJob {
    pub lease_id: String,
    pub prover_build_id: String,
    pub request_hash: String,
    pub result: ProofPayload,
}

pub fn proof_artifact_hash(bytes: &[u8]) -> String {
    tagged_sha256_hex(ARTIFACT_HASH_DOMAIN, bytes)
}

pub fn proof_result_hash(result: &ProofPayload) -> Result<String, String> {
    tagged_commitment_sha256(RESULT_HASH_DOMAIN, result).map_err(|error| error.to_string())
}

pub fn is_hash(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
}

pub fn constant_time_eq(left: &str, right: &str) -> bool {
    if left.len() != right.len() {
        return false;
    }
    left.as_bytes()
        .iter()
        .zip(right.as_bytes())
        .fold(0_u8, |difference, (left, right)| {
            difference | (left ^ right)
        })
        == 0
}

fn tagged_commitment_sha256<T: Serialize>(tag: &str, value: &T) -> Result<String, String> {
    let encoded = serde_json::to_vec(value).map_err(|error| error.to_string())?;
    Ok(tagged_sha256_hex(tag, &encoded))
}

fn tagged_sha256_hex(tag: &str, data: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(tag.as_bytes());
    hasher.update(data);
    hex::encode(hasher.finalize())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn descriptor() -> ProofJobDescriptor {
        let mut descriptor = ProofJobDescriptor {
            schema_version: PROOF_JOB_SCHEMA_VERSION,
            job_id: String::new(),
            statement_kind: ProofStatementKind::Transition,
            transition_id: "transition:0x123".into(),
            epoch_id: Some(7),
            protocol_version: "zylith-v1".into(),
            config_version: "release-1".into(),
            prover_build_id: "stwo-1".into(),
            chain_id: "0x1".into(),
            exchange_address: "0x2".into(),
            proof_program_address: "0x3".into(),
            program_entrypoint: "compile_transition_proof".into(),
            proof_version: "0x4".into(),
            program_variant: "VIRTUAL_SNOS".into(),
            virtual_program_hash: "0x5".into(),
            starknet_os_output_version: "VIRTUAL_SNOS0".into(),
            starknet_os_config_hash: "0x6".into(),
            base_block_number: 100,
            base_block_hash: "0x99".into(),
            input_state_root: Some("0x7".into()),
            expected_output_state_root: Some("0x8".into()),
            statement_commitment: "0x9".into(),
            expected_message: Some("0xa".into()),
            witness_hash: "1".repeat(64),
            request_hash: "2".repeat(64),
            request_bytes: 100,
            created_at_unix_ms: 11,
        };
        descriptor.job_id = descriptor.expected_job_id().unwrap();
        descriptor
    }

    #[test]
    fn job_id_ignores_retry_specific_request_details() {
        let first = descriptor();
        let mut retried = first.clone();
        retried.base_block_number += 1;
        retried.request_hash = "3".repeat(64);
        retried.created_at_unix_ms += 1;
        assert_eq!(first.job_id, retried.expected_job_id().unwrap());
        assert!(first.validate().is_ok());
    }

    #[test]
    fn job_id_binds_the_canonical_transition() {
        let first = descriptor();
        let mut changed = first.clone();
        changed.expected_output_state_root = Some("0xb".into());
        assert_ne!(first.job_id, changed.expected_job_id().unwrap());
    }

    #[test]
    fn content_hashes_have_one_lowercase_representation() {
        let mut uppercase = descriptor();
        uppercase.request_hash = "A".repeat(64);
        assert!(uppercase.validate().is_err());
    }
}

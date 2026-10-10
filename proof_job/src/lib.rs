//! provider-neutral proof-job types shared by the control plane and disposable workers.

use std::{
    collections::{BTreeMap, BTreeSet},
    fmt,
    marker::PhantomData,
};

use serde::{
    Deserialize, Deserializer, Serialize,
    de::{Error as _, MapAccess, Visitor},
};
use sha2::{Digest, Sha256};

pub const PROOF_JOB_SCHEMA_VERSION: u32 = 2;
pub const PROOF_CAPACITY_SCHEMA_VERSION: u32 = 4;
pub const PROOF_VALIDITY_HEADROOM_BLOCKS: u64 = 5;
pub const TRANSITION_STATEMENT_VERSION: &str = "zylith-transition-v2";
pub const WITHDRAWAL_STATEMENT_VERSION: &str = "zylith-withdrawal-v1";
pub const RESIDUAL_RECOVERY_STATEMENT_VERSION: &str = "zylith-residual-recovery-v2";
pub const VIRTUAL_PROGRAM_VARIANT: &str = "VIRTUAL_SNOS";
pub const STARKNET_OS_OUTPUT_VERSION: &str = "VIRTUAL_SNOS0";
const JOB_ID_DOMAIN: &str = "zylith/proof-job/id/v1:";
const ARTIFACT_HASH_DOMAIN: &str = "zylith/proof-job/artifact/v1:";
const RESULT_HASH_DOMAIN: &str = "zylith/proof-job/result/v1:";

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ProofStatementKind {
    Transition,
    Withdrawal,
    ResidualRecovery,
    Benchmark,
}

const PROOF_COMPONENT_REGISTRY_SCHEMA_VERSION: u32 = 1;
const MAX_PROOF_COMPONENTS: usize = 256;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProofReleaseIdentity {
    pub release_commit: String,
    pub prover_build_id: String,
    pub proof_version: String,
    pub program_variant: String,
    pub virtual_program_hash: String,
    pub starknet_os_output_version: String,
    pub starknet_os_config_hash: String,
    pub proof_account_class_hash: String,
    pub proof_program_class_hash: String,
    pub statement_version: String,
}

impl ProofReleaseIdentity {
    fn validate(&self) -> Result<(), String> {
        for (label, value) in [
            ("release commit", &self.release_commit),
            ("prover build id", &self.prover_build_id),
            ("proof version", &self.proof_version),
            ("program variant", &self.program_variant),
            ("virtual program hash", &self.virtual_program_hash),
            ("os output version", &self.starknet_os_output_version),
            ("os config hash", &self.starknet_os_config_hash),
            ("proof account class hash", &self.proof_account_class_hash),
            ("proof program class hash", &self.proof_program_class_hash),
            ("statement version", &self.statement_version),
        ] {
            validate_failure_identifier(label, value, 256)?;
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProofResourceUsage {
    pub component_registry_id: String,
    pub raw_snos_steps: u64,
    pub adapted_rows: u64,
    pub memory_words: u64,
    pub memory_holes: u64,
    #[serde(deserialize_with = "deserialize_unique_u64_map")]
    pub builtin_instances: BTreeMap<String, u64>,
    #[serde(deserialize_with = "deserialize_unique_u32_map")]
    pub component_log_sizes: BTreeMap<String, u32>,
    pub max_domain_log_size: u32,
    pub peak_rss_bytes: u64,
    pub wall_time_ms: u64,
}

struct UniqueMapVisitor<V>(PhantomData<V>);

impl<'de, V> Visitor<'de> for UniqueMapVisitor<V>
where
    V: Deserialize<'de>,
{
    type Value = BTreeMap<String, V>;

    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("an object with unique string keys")
    }

    fn visit_map<A>(self, mut entries: A) -> Result<Self::Value, A::Error>
    where
        A: MapAccess<'de>,
    {
        let mut values = BTreeMap::new();
        while let Some((key, value)) = entries.next_entry::<String, V>()? {
            if values.insert(key.clone(), value).is_some() {
                return Err(A::Error::custom(format!("duplicate component `{key}`")));
            }
        }
        Ok(values)
    }
}

fn deserialize_unique_map<'de, D, V>(deserializer: D) -> Result<BTreeMap<String, V>, D::Error>
where
    D: Deserializer<'de>,
    V: Deserialize<'de>,
{
    deserializer.deserialize_map(UniqueMapVisitor(PhantomData))
}

fn deserialize_unique_u64_map<'de, D>(deserializer: D) -> Result<BTreeMap<String, u64>, D::Error>
where
    D: Deserializer<'de>,
{
    deserialize_unique_map(deserializer)
}

fn deserialize_unique_u32_map<'de, D>(deserializer: D) -> Result<BTreeMap<String, u32>, D::Error>
where
    D: Deserializer<'de>,
{
    deserialize_unique_map(deserializer)
}

impl ProofResourceUsage {
    pub fn expected_component_registry_id(&self) -> Result<String, String> {
        #[derive(Serialize)]
        struct ComponentRegistry<'a> {
            schema_version: u32,
            builtin_components: Vec<&'a str>,
            trace_components: Vec<&'a str>,
        }

        tagged_commitment_sha256(
            "zylith/proof-component-registry/v1:",
            &ComponentRegistry {
                schema_version: PROOF_COMPONENT_REGISTRY_SCHEMA_VERSION,
                builtin_components: self.builtin_instances.keys().map(String::as_str).collect(),
                trace_components: self
                    .component_log_sizes
                    .keys()
                    .map(String::as_str)
                    .collect(),
            },
        )
    }

    fn validate(&self, capacity: bool) -> Result<(), String> {
        if self.raw_snos_steps == 0
            || self.adapted_rows == 0
            || self.memory_words == 0
            || self.max_domain_log_size == 0
            || self.peak_rss_bytes == 0
            || self.wall_time_ms == 0
        {
            return Err("proof resource evidence has a zero required field".into());
        }
        if self.builtin_instances.is_empty()
            || self.component_log_sizes.is_empty()
            || self.builtin_instances.len() > MAX_PROOF_COMPONENTS
            || self.component_log_sizes.len() > MAX_PROOF_COMPONENTS
        {
            return Err("proof resource evidence has an invalid component count".into());
        }
        for name in self
            .builtin_instances
            .keys()
            .chain(self.component_log_sizes.keys())
        {
            validate_failure_identifier("proof component", name, 128)?;
        }
        if !self.component_log_sizes.contains_key("cpu") {
            return Err("proof resource evidence is missing the cpu trace component".into());
        }
        if !is_hash(&self.component_registry_id)
            || self.component_registry_id != self.expected_component_registry_id()?
        {
            return Err("proof component registry id is invalid".into());
        }
        if self
            .component_log_sizes
            .values()
            .any(|value| *value == 0 || *value > self.max_domain_log_size)
            || capacity && self.builtin_instances.values().any(|value| *value == 0)
        {
            return Err("proof component limits are inconsistent".into());
        }
        Ok(())
    }

    fn fits_with_margin(&self, capacity: &Self, margin_bps: u16) -> bool {
        let fits = |used: u64, limit: u64| {
            u128::from(used) * 10_000 <= u128::from(limit) * u128::from(10_000_u16 - margin_bps)
        };
        // Log sizes describe already-padded power-of-two domains. Equality therefore has zero
        // headroom even when every count field satisfies its basis-point margin. Reserve one whole
        // domain step until the adapter reports reviewed unpadded row counts per component.
        let fits_log = |used: u32, limit: u32| used < limit;
        fits(self.raw_snos_steps, capacity.raw_snos_steps)
            && fits(self.adapted_rows, capacity.adapted_rows)
            && fits(self.memory_words, capacity.memory_words)
            && fits(self.memory_holes, capacity.memory_holes)
            && fits(self.peak_rss_bytes, capacity.peak_rss_bytes)
            && fits(self.wall_time_ms, capacity.wall_time_ms)
            && fits_log(self.max_domain_log_size, capacity.max_domain_log_size)
            && self.builtin_instances.iter().all(|(component, used)| {
                capacity
                    .builtin_instances
                    .get(component)
                    .is_some_and(|limit| fits(*used, *limit))
            })
            && self.component_log_sizes.iter().all(|(component, used)| {
                capacity
                    .component_log_sizes
                    .get(component)
                    .is_some_and(|limit| fits_log(*used, *limit))
            })
    }

    pub fn validate_measurement(&self) -> Result<(), String> {
        self.validate(false)
    }
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProofShapeLimits {
    pub markets: u64,
    pub resting_orders: u64,
    pub admissions: u64,
    pub crossings: u64,
    pub outcomes: u64,
    pub nullifiers: u64,
    pub retired_nullifiers: u64,
    pub outputs: u64,
    pub funding_notes: u64,
    pub membership_path_elements: u64,
}

impl ProofShapeLimits {
    pub fn covers(&self, shape: &Self) -> bool {
        shape.markets <= self.markets
            && shape.resting_orders <= self.resting_orders
            && shape.admissions <= self.admissions
            && shape.crossings <= self.crossings
            && shape.outcomes <= self.outcomes
            && shape.nullifiers <= self.nullifiers
            && shape.retired_nullifiers <= self.retired_nullifiers
            && shape.outputs <= self.outputs
            && shape.funding_notes <= self.funding_notes
            && shape.membership_path_elements <= self.membership_path_elements
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProofCapacityVector {
    pub vector_id: String,
    pub evidence_sha256: String,
    pub shape: ProofShapeLimits,
    pub usage: ProofResourceUsage,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProofCapacityProfile {
    pub schema_version: u32,
    pub profile_id: String,
    pub statement_kind: ProofStatementKind,
    pub identity: ProofReleaseIdentity,
    pub vector_family: String,
    pub safety_margin_bps: u16,
    pub capacity: ProofResourceUsage,
    pub limits: ProofShapeLimits,
    pub vectors: Vec<ProofCapacityVector>,
}

#[derive(Serialize)]
struct ProofCapacityCommitment<'a> {
    schema_version: u32,
    statement_kind: &'a ProofStatementKind,
    identity: &'a ProofReleaseIdentity,
    vector_family: &'a str,
    safety_margin_bps: u16,
    capacity: &'a ProofResourceUsage,
    limits: &'a ProofShapeLimits,
    vectors: &'a [ProofCapacityVector],
}

impl ProofCapacityProfile {
    pub fn expected_profile_id(&self) -> Result<String, String> {
        tagged_commitment_sha256(
            "zylith/proof-capacity-profile/v1:",
            &ProofCapacityCommitment {
                schema_version: self.schema_version,
                statement_kind: &self.statement_kind,
                identity: &self.identity,
                vector_family: &self.vector_family,
                safety_margin_bps: self.safety_margin_bps,
                capacity: &self.capacity,
                limits: &self.limits,
                vectors: &self.vectors,
            },
        )
    }

    pub fn validate(&self) -> Result<(), String> {
        if self.schema_version != PROOF_CAPACITY_SCHEMA_VERSION {
            return Err("unsupported proof capacity profile version".into());
        }
        if !is_hash(&self.profile_id) || self.profile_id != self.expected_profile_id()? {
            return Err("proof capacity profile id is invalid".into());
        }
        if self.safety_margin_bps == 0 || self.safety_margin_bps >= 10_000 {
            return Err("proof capacity safety margin must be in 1..9999 bps".into());
        }
        if self.statement_kind == ProofStatementKind::Benchmark {
            return Err("benchmark proof profiles cannot authorize production statements".into());
        }
        validate_failure_identifier("proof vector family", &self.vector_family, 128)?;
        self.identity.validate()?;
        self.capacity.validate(true)?;
        if self.vectors.is_empty() {
            return Err("proof capacity profile has no measured vectors".into());
        }
        let mut vector_ids = BTreeSet::new();
        let mut covers_limit = false;
        for vector in &self.vectors {
            validate_failure_identifier("proof vector id", &vector.vector_id, 128)?;
            if !is_hash(&vector.evidence_sha256) {
                return Err("proof vector evidence hash is invalid".into());
            }
            if !vector_ids.insert(&vector.vector_id) {
                return Err("proof capacity profile repeats a vector id".into());
            }
            vector.usage.validate(false)?;
            if vector.usage.component_registry_id != self.capacity.component_registry_id
                || vector.usage.builtin_instances.keys().collect::<Vec<_>>()
                    != self.capacity.builtin_instances.keys().collect::<Vec<_>>()
                || vector.usage.component_log_sizes.keys().collect::<Vec<_>>()
                    != self.capacity.component_log_sizes.keys().collect::<Vec<_>>()
            {
                return Err("proof vector component registry differs from capacity".into());
            }
            if !self.limits.covers(&vector.shape)
                || !vector
                    .usage
                    .fits_with_margin(&self.capacity, self.safety_margin_bps)
            {
                return Err("proof vector exceeds its declared profile".into());
            }
            covers_limit |= vector.shape == self.limits;
        }
        if !covers_limit {
            return Err("no measured vector covers the declared shape limits".into());
        }
        Ok(())
    }

    pub fn validate_identity(&self, expected: &ProofReleaseIdentity) -> Result<(), String> {
        self.validate()?;
        if &self.identity != expected {
            return Err("proof capacity profile release identity does not match".into());
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
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
    base_block_number: u64,
    base_block_hash: &'a str,
    input_state_root: &'a Option<String>,
    expected_output_state_root: &'a Option<String>,
    statement_commitment: &'a str,
    expected_message: &'a Option<String>,
    witness_hash: &'a str,
    request_hash: &'a str,
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
                base_block_number: self.base_block_number,
                base_block_hash: &self.base_block_hash,
                input_state_root: &self.input_state_root,
                expected_output_state_root: &self.expected_output_state_root,
                statement_commitment: &self.statement_commitment,
                expected_message: &self.expected_message,
                witness_hash: &self.witness_hash,
                request_hash: &self.request_hash,
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
#[serde(deny_unknown_fields)]
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
    FailedRetryable,
    FailedPermanent,
}

/// the closed reason a proof attempt could not complete. no variant carries prover text.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ProofFailureClass {
    CapacityExceeded,
    UnsupportedBuiltin,
    InvalidArtifact,
    InvalidWitness,
    PermanentProverRejection,
    TransientNetwork,
    TransientProverUnavailable,
    WorkerLost,
}

impl ProofFailureClass {
    pub const fn is_retryable(self) -> bool {
        matches!(
            self,
            Self::TransientNetwork | Self::TransientProverUnavailable | Self::WorkerLost
        )
    }
}

/// bounded public diagnostics for one failed attempt.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProofFailure {
    pub class: ProofFailureClass,
    pub code: String,
    pub component: Option<String>,
    pub profile_id: Option<String>,
    pub required: Option<u64>,
    pub available: Option<u64>,
}

impl ProofFailure {
    pub fn validate(&self) -> Result<(), String> {
        validate_failure_identifier("failure code", &self.code, 64)?;
        if let Some(component) = &self.component {
            validate_failure_identifier("failure component", component, 64)?;
        }
        if let Some(profile_id) = &self.profile_id {
            validate_failure_identifier("failure profile", profile_id, 128)?;
        }
        if self.required.is_some() != self.available.is_some() {
            return Err("failure resource bounds must be supplied together".into());
        }
        if self.required.is_some_and(|required| required == 0)
            || self.available.is_some_and(|available| available == 0)
        {
            return Err("failure resource bounds must be nonzero".into());
        }
        if self.class == ProofFailureClass::CapacityExceeded
            && self
                .required
                .zip(self.available)
                .is_some_and(|(required, available)| required <= available)
        {
            return Err("capacity failure does not exceed the available resource".into());
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProofPayload {
    pub proof: String,
    pub proof_facts: Vec<String>,
    /// Present only when the pinned prover adapter emits the complete, structured full-SNOS
    /// resource report. Normal proving accepts its absence; release benchmarking requires it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub resource_usage: Option<ProofResourceUsage>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProofJobStatus {
    pub descriptor: ProofJobDescriptor,
    pub state: ProofJobState,
    pub attempts: u32,
    pub lease_expires_at_unix_ms: Option<u64>,
    pub result: Option<ProofPayload>,
    pub failure: Option<ProofFailure>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
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
#[serde(deny_unknown_fields)]
pub struct RegisterProofWorker {
    pub worker_id: String,
    pub capabilities: WorkerCapabilities,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WorkerSessionConfig {
    pub schema_version: u32,
    pub worker_id: String,
    pub capabilities: WorkerCapabilities,
    pub session_expires_at_unix_ms: u64,
    pub lease_duration_ms: u64,
    pub max_request_bytes: u64,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RegisterProofWorkerResponse {
    pub token: String,
    pub config: WorkerSessionConfig,
    pub config_mac: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProofWorkerRegistrationGrant {
    pub token: String,
    pub expires_at_unix_ms: u64,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProofJobClaim {
    pub descriptor: ProofJobDescriptor,
    pub lease_id: String,
    pub lease_expires_at_unix_ms: u64,
    pub artifact_path: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProofJobLeaseRequest {
    pub lease_id: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CompleteProofJob {
    pub lease_id: String,
    pub prover_build_id: String,
    pub request_hash: String,
    pub result: ProofPayload,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FailProofJob {
    pub lease_id: String,
    pub prover_build_id: String,
    pub request_hash: String,
    pub failure: ProofFailure,
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

fn validate_failure_identifier(label: &str, value: &str, maximum: usize) -> Result<(), String> {
    if value.is_empty()
        || value.len() > maximum
        || !value.bytes().all(|byte| {
            byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-' | b'.' | b':' | b'/')
        })
    {
        return Err(format!("{label} is invalid"));
    }
    Ok(())
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
    use std::collections::BTreeMap;

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

    fn resource_usage() -> ProofResourceUsage {
        let builtin_instances = BTreeMap::from([
            ("bitwise".into(), 1),
            ("cpu".into(), 800_000),
            ("ec_op".into(), 1),
            ("ecdsa".into(), 1),
            ("pedersen".into(), 1),
            ("poseidon".into(), 719),
            ("range_check".into(), 1_000),
        ]);
        let component_log_sizes = BTreeMap::from([
            ("bitwise".into(), 4),
            ("cpu".into(), 20),
            ("ec_op".into(), 4),
            ("ecdsa".into(), 4),
            ("pedersen".into(), 4),
            ("poseidon".into(), 10),
            ("range_check".into(), 12),
        ]);
        let mut usage = ProofResourceUsage {
            component_registry_id: String::new(),
            raw_snos_steps: 802_000,
            adapted_rows: 900_000,
            memory_words: 900_000,
            memory_holes: 2_000,
            builtin_instances,
            component_log_sizes,
            max_domain_log_size: 20,
            peak_rss_bytes: 2_000_000_000,
            wall_time_ms: 120_000,
        };
        usage.component_registry_id = usage.expected_component_registry_id().unwrap();
        usage
    }

    fn capacity_profile() -> ProofCapacityProfile {
        let identity = ProofReleaseIdentity {
            release_commit: "release-1".into(),
            prover_build_id: "stwo-0.19.0-zylith.1".into(),
            proof_version: "0x1".into(),
            program_variant: "VIRTUAL_SNOS".into(),
            virtual_program_hash: "0x2".into(),
            starknet_os_output_version: "VIRTUAL_SNOS0".into(),
            starknet_os_config_hash: "0x3".into(),
            proof_account_class_hash: "0x4".into(),
            proof_program_class_hash: "0x5".into(),
            statement_version: "transition-v2".into(),
        };
        let limits = ProofShapeLimits {
            markets: 3,
            resting_orders: 64,
            admissions: 16,
            crossings: 64,
            outcomes: 16,
            nullifiers: 64,
            retired_nullifiers: 8,
            outputs: 256,
            funding_notes: 64,
            membership_path_elements: 3_072,
        };
        let mut profile = ProofCapacityProfile {
            schema_version: PROOF_CAPACITY_SCHEMA_VERSION,
            profile_id: String::new(),
            statement_kind: ProofStatementKind::Transition,
            identity,
            vector_family: "transition-worst-case-v1".into(),
            safety_margin_bps: 1_000,
            capacity: {
                let mut usage = ProofResourceUsage {
                    component_registry_id: String::new(),
                    raw_snos_steps: 1_048_576,
                    adapted_rows: 1_048_576,
                    memory_words: 1_048_576,
                    memory_holes: 65_536,
                    builtin_instances: BTreeMap::from([
                        ("bitwise".into(), 1_024),
                        ("cpu".into(), 1_048_576),
                        ("ec_op".into(), 1_024),
                        ("ecdsa".into(), 1_024),
                        ("pedersen".into(), 1_024),
                        ("poseidon".into(), 1_024),
                        ("range_check".into(), 65_536),
                    ]),
                    component_log_sizes: BTreeMap::from([
                        ("bitwise".into(), 10),
                        ("cpu".into(), 21),
                        ("ec_op".into(), 10),
                        ("ecdsa".into(), 10),
                        ("pedersen".into(), 10),
                        ("poseidon".into(), 11),
                        ("range_check".into(), 16),
                    ]),
                    max_domain_log_size: 21,
                    peak_rss_bytes: 4_000_000_000,
                    wall_time_ms: 900_000,
                };
                usage.component_registry_id = usage.expected_component_registry_id().unwrap();
                usage
            },
            limits: limits.clone(),
            vectors: vec![ProofCapacityVector {
                vector_id: "transition-max-v1".into(),
                evidence_sha256: "a".repeat(64),
                shape: limits,
                usage: resource_usage(),
            }],
        };
        profile.profile_id = profile.expected_profile_id().unwrap();
        profile
    }

    #[test]
    fn capacity_profile_identity_binds_every_release_and_measurement_field() {
        type ProfileMutation = Box<dyn Fn(&mut ProofCapacityProfile)>;

        let profile = capacity_profile();
        profile.validate().unwrap();
        let original = profile.profile_id.clone();
        let mutations: Vec<ProfileMutation> = vec![
            Box::new(|p| p.identity.release_commit.push('x')),
            Box::new(|p| p.identity.prover_build_id.push('x')),
            Box::new(|p| p.identity.proof_version.push('1')),
            Box::new(|p| p.identity.program_variant.push('x')),
            Box::new(|p| p.identity.virtual_program_hash.push('1')),
            Box::new(|p| p.identity.starknet_os_output_version.push('1')),
            Box::new(|p| p.identity.starknet_os_config_hash.push('1')),
            Box::new(|p| p.identity.proof_account_class_hash.push('1')),
            Box::new(|p| p.identity.proof_program_class_hash.push('1')),
            Box::new(|p| p.identity.statement_version.push('1')),
            Box::new(|p| p.capacity.component_registry_id.replace_range(..1, "b")),
            Box::new(|p| p.vector_family.push('x')),
            Box::new(|p| p.safety_margin_bps += 1),
            Box::new(|p| p.capacity.adapted_rows += 1),
            Box::new(|p| p.capacity.memory_words += 1),
            Box::new(|p| p.capacity.wall_time_ms += 1),
            Box::new(|p| p.capacity.peak_rss_bytes += 1),
            Box::new(|p| *p.capacity.component_log_sizes.get_mut("poseidon").unwrap() += 1),
            Box::new(|p| p.limits.outputs += 1),
            Box::new(|p| p.vectors[0].evidence_sha256.replace_range(..1, "b")),
            Box::new(|p| p.vectors[0].usage.raw_snos_steps += 1),
        ];
        for mutate in mutations {
            let mut changed = profile.clone();
            mutate(&mut changed);
            assert_ne!(changed.expected_profile_id().unwrap(), original);
            assert!(changed.validate().is_err());
        }
    }

    #[test]
    fn component_registry_has_a_cross_language_known_answer_and_separate_namespaces() {
        let usage = resource_usage();
        assert_eq!(
            usage.component_registry_id,
            "82a8e16371e7bd66c2d7ee4775ea8335e91968af881fca808155f0fe1c1c95e7"
        );

        let mut profile = capacity_profile();
        profile
            .capacity
            .builtin_instances
            .insert("output".into(), 10);
        profile.capacity.component_registry_id =
            profile.capacity.expected_component_registry_id().unwrap();
        profile.vectors[0]
            .usage
            .builtin_instances
            .insert("output".into(), 1);
        profile.vectors[0].usage.component_registry_id = profile.vectors[0]
            .usage
            .expected_component_registry_id()
            .unwrap();
        profile.profile_id = profile.expected_profile_id().unwrap();
        profile.validate().unwrap();
    }

    #[test]
    fn capacity_profiles_fail_closed_on_incomplete_or_inconsistent_evidence() {
        let mut profile = capacity_profile();
        profile.capacity.component_log_sizes.remove("poseidon");
        assert!(profile.validate().is_err());

        let mut profile = capacity_profile();
        profile.vectors[0]
            .usage
            .component_log_sizes
            .insert("new_trace_component".into(), 4);
        profile.vectors[0].usage.component_registry_id = profile.vectors[0]
            .usage
            .expected_component_registry_id()
            .unwrap();
        assert!(profile.validate().is_err());

        let mut profile = capacity_profile();
        profile
            .capacity
            .component_log_sizes
            .insert("new_trace_component".into(), 10);
        profile.capacity.component_registry_id =
            profile.capacity.expected_component_registry_id().unwrap();
        profile.vectors[0]
            .usage
            .component_log_sizes
            .insert("new_trace_component".into(), 4);
        profile.vectors[0].usage.component_registry_id = profile.vectors[0]
            .usage
            .expected_component_registry_id()
            .unwrap();
        profile.profile_id = profile.expected_profile_id().unwrap();
        profile.validate().unwrap();

        let mut profile = capacity_profile();
        profile.safety_margin_bps = 0;
        assert!(profile.validate().is_err());

        let mut profile = capacity_profile();
        profile.vectors[0].usage.adapted_rows = profile.capacity.adapted_rows;
        assert!(profile.validate().is_err());

        let mut profile = capacity_profile();
        let domain_limit = profile.capacity.max_domain_log_size;
        profile.vectors[0].usage.max_domain_log_size = domain_limit;
        profile.vectors[0]
            .usage
            .component_log_sizes
            .insert("cpu".into(), domain_limit);
        profile.profile_id = profile.expected_profile_id().unwrap();
        assert!(profile.validate().is_err());

        let mut profile = capacity_profile();
        let poseidon_limit = profile.capacity.component_log_sizes["poseidon"];
        profile.vectors[0]
            .usage
            .component_log_sizes
            .insert("poseidon".into(), poseidon_limit);
        profile.profile_id = profile.expected_profile_id().unwrap();
        assert!(profile.validate().is_err());

        let mut profile = capacity_profile();
        profile.vectors.clear();
        assert!(profile.validate().is_err());

        let profile = capacity_profile();
        let mut mismatched = profile.identity.clone();
        mismatched.prover_build_id = "other-build".into();
        assert!(profile.validate_identity(&mismatched).is_err());
        profile.validate_identity(&profile.identity).unwrap();
    }

    #[test]
    fn job_id_binds_each_immutable_proving_attempt() {
        let first = descriptor();
        let mut retried = first.clone();
        retried.base_block_number += 1;
        retried.base_block_hash = "0x100".into();
        retried.request_hash = "3".repeat(64);
        retried.created_at_unix_ms += 1;
        assert_ne!(first.job_id, retried.expected_job_id().unwrap());
        assert!(first.validate().is_ok());

        let mut timestamp_only = first.clone();
        timestamp_only.created_at_unix_ms += 1;
        assert_eq!(first.job_id, timestamp_only.expected_job_id().unwrap());
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

    #[test]
    fn control_plane_messages_reject_unversioned_extension_fields() {
        let mut encoded = serde_json::to_value(descriptor()).unwrap();
        encoded["future_semantics"] = serde_json::json!("must require a schema bump");
        assert!(serde_json::from_value::<ProofJobDescriptor>(encoded).is_err());

        let mut capabilities = serde_json::to_value(WorkerCapabilities {
            prover_build_id: "stwo-1".into(),
            proof_version: "0x4".into(),
            program_variant: "VIRTUAL_SNOS".into(),
            virtual_program_hash: "0x5".into(),
            starknet_os_output_version: "VIRTUAL_SNOS0".into(),
            starknet_os_config_hash: "0x6".into(),
        })
        .unwrap();
        capabilities["uncommitted_capability"] = serde_json::json!(true);
        assert!(serde_json::from_value::<WorkerCapabilities>(capabilities).is_err());
    }

    #[test]
    fn proof_failures_are_closed_bounded_and_message_free() {
        let failure = ProofFailure {
            class: ProofFailureClass::CapacityExceeded,
            code: "TRACE_DOMAIN_EXCEEDED".into(),
            component: Some("poseidon".into()),
            profile_id: Some("proof1-log20".into()),
            required: Some(21),
            available: Some(20),
        };
        assert!(failure.validate().is_ok());
        let encoded = serde_json::to_value(&failure).unwrap();
        assert!(encoded.get("message").is_none());
        assert!(
            serde_json::from_value::<ProofFailure>(serde_json::json!({
                "class": "UNKNOWN_FAILURE",
                "code": "UNKNOWN"
            }))
            .is_err()
        );
        let mut extra = encoded.clone();
        extra["message"] = serde_json::json!("private witness 0x123");
        assert!(serde_json::from_value::<ProofFailure>(extra).is_err());
    }

    #[test]
    fn proof_failure_validation_rejects_unbounded_or_inconsistent_diagnostics() {
        let valid = ProofFailure {
            class: ProofFailureClass::InvalidWitness,
            code: "INVALID_WITNESS".into(),
            component: None,
            profile_id: None,
            required: None,
            available: None,
        };
        for failure in [
            ProofFailure {
                code: "x".repeat(65),
                ..valid.clone()
            },
            ProofFailure {
                code: "contains a space".into(),
                ..valid.clone()
            },
            ProofFailure {
                required: Some(1),
                ..valid.clone()
            },
            ProofFailure {
                required: Some(0),
                available: Some(1),
                ..valid.clone()
            },
        ] {
            assert!(failure.validate().is_err());
        }
        assert!(ProofFailureClass::TransientNetwork.is_retryable());
        assert!(ProofFailureClass::WorkerLost.is_retryable());
        assert!(!ProofFailureClass::InvalidArtifact.is_retryable());
    }
}

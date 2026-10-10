//! disposable proof worker: claims immutable jobs, invokes a local stwo engine and returns proofs.

use std::env;
use std::fmt;
use std::time::Duration;

use hmac::{Hmac, Mac};
use reqwest::{Client, StatusCode};
use serde::{Deserialize, de::IgnoredAny};
use sha2::Sha256;
use tokio::sync::watch;
use tokio::time::sleep;
use url::Url;
use zeroize::Zeroizing;
use zylith_proof_job::{
    CompleteProofJob, FailProofJob, ProofFailure, ProofFailureClass, ProofJobClaim,
    ProofJobLeaseRequest, ProofPayload, ProofResourceUsage, RegisterProofWorker,
    RegisterProofWorkerResponse, WorkerCapabilities, WorkerSessionConfig, constant_time_eq,
    proof_artifact_hash,
};

const MAX_RESPONSE_BYTES: usize = 16 * 1024 * 1024;
const TERMINAL_CREDENTIAL_ERROR: &str = "terminal worker credentials:";

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ProveResponse {
    jsonrpc: String,
    id: u64,
    result: Option<ProveResult>,
    error: Option<ProveError>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ProveResult {
    proof: String,
    proof_facts: Vec<String>,
    #[serde(default)]
    resource_usage: Option<ProofResourceUsage>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ProveError {
    code: i64,
    #[serde(rename = "message")]
    _message: IgnoredAny,
    data: Option<StructuredProverFailure>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct StructuredProverFailure {
    schema_version: u32,
    class: ProofFailureClass,
    code: String,
    component: Option<String>,
    profile_id: Option<String>,
    required: Option<u64>,
    available: Option<u64>,
}

#[derive(Debug, PartialEq, Eq)]
enum BoundedReadError {
    TooLarge { maximum: usize },
    Transport,
}

impl fmt::Display for BoundedReadError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::TooLarge { maximum } => {
                write!(formatter, "response exceeds {maximum} bytes")
            }
            Self::Transport => formatter.write_str("response read failed"),
        }
    }
}

struct Worker {
    http: Client,
    queue_url: String,
    stwo_url: String,
    registration_token: Option<String>,
    worker_id: String,
    capabilities: WorkerCapabilities,
    poll_interval: Duration,
    max_proof_duration: Duration,
    session: Option<RegisterProofWorkerResponse>,
}

#[tokio::main]
async fn main() -> Result<(), String> {
    rustls::crypto::aws_lc_rs::default_provider()
        .install_default()
        .map_err(|_| "failed to install the tls crypto provider".to_string())?;
    let required = |name: &str| {
        env::var(name)
            .ok()
            .filter(|value| !value.trim().is_empty())
            .ok_or_else(|| format!("{name} is required"))
    };
    let timeout_seconds = env::var("ZYLITH_PROOF_WORKER_REQUEST_TIMEOUT_SECONDS")
        .ok()
        .map(|value| value.parse().map_err(|_| "worker timeout is invalid"))
        .transpose()?
        .unwrap_or(900);
    let poll_ms = env::var("ZYLITH_PROOF_WORKER_POLL_MS")
        .ok()
        .map(|value| value.parse().map_err(|_| "worker poll interval is invalid"))
        .transpose()?
        .unwrap_or(250);
    let prover_build_id = required("ZYLITH_PROVER_BUILD_ID")?;
    let proof_version = required("ZYLITH_PROOF_VERSION")?;
    let virtual_program_hash = required("ZYLITH_VIRTUAL_PROGRAM_HASH")?;
    let starknet_os_config_hash = required("ZYLITH_STARKNET_OS_CONFIG_HASH")?;
    verify_compiled_pin(
        "prover build id",
        &prover_build_id,
        option_env!("ZYLITH_PROVER_BUILD_ID"),
    )?;
    verify_compiled_pin(
        "proof version",
        &proof_version,
        option_env!("ZYLITH_PROOF_VERSION"),
    )?;
    verify_compiled_pin(
        "virtual program hash",
        &virtual_program_hash,
        option_env!("ZYLITH_VIRTUAL_PROGRAM_HASH"),
    )?;
    verify_compiled_pin(
        "os config hash",
        &starknet_os_config_hash,
        option_env!("ZYLITH_STARKNET_OS_CONFIG_HASH"),
    )?;
    let http = Client::builder()
        .timeout(Duration::from_secs(timeout_seconds))
        .build()
        .map_err(|error| format!("http client: {error}"))?;
    let mut worker = Worker {
        http,
        queue_url: validate_queue_url(&required("ZYLITH_PROOF_QUEUE_URL")?)?,
        stwo_url: validate_stwo_url(&required("ZYLITH_STWO_PROVER_URL")?)?,
        registration_token: Some(required("ZYLITH_PROOF_WORKER_REGISTRATION_TOKEN")?),
        worker_id: required("ZYLITH_PROOF_WORKER_ID")?,
        capabilities: WorkerCapabilities {
            prover_build_id,
            proof_version,
            program_variant: zylith_proof_job::VIRTUAL_PROGRAM_VARIANT.into(),
            virtual_program_hash,
            starknet_os_output_version: zylith_proof_job::STARKNET_OS_OUTPUT_VERSION.into(),
            starknet_os_config_hash,
        },
        poll_interval: Duration::from_millis(poll_ms),
        max_proof_duration: Duration::from_secs(timeout_seconds),
        session: None,
    };
    worker.register().await?;
    eprintln!("zylith proof worker {} ready", worker.worker_id);
    loop {
        match worker.claim().await {
            Ok(Some(claim)) => {
                if let Err(error) = worker.prove(claim).await {
                    if error.starts_with(TERMINAL_CREDENTIAL_ERROR) {
                        return Err(error);
                    }
                    eprintln!("proof job failed: {}", sanitize(&error));
                }
            }
            Ok(None) => sleep(worker.poll_interval).await,
            Err(error) => {
                if error.starts_with(TERMINAL_CREDENTIAL_ERROR) {
                    return Err(error);
                }
                eprintln!("proof queue unavailable: {}", sanitize(&error));
                sleep(worker.poll_interval).await;
            }
        }
    }
}

impl Worker {
    async fn register(&mut self) -> Result<(), String> {
        let registration_token = self
            .registration_token
            .as_deref()
            .ok_or_else(|| "worker needs a new one-time registration grant".to_string())?;
        let response = self
            .http
            .post(format!(
                "{}/internal/proof-workers/register",
                self.queue_url
            ))
            .header("x-zylith-worker-registration", registration_token)
            .json(&RegisterProofWorker {
                worker_id: self.worker_id.clone(),
                capabilities: self.capabilities.clone(),
            })
            .send()
            .await
            .map_err(|error| format!("worker registration: {error}"))?;
        if response.status() == StatusCode::UNAUTHORIZED {
            self.session = None;
            return Err(format!(
                "{TERMINAL_CREDENTIAL_ERROR} registration grant was rejected"
            ));
        }
        if !response.status().is_success() {
            return Err(format!(
                "worker registration returned http {}",
                response.status()
            ));
        }
        let response: RegisterProofWorkerResponse = response
            .json()
            .await
            .map_err(|error| format!("worker registration response: {error}"))?;
        verify_config_mac(registration_token, &response.config, &response.config_mac)?;
        if response.config.schema_version != zylith_proof_job::PROOF_JOB_SCHEMA_VERSION {
            return Err("coordinator uses an unsupported proof-job version".into());
        }
        self.verify_session_identity(&response.config)?;
        self.session = Some(response);
        self.registration_token = None;
        Ok(())
    }

    async fn refresh(&mut self) -> Result<(), String> {
        let token = self
            .session
            .as_ref()
            .ok_or_else(|| "worker has no session to refresh".to_string())?
            .token
            .clone();
        let response = self
            .http
            .post(format!("{}/internal/proof-workers/refresh", self.queue_url))
            .bearer_auth(&token)
            .send()
            .await
            .map_err(|error| format!("worker session refresh: {error}"))?;
        if response.status() == StatusCode::UNAUTHORIZED {
            self.session = None;
            return Err(format!(
                "{TERMINAL_CREDENTIAL_ERROR} session refresh was rejected"
            ));
        }
        if !response.status().is_success() {
            return Err(format!(
                "worker session refresh returned http {}",
                response.status()
            ));
        }
        let response: RegisterProofWorkerResponse = response
            .json()
            .await
            .map_err(|error| format!("worker session refresh response: {error}"))?;
        verify_config_mac(&token, &response.config, &response.config_mac)?;
        self.verify_session_identity(&response.config)?;
        self.session = Some(response);
        Ok(())
    }

    fn verify_session_identity(&self, config: &WorkerSessionConfig) -> Result<(), String> {
        if config.worker_id != self.worker_id || config.capabilities != self.capabilities {
            return Err("coordinator signed a session for another worker build".into());
        }
        validate_worker_resource_limits(config.lease_duration_ms, config.max_request_bytes)?;
        let required_lifetime =
            required_session_lifetime(self.max_proof_duration, config.lease_duration_ms);
        if config.session_expires_at_unix_ms < now_ms().saturating_add(required_lifetime) {
            return Err("worker session is too short for one bounded proof and its lease".into());
        }
        Ok(())
    }

    async fn token(&mut self) -> Result<String, String> {
        let now = now_ms();
        let needs_refresh = self.session.as_ref().is_some_and(|session| {
            session_needs_refresh(
                session.config.session_expires_at_unix_ms,
                now,
                self.max_proof_duration,
                session.config.lease_duration_ms,
            )
        });
        if self.session.is_none() {
            self.register().await?;
        } else if needs_refresh {
            self.refresh().await?;
        }
        Ok(self
            .session
            .as_ref()
            .expect("session was registered")
            .token
            .clone())
    }

    async fn claim(&mut self) -> Result<Option<ProofJobClaim>, String> {
        let token = self.token().await?;
        let response = self
            .http
            .post(format!("{}/internal/proof-jobs/claim", self.queue_url))
            .bearer_auth(token)
            .send()
            .await
            .map_err(|error| format!("job claim: {error}"))?;
        if response.status() == StatusCode::NO_CONTENT {
            return Ok(None);
        }
        if response.status() == StatusCode::UNAUTHORIZED {
            self.session = None;
            return Err(format!("{TERMINAL_CREDENTIAL_ERROR} session was rejected"));
        }
        if !response.status().is_success() {
            return Err(format!("job claim returned http {}", response.status()));
        }
        let claim: ProofJobClaim = response
            .json()
            .await
            .map_err(|error| format!("job claim response: {error}"))?;
        claim.descriptor.validate()?;
        if !self.capabilities.supports(&claim.descriptor) {
            return Err("coordinator assigned a job for another prover build".into());
        }
        Ok(Some(claim))
    }

    async fn prove(&mut self, claim: ProofJobClaim) -> Result<(), String> {
        let token = self.token().await?;
        let max_request_bytes = self
            .session
            .as_ref()
            .expect("worker has a session")
            .config
            .max_request_bytes;
        let request_bytes =
            match bounded_request_size(claim.descriptor.request_bytes, max_request_bytes) {
                Ok(request_bytes) => request_bytes,
                Err(failure) => {
                    self.report_failure(&token, &claim, failure).await?;
                    return Err("proof artifact exceeds the signed worker limit".into());
                }
            };
        let response = self
            .http
            .get(format!("{}{}", self.queue_url, claim.artifact_path))
            .bearer_auth(&token)
            .send()
            .await
            .map_err(|error| format!("artifact fetch: {error}"))?;
        let artifact_status = response.status();
        if matches!(
            artifact_status,
            StatusCode::UNAUTHORIZED | StatusCode::FORBIDDEN
        ) {
            self.session = None;
            return Err(format!(
                "{TERMINAL_CREDENTIAL_ERROR} artifact fetch was rejected"
            ));
        }
        if !artifact_status.is_success() {
            if artifact_status.is_server_error()
                || matches!(
                    artifact_status,
                    StatusCode::REQUEST_TIMEOUT
                        | StatusCode::TOO_EARLY
                        | StatusCode::TOO_MANY_REQUESTS
                )
            {
                return Err(format!("artifact fetch returned http {artifact_status}"));
            }
            self.report_failure(
                &token,
                &claim,
                proof_failure(
                    ProofFailureClass::InvalidArtifact,
                    "ARTIFACT_FETCH_REJECTED",
                    None,
                ),
            )
            .await?;
            return Err(format!("artifact fetch returned http {artifact_status}"));
        }
        let artifact = match read_bounded(response, request_bytes).await {
            Ok(artifact) => artifact,
            Err(BoundedReadError::TooLarge { .. }) => {
                self.report_failure(
                    &token,
                    &claim,
                    proof_failure(
                        ProofFailureClass::InvalidArtifact,
                        "ARTIFACT_TOO_LARGE",
                        None,
                    ),
                )
                .await?;
                return Err("proof artifact exceeds its pinned size".into());
            }
            Err(BoundedReadError::Transport) => {
                return Err("proof artifact response read failed".into());
            }
        };
        if artifact.len() as u64 != claim.descriptor.request_bytes
            || proof_artifact_hash(&artifact) != claim.descriptor.request_hash
        {
            self.report_failure(
                &token,
                &claim,
                proof_failure(
                    ProofFailureClass::InvalidArtifact,
                    "ARTIFACT_MISMATCH",
                    None,
                ),
            )
            .await?;
            return Err("proof artifact failed its size or hash check".into());
        }
        let response = self
            .http
            .post(format!(
                "{}/internal/proof-jobs/{}/start",
                self.queue_url, claim.descriptor.job_id
            ))
            .bearer_auth(&token)
            .json(&ProofJobLeaseRequest {
                lease_id: claim.lease_id.clone(),
            })
            .send()
            .await
            .map_err(|error| format!("proof start: {error}"))?;
        if matches!(
            response.status(),
            StatusCode::UNAUTHORIZED | StatusCode::FORBIDDEN
        ) {
            self.session = None;
            return Err(format!(
                "{TERMINAL_CREDENTIAL_ERROR} proof start was rejected"
            ));
        }
        if !response.status().is_success() {
            return Err(format!("proof lease is stale ({})", response.status()));
        }
        let lease_duration_ms = self
            .session
            .as_ref()
            .expect("worker has a session")
            .config
            .lease_duration_ms;
        let (stop_heartbeat, heartbeat_stop) = watch::channel(false);
        let mut heartbeat = tokio::spawn(renew_lease(
            self.http.clone(),
            self.queue_url.clone(),
            token.clone(),
            claim.descriptor.job_id.clone(),
            claim.lease_id.clone(),
            lease_duration_ms,
            heartbeat_stop,
        ));
        let completion = async {
            let result = match self.run_prover(artifact).await {
                Ok(result) => result,
                Err(failure) => {
                    let code = failure.code.clone();
                    self.report_failure(&token, &claim, failure).await?;
                    return Err(format!("stwo prover failed with {code}"));
                }
            };
            let completion = CompleteProofJob {
                lease_id: claim.lease_id.clone(),
                prover_build_id: self.capabilities.prover_build_id.clone(),
                request_hash: claim.descriptor.request_hash.clone(),
                result: ProofPayload {
                    proof: result.proof,
                    proof_facts: result.proof_facts,
                    resource_usage: result.resource_usage,
                },
            };
            let response = self
                .http
                .post(format!(
                    "{}/internal/proof-jobs/{}/complete",
                    self.queue_url, claim.descriptor.job_id
                ))
                .bearer_auth(&token)
                .json(&completion)
                .send()
                .await
                .map_err(|error| format!("proof completion: {error}"))?;
            if matches!(
                response.status(),
                StatusCode::UNAUTHORIZED | StatusCode::FORBIDDEN
            ) {
                return Err(format!(
                    "{TERMINAL_CREDENTIAL_ERROR} proof completion was rejected"
                ));
            }
            if response.status() == StatusCode::CONFLICT {
                return Err("proof completed after its lease expired".into());
            }
            if completion_rejection_is_permanent(response.status()) {
                self.report_failure(
                    &token,
                    &claim,
                    proof_failure(
                        ProofFailureClass::PermanentProverRejection,
                        "INVALID_PROVER_RESULT",
                        None,
                    ),
                )
                .await?;
                return Err("coordinator rejected the prover result".into());
            }
            if !response.status().is_success() {
                return Err(format!(
                    "proof completion returned http {}",
                    response.status()
                ));
            }
            Ok(())
        };
        tokio::pin!(completion);
        tokio::select! {
            completion = &mut completion => {
                let _ = stop_heartbeat.send(true);
                heartbeat
                    .await
                    .map_err(|error| format!("proof lease heartbeat task: {error}"))??;
                completion?;
            }
            heartbeat = &mut heartbeat => {
                match heartbeat {
                    Ok(Ok(())) => return Err("proof lease heartbeat stopped unexpectedly".into()),
                    Ok(Err(error)) => return Err(error),
                    Err(error) => {
                        return Err(format!("proof lease heartbeat task: {error}"));
                    }
                }
            }
        }
        eprintln!("proof job complete");
        Ok(())
    }

    async fn run_prover(&self, artifact: Vec<u8>) -> Result<ProveResult, ProofFailure> {
        let response = self
            .http
            .post(&self.stwo_url)
            .header("content-type", "application/json")
            .body(artifact)
            .send()
            .await
            .map_err(|_| {
                proof_failure(
                    ProofFailureClass::TransientNetwork,
                    "PROVER_REQUEST_FAILED",
                    None,
                )
            })?;
        if !response.status().is_success() {
            return Err(classify_prover_http(response.status()));
        }
        let bytes = Zeroizing::new(
            read_bounded(response, MAX_RESPONSE_BYTES)
                .await
                .map_err(classify_prover_response_read)?,
        );
        let response: ProveResponse = serde_json::from_slice(&bytes).map_err(|_| {
            proof_failure(
                ProofFailureClass::PermanentProverRejection,
                "MALFORMED_PROVER_RESPONSE",
                None,
            )
        })?;
        interpret_prover_response(response)
    }

    async fn report_failure(
        &self,
        token: &str,
        claim: &ProofJobClaim,
        failure: ProofFailure,
    ) -> Result<(), String> {
        let response = self
            .http
            .post(format!(
                "{}/internal/proof-jobs/{}/fail",
                self.queue_url, claim.descriptor.job_id
            ))
            .bearer_auth(token)
            .json(&FailProofJob {
                lease_id: claim.lease_id.clone(),
                prover_build_id: self.capabilities.prover_build_id.clone(),
                request_hash: claim.descriptor.request_hash.clone(),
                failure,
            })
            .send()
            .await
            .map_err(|_| "proof failure report could not reach the coordinator".to_string())?;
        if response.status() == StatusCode::CONFLICT {
            return Err("proof failed after its lease expired".into());
        }
        if matches!(
            response.status(),
            StatusCode::UNAUTHORIZED | StatusCode::FORBIDDEN
        ) {
            return Err(format!(
                "{TERMINAL_CREDENTIAL_ERROR} proof failure report was rejected"
            ));
        }
        if !response.status().is_success() {
            return Err(format!(
                "proof failure report returned http {}",
                response.status()
            ));
        }
        Ok(())
    }
}

fn validate_prover_result(result: ProveResult) -> Result<ProveResult, ProofFailure> {
    if result
        .resource_usage
        .as_ref()
        .is_some_and(|usage| usage.validate_measurement().is_err())
    {
        return Err(proof_failure(
            ProofFailureClass::PermanentProverRejection,
            "INVALID_RESOURCE_USAGE",
            None,
        ));
    }
    Ok(result)
}

fn interpret_prover_response(response: ProveResponse) -> Result<ProveResult, ProofFailure> {
    if response.jsonrpc != "2.0" || response.id != 1 {
        return Err(proof_failure(
            ProofFailureClass::PermanentProverRejection,
            "INVALID_JSON_RPC_ENVELOPE",
            None,
        ));
    }
    match (response.result, response.error) {
        (Some(result), None) => validate_prover_result(result),
        (None, Some(error)) => Err(classify_prover_error(error.code, error.data)),
        (Some(_), Some(_)) => Err(proof_failure(
            ProofFailureClass::PermanentProverRejection,
            "AMBIGUOUS_PROVER_RESPONSE",
            None,
        )),
        (None, None) => Err(proof_failure(
            ProofFailureClass::PermanentProverRejection,
            "EMPTY_PROVER_RESPONSE",
            None,
        )),
    }
}

fn required_session_lifetime(max_proof_duration: Duration, lease_duration_ms: u64) -> u64 {
    u64::try_from(max_proof_duration.as_millis())
        .unwrap_or(u64::MAX)
        .saturating_add(lease_duration_ms)
}

fn validate_worker_resource_limits(
    lease_duration_ms: u64,
    max_request_bytes: u64,
) -> Result<(), String> {
    if lease_duration_ms == 0
        || max_request_bytes == 0
        || usize::try_from(max_request_bytes).is_err()
    {
        return Err("coordinator signed invalid worker resource limits".into());
    }
    Ok(())
}

fn session_needs_refresh(
    expires_at_ms: u64,
    now_ms: u64,
    max_proof_duration: Duration,
    lease_duration_ms: u64,
) -> bool {
    expires_at_ms
        < now_ms.saturating_add(required_session_lifetime(
            max_proof_duration,
            lease_duration_ms,
        ))
}

async fn renew_lease(
    http: Client,
    queue_url: String,
    token: String,
    job_id: String,
    lease_id: String,
    lease_duration_ms: u64,
    mut stop: watch::Receiver<bool>,
) -> Result<(), String> {
    let interval_ms = (lease_duration_ms / 3).max(1_000);
    loop {
        tokio::select! {
            changed = stop.changed() => {
                if changed.is_err() || *stop.borrow() {
                    return Ok(());
                }
            }
            () = sleep(Duration::from_millis(interval_ms)) => {
                let response = http
                    .post(format!("{queue_url}/internal/proof-jobs/{job_id}/start"))
                    .bearer_auth(&token)
                    .timeout(Duration::from_secs(10))
                    .json(&ProofJobLeaseRequest { lease_id: lease_id.clone() })
                    .send()
                    .await
                    .map_err(|error| format!("proof lease heartbeat: {error}"))?;
                if matches!(
                    response.status(),
                    StatusCode::UNAUTHORIZED | StatusCode::FORBIDDEN
                ) {
                    return Err(format!(
                        "{TERMINAL_CREDENTIAL_ERROR} proof lease heartbeat was rejected"
                    ));
                }
                if !response.status().is_success() {
                    return Err(format!(
                        "proof lease heartbeat returned http {}",
                        response.status()
                    ));
                }
            }
        }
    }
}

fn verify_config_mac(
    secret: &str,
    config: &WorkerSessionConfig,
    expected: &str,
) -> Result<(), String> {
    let encoded = serde_json::to_vec(config).map_err(|error| error.to_string())?;
    let mut mac = <Hmac<Sha256> as Mac>::new_from_slice(secret.as_bytes())
        .map_err(|_| "worker config mac key is invalid".to_string())?;
    mac.update(&encoded);
    let actual = hex::encode(mac.finalize().into_bytes());
    if !constant_time_eq(&actual, expected) {
        return Err("worker config signature is invalid".into());
    }
    Ok(())
}

async fn read_bounded(
    response: reqwest::Response,
    max_bytes: usize,
) -> Result<Vec<u8>, BoundedReadError> {
    if response
        .content_length()
        .is_some_and(|length| length > max_bytes as u64)
    {
        return Err(BoundedReadError::TooLarge { maximum: max_bytes });
    }
    let mut response = response;
    let mut bytes = Vec::new();
    while let Some(chunk) = response
        .chunk()
        .await
        .map_err(|_| BoundedReadError::Transport)?
    {
        if bytes
            .len()
            .checked_add(chunk.len())
            .is_none_or(|length| length > max_bytes)
        {
            return Err(BoundedReadError::TooLarge { maximum: max_bytes });
        }
        bytes.extend_from_slice(&chunk);
    }
    Ok(bytes)
}

fn bounded_request_size(request_bytes: u64, maximum: u64) -> Result<usize, ProofFailure> {
    if request_bytes == 0 || request_bytes > maximum {
        return Err(proof_failure(
            ProofFailureClass::InvalidArtifact,
            "ARTIFACT_TOO_LARGE",
            None,
        ));
    }
    usize::try_from(request_bytes).map_err(|_| {
        proof_failure(
            ProofFailureClass::InvalidArtifact,
            "ARTIFACT_TOO_LARGE",
            None,
        )
    })
}

fn classify_prover_response_read(error: BoundedReadError) -> ProofFailure {
    match error {
        BoundedReadError::TooLarge { .. } => proof_failure(
            ProofFailureClass::PermanentProverRejection,
            "PROVER_RESPONSE_TOO_LARGE",
            None,
        ),
        BoundedReadError::Transport => proof_failure(
            ProofFailureClass::TransientNetwork,
            "PROVER_RESPONSE_READ_FAILED",
            None,
        ),
    }
}

fn sanitize(value: &str) -> String {
    let mut output = String::new();
    let mut run = String::new();
    let flush = |run: &mut String, output: &mut String| {
        if run.len() >= 32 {
            output.push_str("<redacted>");
        } else {
            output.push_str(run);
        }
        run.clear();
    };
    for character in value.chars() {
        if character.is_ascii_alphanumeric() {
            run.push(character);
        } else {
            flush(&mut run, &mut output);
            output.push(character);
        }
    }
    flush(&mut run, &mut output);
    output.chars().take(512).collect()
}

fn proof_failure(class: ProofFailureClass, code: &str, component: Option<&str>) -> ProofFailure {
    ProofFailure {
        class,
        code: code.into(),
        component: component.map(str::to_owned),
        profile_id: None,
        required: None,
        available: None,
    }
}

fn classify_prover_http(status: StatusCode) -> ProofFailure {
    if matches!(
        status,
        StatusCode::REQUEST_TIMEOUT | StatusCode::TOO_EARLY | StatusCode::TOO_MANY_REQUESTS
    ) || status.is_server_error()
    {
        proof_failure(
            ProofFailureClass::TransientProverUnavailable,
            "PROVER_HTTP_UNAVAILABLE",
            None,
        )
    } else {
        proof_failure(
            ProofFailureClass::PermanentProverRejection,
            "PROVER_HTTP_REJECTED",
            None,
        )
    }
}

fn completion_rejection_is_permanent(status: StatusCode) -> bool {
    matches!(
        status,
        StatusCode::BAD_REQUEST | StatusCode::PAYLOAD_TOO_LARGE | StatusCode::UNPROCESSABLE_ENTITY
    )
}

fn classify_prover_error(code: i64, data: Option<StructuredProverFailure>) -> ProofFailure {
    if let Some(data) = data {
        let failure = ProofFailure {
            class: data.class,
            code: data.code,
            component: data.component,
            profile_id: data.profile_id,
            required: data.required,
            available: data.available,
        };
        if data.schema_version == 1 && failure.validate().is_ok() {
            return failure;
        }
        return proof_failure(
            ProofFailureClass::PermanentProverRejection,
            "INVALID_FAILURE_ADAPTER_DATA",
            None,
        );
    }
    let code = match code {
        -32700 => "PROVER_PARSE_ERROR",
        -32600 => "INVALID_PROVER_REQUEST",
        -32601 => "PROVER_METHOD_NOT_FOUND",
        -32602 => "INVALID_PROVER_PARAMS",
        -32603 => "PROVER_INTERNAL_ERROR",
        _ => "UNCLASSIFIED_PROVER_REJECTION",
    };
    proof_failure(ProofFailureClass::PermanentProverRejection, code, None)
}

fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("clock after 1970")
        .as_millis() as u64
}

fn validate_queue_url(value: &str) -> Result<String, String> {
    let parsed = Url::parse(value).map_err(|error| format!("proof queue url: {error}"))?;
    let local = parsed.host_str().is_some_and(is_private_host);
    if parsed.scheme() != "https" && !(parsed.scheme() == "http" && local) {
        return Err("proof queue url must use https unless it is on a private network".into());
    }
    Ok(value.trim_end_matches('/').to_owned())
}

fn validate_stwo_url(value: &str) -> Result<String, String> {
    let parsed = Url::parse(value).map_err(|error| format!("stwo prover url: {error}"))?;
    if parsed.scheme() != "http" || parsed.host_str().is_none_or(|host| !is_private_host(host)) {
        return Err("stwo prover must use a local or private http endpoint".into());
    }
    Ok(value.trim_end_matches('/').to_owned())
}

fn is_private_host(host: &str) -> bool {
    if matches!(host, "localhost" | "stwo") {
        return true;
    }
    match host
        .trim_start_matches('[')
        .trim_end_matches(']')
        .parse::<std::net::IpAddr>()
    {
        Ok(std::net::IpAddr::V4(ip)) => ip.is_loopback() || ip.is_private(),
        Ok(std::net::IpAddr::V6(ip)) => ip.is_loopback() || (ip.segments()[0] & 0xfe00) == 0xfc00,
        Err(_) => false,
    }
}

fn verify_compiled_pin(label: &str, runtime: &str, compiled: Option<&str>) -> Result<(), String> {
    let compiled = compiled.ok_or_else(|| format!("worker binary has no compiled {label}"))?;
    if runtime != compiled {
        return Err(format!("runtime {label} does not match the worker image"));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn resource_usage() -> ProofResourceUsage {
        let components = [
            "bitwise",
            "cpu",
            "ec_op",
            "ecdsa",
            "pedersen",
            "poseidon",
            "range_check",
        ];
        let mut usage = ProofResourceUsage {
            component_registry_id: String::new(),
            raw_snos_steps: 1,
            adapted_rows: 1,
            memory_words: 1,
            memory_holes: 0,
            builtin_instances: components
                .into_iter()
                .map(|component| (component.into(), 1))
                .collect(),
            component_log_sizes: components
                .into_iter()
                .map(|component| (component.into(), 1))
                .collect(),
            max_domain_log_size: 1,
            peak_rss_bytes: 1,
            wall_time_ms: 1,
        };
        usage.component_registry_id = usage.expected_component_registry_id().unwrap();
        usage
    }

    #[test]
    fn the_queue_requires_tls_outside_private_networks() {
        assert!(validate_queue_url("https://control.zylith.fi").is_ok());
        assert!(validate_queue_url("http://10.0.0.3:3000").is_ok());
        assert!(validate_queue_url("http://control.zylith.fi").is_err());
    }

    #[test]
    fn the_stwo_endpoint_cannot_name_a_public_host() {
        assert!(validate_stwo_url("http://127.0.0.1:3100").is_ok());
        assert!(validate_stwo_url("http://stwo:3100").is_ok());
        assert!(validate_stwo_url("https://prover.example").is_err());
        assert!(validate_stwo_url("http://8.8.8.8:3100").is_err());
    }

    #[test]
    fn a_session_budget_includes_the_full_proof_and_lease() {
        assert_eq!(
            required_session_lifetime(Duration::from_secs(900), 60_000),
            960_000
        );
        assert!(!session_needs_refresh(
            1_960_000,
            1_000_000,
            Duration::from_secs(900),
            60_000,
        ));
        assert!(session_needs_refresh(
            1_959_999,
            1_000_000,
            Duration::from_secs(900),
            60_000,
        ));
    }

    #[test]
    fn structured_resource_usage_is_optional_but_never_partially_trusted() {
        let valid = ProveResult {
            proof: "proof".into(),
            proof_facts: Vec::new(),
            resource_usage: Some(resource_usage()),
        };
        assert!(validate_prover_result(valid).is_ok());
        let mut malformed = resource_usage();
        malformed.component_log_sizes.remove("poseidon");
        let failure = validate_prover_result(ProveResult {
            proof: "proof".into(),
            proof_facts: Vec::new(),
            resource_usage: Some(malformed),
        })
        .err()
        .unwrap();
        assert_eq!(failure.class, ProofFailureClass::PermanentProverRejection);
        assert_eq!(failure.code, "INVALID_RESOURCE_USAGE");
    }

    #[test]
    fn prover_errors_cannot_echo_witness_values() {
        let secret_hex = format!("0x{}", "ab".repeat(32));
        let secret_decimal = "1234567890123456789012345678901234567890";
        let message = format!("invalid witness {secret_hex} at value {secret_decimal}");
        let sanitized = sanitize(&message);
        assert!(!sanitized.contains(&secret_hex));
        assert!(!sanitized.contains(secret_decimal));
        assert_eq!(sanitized.matches("<redacted>").count(), 2);
        let response: ProveResponse = serde_json::from_value(serde_json::json!({
            "jsonrpc": "2.0",
            "id": 1,
            "error": {
                "code": -32001,
                "message": message,
                "data": null
            }
        }))
        .unwrap();
        let failure = classify_prover_error(-32001, response.error.unwrap().data);
        assert_eq!(
            failure,
            proof_failure(
                ProofFailureClass::PermanentProverRejection,
                "UNCLASSIFIED_PROVER_REJECTION",
                None,
            )
        );
        assert!(
            !serde_json::to_string(&failure)
                .unwrap()
                .contains("invalid witness")
        );
    }

    #[test]
    fn structured_adapter_classifies_capacity_without_reading_the_message() {
        let response: ProveResponse = serde_json::from_value(serde_json::json!({
            "jsonrpc": "2.0",
            "id": 1,
            "error": {
                "code": -32001,
                "message": "secret witness text that must never leave the worker",
                "data": {
                    "schema_version": 1,
                    "class": "CAPACITY_EXCEEDED",
                    "code": "TRACE_DOMAIN_EXCEEDED",
                    "component": "POSEIDON",
                    "profile_id": "proof1-log20",
                    "required": 1079477,
                    "available": 1048576
                }
            }
        }))
        .unwrap();
        let failure = classify_prover_error(-32001, response.error.unwrap().data);
        assert_eq!(failure.class, ProofFailureClass::CapacityExceeded);
        assert_eq!(failure.component.as_deref(), Some("POSEIDON"));
        assert_eq!(failure.required, Some(1_079_477));
        assert_eq!(failure.available, Some(1_048_576));
        assert!(!serde_json::to_string(&failure).unwrap().contains("secret"));
    }

    #[test]
    fn success_plus_error_is_a_permanent_ambiguous_response() {
        let response: ProveResponse = serde_json::from_value(serde_json::json!({
            "jsonrpc": "2.0",
            "id": 1,
            "result": {
                "proof": "proof",
                "proof_facts": []
            },
            "error": {
                "code": -32001,
                "message": "must stay ignored",
                "data": {
                    "schema_version": 1,
                    "class": "TRANSIENT_NETWORK",
                    "code": "NETWORK",
                    "component": null,
                    "profile_id": null,
                    "required": null,
                    "available": null
                }
            }
        }))
        .unwrap();
        let failure = match interpret_prover_response(response) {
            Err(failure) => failure,
            Ok(_) => panic!("ambiguous response was accepted"),
        };
        assert_eq!(failure.class, ProofFailureClass::PermanentProverRejection);
        assert_eq!(failure.code, "AMBIGUOUS_PROVER_RESPONSE");
    }

    #[test]
    fn malformed_or_unknown_adapter_data_fails_closed() {
        let unknown = serde_json::from_value::<ProveResponse>(serde_json::json!({
            "jsonrpc": "2.0",
            "id": 1,
            "error": {
                "code": -32001,
                "message": "ignored",
                "data": {
                    "schema_version": 1,
                    "class": "SOMETHING_NEW",
                    "code": "NEW",
                    "component": null,
                    "profile_id": null,
                    "required": null,
                    "available": null
                }
            }
        }));
        assert!(unknown.is_err());

        for malformed in [
            serde_json::json!({
                "jsonrpc": "1.0",
                "id": 1,
                "result": { "proof": "proof", "proof_facts": [] }
            }),
            serde_json::json!({
                "jsonrpc": "2.0",
                "id": 2,
                "result": { "proof": "proof", "proof_facts": [] }
            }),
        ] {
            let failure = interpret_prover_response(serde_json::from_value(malformed).unwrap())
                .err()
                .unwrap();
            assert_eq!(failure.class, ProofFailureClass::PermanentProverRejection);
            assert_eq!(failure.code, "INVALID_JSON_RPC_ENVELOPE");
        }

        for extended in [
            serde_json::json!({
                "jsonrpc": "2.0",
                "id": 1,
                "result": { "proof": "proof", "proof_facts": [] },
                "extra": true
            }),
            serde_json::json!({
                "jsonrpc": "2.0",
                "id": 1,
                "result": { "proof": "proof", "proof_facts": [], "extra": true }
            }),
            serde_json::json!({
                "jsonrpc": "2.0",
                "id": 1,
                "error": { "code": -32001, "message": "ignored", "data": null, "extra": true }
            }),
        ] {
            assert!(serde_json::from_value::<ProveResponse>(extended).is_err());
        }

        let malformed = StructuredProverFailure {
            schema_version: 2,
            class: ProofFailureClass::CapacityExceeded,
            code: "TRACE_DOMAIN_EXCEEDED".into(),
            component: Some("POSEIDON".into()),
            profile_id: None,
            required: Some(1),
            available: Some(2),
        };
        assert_eq!(
            classify_prover_error(-32001, Some(malformed)).code,
            "INVALID_FAILURE_ADAPTER_DATA"
        );
    }

    #[test]
    fn transport_and_http_failures_have_closed_retry_semantics() {
        assert!(validate_worker_resource_limits(1, 1).is_ok());
        assert!(validate_worker_resource_limits(0, 1).is_err());
        assert!(validate_worker_resource_limits(1, 0).is_err());
        assert_eq!(bounded_request_size(1, 1).unwrap(), 1);
        for (requested, maximum) in [(0, 1), (2, 1)] {
            let failure = bounded_request_size(requested, maximum).unwrap_err();
            assert_eq!(failure.class, ProofFailureClass::InvalidArtifact);
            assert_eq!(failure.code, "ARTIFACT_TOO_LARGE");
        }
        assert_eq!(
            classify_prover_http(StatusCode::SERVICE_UNAVAILABLE).class,
            ProofFailureClass::TransientProverUnavailable
        );
        assert_eq!(
            classify_prover_http(StatusCode::TOO_MANY_REQUESTS).class,
            ProofFailureClass::TransientProverUnavailable
        );
        assert_eq!(
            classify_prover_http(StatusCode::REQUEST_TIMEOUT).class,
            ProofFailureClass::TransientProverUnavailable
        );
        assert_eq!(
            classify_prover_http(StatusCode::TOO_EARLY).class,
            ProofFailureClass::TransientProverUnavailable
        );
        assert_eq!(
            classify_prover_http(StatusCode::BAD_REQUEST).class,
            ProofFailureClass::PermanentProverRejection
        );
        assert_eq!(
            proof_failure(
                ProofFailureClass::TransientNetwork,
                "PROVER_REQUEST_FAILED",
                None,
            )
            .class,
            ProofFailureClass::TransientNetwork
        );
        assert_eq!(
            classify_prover_error(-32602, None).code,
            "INVALID_PROVER_PARAMS"
        );
        assert_eq!(
            classify_prover_response_read(BoundedReadError::TooLarge { maximum: 1 }).class,
            ProofFailureClass::PermanentProverRejection
        );
        assert_eq!(
            classify_prover_response_read(BoundedReadError::TooLarge { maximum: 1 }).code,
            "PROVER_RESPONSE_TOO_LARGE"
        );
        assert_eq!(
            classify_prover_response_read(BoundedReadError::Transport).class,
            ProofFailureClass::TransientNetwork
        );
        for status in [
            StatusCode::BAD_REQUEST,
            StatusCode::PAYLOAD_TOO_LARGE,
            StatusCode::UNPROCESSABLE_ENTITY,
        ] {
            assert!(completion_rejection_is_permanent(status));
        }
        assert!(!completion_rejection_is_permanent(
            StatusCode::SERVICE_UNAVAILABLE
        ));
    }
}

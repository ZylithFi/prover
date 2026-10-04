//! disposable proof worker: claims immutable jobs, invokes a local stwo engine and returns proofs.

use std::env;
use std::time::Duration;

use hmac::{Hmac, Mac};
use reqwest::{Client, StatusCode};
use serde::Deserialize;
use sha2::Sha256;
use tokio::sync::watch;
use tokio::time::sleep;
use url::Url;
use zylith_proof_job::{
    CompleteProofJob, ProofJobClaim, ProofJobLeaseRequest, ProofPayload, RegisterProofWorker,
    RegisterProofWorkerResponse, WorkerCapabilities, WorkerSessionConfig, constant_time_eq,
    proof_artifact_hash,
};

const MAX_RESPONSE_BYTES: usize = 16 * 1024 * 1024;
const TERMINAL_CREDENTIAL_ERROR: &str = "terminal worker credentials:";

#[derive(Deserialize)]
struct ProveResponse {
    result: Option<ProveResult>,
    error: Option<ProveError>,
}

#[derive(Deserialize)]
struct ProveResult {
    proof: String,
    proof_facts: Vec<String>,
}

#[derive(Deserialize)]
struct ProveError {
    code: i64,
    #[serde(rename = "message")]
    _message: String,
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
            program_variant: "VIRTUAL_SNOS".into(),
            virtual_program_hash,
            starknet_os_output_version: "VIRTUAL_SNOS0".into(),
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
        let response = self
            .http
            .get(format!("{}{}", self.queue_url, claim.artifact_path))
            .bearer_auth(&token)
            .send()
            .await
            .map_err(|error| format!("artifact fetch: {error}"))?;
        if !response.status().is_success() {
            return Err(format!(
                "artifact fetch returned http {}",
                response.status()
            ));
        }
        let artifact = read_bounded(response, claim.descriptor.request_bytes as usize).await?;
        if artifact.len() as u64 != claim.descriptor.request_bytes
            || proof_artifact_hash(&artifact) != claim.descriptor.request_hash
        {
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
            let response = self
                .http
                .post(&self.stwo_url)
                .header("content-type", "application/json")
                .body(artifact)
                .send()
                .await
                .map_err(|error| format!("stwo prover: {error}"))?;
            if !response.status().is_success() {
                return Err(format!("stwo prover returned http {}", response.status()));
            }
            let bytes = read_bounded(response, MAX_RESPONSE_BYTES).await?;
            let response: ProveResponse = serde_json::from_slice(&bytes)
                .map_err(|error| format!("stwo response: {error}"))?;
            let result = match (response.result, response.error) {
                (Some(result), None) => result,
                (_, Some(error)) => {
                    return Err(prover_error(error.code));
                }
                _ => return Err("stwo prover returned no result".into()),
            };
            let completion = CompleteProofJob {
                lease_id: claim.lease_id,
                prover_build_id: self.capabilities.prover_build_id.clone(),
                request_hash: claim.descriptor.request_hash,
                result: ProofPayload {
                    proof: result.proof,
                    proof_facts: result.proof_facts,
                },
            };
            let response = self
                .http
                .post(format!(
                    "{}/internal/proof-jobs/{}/complete",
                    self.queue_url, claim.descriptor.job_id
                ))
                .bearer_auth(token)
                .json(&completion)
                .send()
                .await
                .map_err(|error| format!("proof completion: {error}"))?;
            if response.status() == StatusCode::CONFLICT {
                return Err("proof completed after its lease expired".into());
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
}

fn required_session_lifetime(max_proof_duration: Duration, lease_duration_ms: u64) -> u64 {
    u64::try_from(max_proof_duration.as_millis())
        .unwrap_or(u64::MAX)
        .saturating_add(lease_duration_ms)
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

async fn read_bounded(response: reqwest::Response, max_bytes: usize) -> Result<Vec<u8>, String> {
    if response
        .content_length()
        .is_some_and(|length| length > max_bytes as u64)
    {
        return Err(format!("response exceeds {max_bytes} bytes"));
    }
    let mut response = response;
    let mut bytes = Vec::new();
    while let Some(chunk) = response
        .chunk()
        .await
        .map_err(|error| format!("response read: {error}"))?
    {
        if bytes.len() + chunk.len() > max_bytes {
            return Err(format!("response exceeds {max_bytes} bytes"));
        }
        bytes.extend_from_slice(&chunk);
    }
    Ok(bytes)
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

fn prover_error(code: i64) -> String {
    format!("stwo prover error code {code}")
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
    fn prover_errors_cannot_echo_witness_values() {
        let secret_hex = format!("0x{}", "ab".repeat(32));
        let secret_decimal = "1234567890123456789012345678901234567890";
        let message = format!("invalid witness {secret_hex} at value {secret_decimal}");
        let sanitized = sanitize(&message);
        assert!(!sanitized.contains(&secret_hex));
        assert!(!sanitized.contains(secret_decimal));
        assert_eq!(sanitized.matches("<redacted>").count(), 2);
        assert_eq!(prover_error(-32_001), "stwo prover error code -32001");
    }
}

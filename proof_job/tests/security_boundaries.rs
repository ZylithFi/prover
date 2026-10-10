use std::collections::BTreeMap;

use zylith_proof_job::{
    PROOF_CAPACITY_SCHEMA_VERSION, PROOF_JOB_SCHEMA_VERSION, ProofCapacityProfile,
    ProofCapacityVector, ProofFailure, ProofFailureClass, ProofJobDescriptor, ProofReleaseIdentity,
    ProofResourceUsage, ProofShapeLimits, ProofStatementKind, constant_time_eq,
};

fn descriptor() -> ProofJobDescriptor {
    let mut descriptor = ProofJobDescriptor {
        schema_version: PROOF_JOB_SCHEMA_VERSION,
        job_id: String::new(),
        statement_kind: ProofStatementKind::Transition,
        transition_id: "transition:security-boundary".into(),
        epoch_id: Some(7),
        protocol_version: "zylith-v2".into(),
        config_version: "release-2".into(),
        prover_build_id: "stwo-pinned".into(),
        chain_id: "0x1".into(),
        exchange_address: "0x2".into(),
        proof_program_address: "0x3".into(),
        program_entrypoint: "compile_transition_proof".into(),
        proof_version: "proof2".into(),
        program_variant: "VIRTUAL_SNOS".into(),
        virtual_program_hash: "0x4".into(),
        starknet_os_output_version: "VIRTUAL_SNOS0".into(),
        starknet_os_config_hash: "0x5".into(),
        base_block_number: 100,
        base_block_hash: "0x6".into(),
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

fn refresh_descriptor(descriptor: &mut ProofJobDescriptor) {
    descriptor.job_id = descriptor.expected_job_id().unwrap();
}

fn usage(scale: u64, capacity: bool) -> ProofResourceUsage {
    let domain_log_size = if capacity { 5 } else { 4 };
    let mut usage = ProofResourceUsage {
        component_registry_id: String::new(),
        raw_snos_steps: scale,
        adapted_rows: scale,
        memory_words: scale,
        memory_holes: 0,
        builtin_instances: BTreeMap::from([
            ("cpu".into(), if capacity { scale } else { 1 }),
            ("poseidon".into(), if capacity { scale } else { 1 }),
        ]),
        component_log_sizes: BTreeMap::from([
            ("cpu".into(), domain_log_size),
            ("poseidon".into(), domain_log_size),
        ]),
        max_domain_log_size: domain_log_size,
        peak_rss_bytes: scale,
        wall_time_ms: scale,
    };
    usage.component_registry_id = usage.expected_component_registry_id().unwrap();
    usage
}

fn profile() -> ProofCapacityProfile {
    let shape = ProofShapeLimits {
        markets: 1,
        resting_orders: 1,
        admissions: 1,
        crossings: 1,
        outcomes: 1,
        nullifiers: 1,
        retired_nullifiers: 1,
        outputs: 1,
        funding_notes: 1,
        membership_path_elements: 1,
    };
    let mut profile = ProofCapacityProfile {
        schema_version: PROOF_CAPACITY_SCHEMA_VERSION,
        profile_id: String::new(),
        statement_kind: ProofStatementKind::Transition,
        identity: ProofReleaseIdentity {
            release_commit: "release".into(),
            prover_build_id: "prover".into(),
            proof_version: "proof".into(),
            program_variant: "VIRTUAL_SNOS".into(),
            virtual_program_hash: "0x1".into(),
            starknet_os_output_version: "VIRTUAL_SNOS0".into(),
            starknet_os_config_hash: "0x2".into(),
            proof_account_class_hash: "0x3".into(),
            proof_program_class_hash: "0x4".into(),
            statement_version: "transition-v2".into(),
        },
        vector_family: "security-boundaries".into(),
        safety_margin_bps: 1_000,
        capacity: usage(1_000, true),
        limits: shape.clone(),
        vectors: vec![ProofCapacityVector {
            vector_id: "boundary".into(),
            evidence_sha256: "a".repeat(64),
            shape,
            usage: usage(100, false),
        }],
    };
    refresh(&mut profile);
    profile
}

fn refresh(profile: &mut ProofCapacityProfile) {
    profile.capacity.component_registry_id =
        profile.capacity.expected_component_registry_id().unwrap();
    for vector in &mut profile.vectors {
        vector.usage.component_registry_id = vector.usage.expected_component_registry_id().unwrap();
    }
    profile.profile_id = profile.expected_profile_id().unwrap();
}

fn set_component_count(usage: &mut ProofResourceUsage, count: usize, builtins: bool) {
    if builtins {
        usage.builtin_instances = (0..count.saturating_sub(1))
            .map(|index| (format!("component-{index}"), 1_u64))
            .chain(std::iter::once(("cpu".into(), 1_u64)))
            .collect();
    } else {
        usage.component_log_sizes = (0..count.saturating_sub(1))
            .map(|index| (format!("component-{index}"), 1_u32))
            .chain(std::iter::once(("cpu".into(), 1_u32)))
            .collect();
    }
    usage.component_registry_id = usage.expected_component_registry_id().unwrap();
}

#[test]
fn resource_component_maps_reject_duplicate_json_keys_before_validation() {
    let expected = usage(1, false);
    let encoded = serde_json::to_string(&expected).unwrap();
    assert_eq!(
        serde_json::from_str::<ProofResourceUsage>(&encoded).unwrap(),
        expected
    );
    let duplicate_builtin = encoded.replacen(r#""cpu":1"#, r#""cpu":1,"cpu":1"#, 1);
    assert_ne!(duplicate_builtin, encoded);
    assert!(serde_json::from_str::<ProofResourceUsage>(&duplicate_builtin).is_err());

    let duplicate_trace = encoded.replacen(r#""cpu":4"#, r#""cpu":4,"cpu":4"#, 1);
    assert_ne!(duplicate_trace, encoded);
    assert!(serde_json::from_str::<ProofResourceUsage>(&duplicate_trace).is_err());
}

#[test]
fn profiles_require_evidence_and_a_vector_covering_the_declared_limits() {
    let mut missing = profile();
    missing.vectors.clear();
    refresh(&mut missing);
    assert!(missing.validate().is_err());

    let mut uncovered = profile();
    uncovered.limits.outputs += 1;
    refresh(&mut uncovered);
    assert!(uncovered.validate().is_err());
}

#[test]
fn profiles_require_the_exact_capacity_component_universe() {
    let mut missing_component = profile();
    let vector = &mut missing_component.vectors[0];
    vector.usage.builtin_instances.remove("poseidon");
    vector.usage.component_log_sizes.remove("poseidon");
    refresh(&mut missing_component);
    assert!(missing_component.validate().is_err());
}

#[test]
fn release_identity_validation_is_not_masked_by_the_profile_commitment() {
    let mut maximum = profile();
    maximum.identity.release_commit = "x".repeat(256);
    refresh(&mut maximum);
    assert!(maximum.validate().is_ok());

    let mutations: [fn(&mut ProofReleaseIdentity); 10] = [
        |identity| identity.release_commit.clear(),
        |identity| identity.prover_build_id.clear(),
        |identity| identity.proof_version.clear(),
        |identity| identity.program_variant.clear(),
        |identity| identity.virtual_program_hash.clear(),
        |identity| identity.starknet_os_output_version.clear(),
        |identity| identity.starknet_os_config_hash.clear(),
        |identity| identity.proof_account_class_hash.clear(),
        |identity| identity.proof_program_class_hash.clear(),
        |identity| identity.statement_version.clear(),
    ];
    for mutate in mutations {
        let mut candidate = profile();
        mutate(&mut candidate.identity);
        refresh(&mut candidate);
        assert!(candidate.validate().is_err());
    }

    let mut candidate = profile();
    candidate.identity.release_commit = "x".repeat(257);
    refresh(&mut candidate);
    assert!(candidate.validate().is_err());

    let mut candidate = profile();
    candidate.identity.release_commit = "not allowed".into();
    refresh(&mut candidate);
    assert!(candidate.validate().is_err());
}

#[test]
fn resource_validation_directly_rejects_every_closed_schema_boundary() {
    type UsageMutation = Box<dyn Fn(&mut ProofResourceUsage)>;
    let mutations: Vec<UsageMutation> = vec![
        Box::new(|usage| usage.raw_snos_steps = 0),
        Box::new(|usage| usage.adapted_rows = 0),
        Box::new(|usage| usage.memory_words = 0),
        Box::new(|usage| usage.max_domain_log_size = 0),
        Box::new(|usage| usage.peak_rss_bytes = 0),
        Box::new(|usage| usage.wall_time_ms = 0),
        Box::new(|usage| usage.builtin_instances.clear()),
        Box::new(|usage| usage.component_log_sizes.clear()),
        Box::new(|usage| {
            usage.component_log_sizes.remove("cpu");
        }),
        Box::new(|usage| {
            usage.component_log_sizes.insert("invalid name".into(), 1);
        }),
        Box::new(|usage| {
            usage.component_log_sizes.insert("poseidon".into(), 0);
        }),
        Box::new(|usage| {
            usage.component_log_sizes.insert("poseidon".into(), 6);
        }),
        Box::new(|usage| {
            usage.builtin_instances.insert("poseidon".into(), 0);
        }),
    ];
    for mutate in mutations {
        let mut candidate = profile();
        mutate(&mut candidate.capacity);
        refresh(&mut candidate);
        assert!(candidate.validate().is_err());
    }

    let measurement_mutations: Vec<UsageMutation> = vec![
        Box::new(|usage| usage.raw_snos_steps = 0),
        Box::new(|usage| usage.adapted_rows = 0),
        Box::new(|usage| usage.memory_words = 0),
        Box::new(|usage| usage.max_domain_log_size = 0),
        Box::new(|usage| usage.peak_rss_bytes = 0),
        Box::new(|usage| usage.wall_time_ms = 0),
        Box::new(|usage| usage.builtin_instances.clear()),
        Box::new(|usage| usage.component_log_sizes.clear()),
        Box::new(|usage| {
            usage.component_log_sizes.remove("cpu");
        }),
        Box::new(|usage| {
            usage.component_log_sizes.insert("invalid name".into(), 1);
        }),
        Box::new(|usage| {
            usage.component_log_sizes.insert("poseidon".into(), 0);
        }),
        Box::new(|usage| {
            usage.component_log_sizes.insert("poseidon".into(), 5);
        }),
    ];
    for mutate in measurement_mutations {
        let mut candidate = usage(100, false);
        mutate(&mut candidate);
        if let Ok(registry_id) = candidate.expected_component_registry_id() {
            candidate.component_registry_id = registry_id;
        }
        assert!(candidate.validate_measurement().is_err());
    }

    for replacement in ["0".repeat(64), "f".repeat(64)] {
        let mut candidate = usage(100, false);
        candidate.component_registry_id = replacement;
        assert!(candidate.validate_measurement().is_err());
    }

    let mut builtin_components = (0..256)
        .map(|index| (format!("component-{index}"), 1_u64))
        .collect::<BTreeMap<_, _>>();
    builtin_components.insert("cpu".into(), 1);
    let mut trace_components = (0..256)
        .map(|index| (format!("component-{index}"), 1_u32))
        .collect::<BTreeMap<_, _>>();
    trace_components.insert("cpu".into(), 1);
    let mut oversized = usage(100, false);
    oversized.builtin_instances = builtin_components;
    oversized.component_log_sizes = trace_components;
    oversized.component_registry_id = oversized.expected_component_registry_id().unwrap();
    assert!(oversized.validate_measurement().is_err());

    for mutate_capacity in [true, false] {
        let mut candidate = profile();
        let target = if mutate_capacity {
            &mut candidate.capacity
        } else {
            &mut candidate.vectors[0].usage
        };
        target.builtin_instances = (0..=256)
            .map(|index| (format!("component-{index}"), 1))
            .collect();
        refresh(&mut candidate);
        assert!(candidate.validate().is_err());
    }

    let mut candidate = profile();
    candidate.capacity.builtin_instances.clear();
    candidate.vectors[0].usage.builtin_instances.clear();
    refresh(&mut candidate);
    assert!(candidate.validate().is_err());

    let mut candidate = profile();
    let oversized = (0..=256)
        .map(|index| (format!("component-{index}"), 1))
        .collect::<BTreeMap<_, _>>();
    candidate.capacity.builtin_instances = oversized.clone();
    candidate.vectors[0].usage.builtin_instances = oversized;
    refresh(&mut candidate);
    assert!(candidate.validate().is_err());

    let mut candidate = profile();
    candidate.capacity.component_log_sizes.remove("cpu");
    candidate.vectors[0].usage.component_log_sizes.remove("cpu");
    candidate.capacity.builtin_instances.remove("cpu");
    candidate.vectors[0].usage.builtin_instances.remove("cpu");
    refresh(&mut candidate);
    assert!(candidate.validate().is_err());

    let mut candidate = profile();
    candidate.capacity.component_log_sizes =
        BTreeMap::from([("cpu".into(), 4), ("invalid name".into(), 4)]);
    candidate.vectors[0].usage.component_log_sizes = candidate.capacity.component_log_sizes.clone();
    candidate.capacity.builtin_instances =
        BTreeMap::from([("cpu".into(), 1_000), ("invalid name".into(), 1_000)]);
    candidate.vectors[0].usage.builtin_instances =
        BTreeMap::from([("cpu".into(), 1), ("invalid name".into(), 1)]);
    refresh(&mut candidate);
    assert!(candidate.validate().is_err());

    for replacement in ["0".repeat(64), "f".repeat(64)] {
        let mut candidate = profile();
        candidate.capacity.component_registry_id = replacement;
        candidate.profile_id = candidate.expected_profile_id().unwrap();
        assert!(candidate.validate().is_err());
    }
}

#[test]
fn resource_component_counts_accept_the_exact_limit_and_reject_one_more() {
    for builtins in [true, false] {
        let mut exact = usage(100, false);
        set_component_count(&mut exact, 256, builtins);
        assert!(exact.validate_measurement().is_ok());

        let mut excessive = usage(100, false);
        set_component_count(&mut excessive, 257, builtins);
        assert!(excessive.validate_measurement().is_err());
    }
}

#[test]
fn capacity_counters_and_padded_domains_fail_closed_at_their_real_boundaries() {
    let mut zero_capacity_counter = profile();
    zero_capacity_counter
        .capacity
        .builtin_instances
        .insert("poseidon".into(), 0);
    zero_capacity_counter.vectors[0]
        .usage
        .builtin_instances
        .insert("poseidon".into(), 0);
    refresh(&mut zero_capacity_counter);
    assert!(zero_capacity_counter.validate().is_err());

    let mut above_component_domain = profile();
    above_component_domain.capacity.max_domain_log_size = 7;
    above_component_domain
        .capacity
        .component_log_sizes
        .insert("poseidon".into(), 5);
    above_component_domain.vectors[0].usage.max_domain_log_size = 6;
    above_component_domain.vectors[0]
        .usage
        .component_log_sizes
        .insert("poseidon".into(), 6);
    refresh(&mut above_component_domain);
    assert!(above_component_domain.validate().is_err());

    let mut overflowing_margin = profile();
    overflowing_margin.safety_margin_bps = 10_001;
    refresh(&mut overflowing_margin);
    assert!(overflowing_margin.validate().is_err());
}

#[test]
fn profile_validation_is_not_masked_by_recomputing_its_content_hash() {
    let mut candidates = Vec::new();

    let mut candidate = profile();
    candidate.schema_version += 1;
    candidates.push(candidate);

    let mut candidate = profile();
    candidate.schema_version = 0;
    candidates.push(candidate);

    let mut candidate = profile();
    candidate.safety_margin_bps = 0;
    candidates.push(candidate);

    let mut candidate = profile();
    candidate.safety_margin_bps = 10_000;
    candidates.push(candidate);

    let mut candidate = profile();
    candidate.statement_kind = ProofStatementKind::Benchmark;
    candidates.push(candidate);

    let mut candidate = profile();
    candidate.vector_family.clear();
    candidates.push(candidate);

    let mut candidate = profile();
    candidate.vector_family = "invalid family".into();
    candidates.push(candidate);

    let mut candidate = profile();
    candidate.vector_family = "x".repeat(129);
    candidates.push(candidate);

    let mut candidate = profile();
    candidate.vectors.clear();
    candidates.push(candidate);

    let mut candidate = profile();
    candidate.vectors[0].evidence_sha256 = "A".repeat(64);
    candidates.push(candidate);

    let mut candidate = profile();
    candidate.vectors[0]
        .usage
        .component_log_sizes
        .insert("segment_arena".into(), 1);
    candidate.vectors[0]
        .usage
        .builtin_instances
        .insert("segment_arena".into(), 0);
    candidates.push(candidate);

    for candidate in &mut candidates {
        refresh(candidate);
        assert!(candidate.validate().is_err());
    }

    for replacement in ["0".repeat(64), "f".repeat(64)] {
        let mut candidate = profile();
        candidate.vectors[0].usage.component_registry_id = replacement;
        candidate.profile_id = candidate.expected_profile_id().unwrap();
        assert!(candidate.validate().is_err());
    }

    let mut invalid = profile();
    invalid.schema_version = 0;
    refresh(&mut invalid);
    let matching_identity = invalid.identity.clone();
    assert!(invalid.validate_identity(&matching_identity).is_err());
}

#[test]
fn capacity_boundaries_require_strict_log_headroom() {
    let baseline = profile();
    assert!(baseline.validate().is_ok());

    let mut maximum_identifiers = profile();
    maximum_identifiers.vector_family = "x".repeat(128);
    maximum_identifiers.vectors[0].vector_id = "y".repeat(128);
    refresh(&mut maximum_identifiers);
    assert!(maximum_identifiers.validate().is_ok());

    let mut exact_max_domain = profile();
    exact_max_domain.vectors[0].usage.max_domain_log_size = 5;
    exact_max_domain.vectors[0]
        .usage
        .component_log_sizes
        .insert("cpu".into(), 5);
    refresh(&mut exact_max_domain);
    assert!(exact_max_domain.validate().is_err());

    let mut exact_component = profile();
    exact_component.vectors[0]
        .usage
        .component_log_sizes
        .insert("poseidon".into(), 4);
    exact_component
        .capacity
        .component_log_sizes
        .insert("poseidon".into(), 4);
    refresh(&mut exact_component);
    assert!(exact_component.validate().is_err());

    let mut with_smaller_vector = profile();
    let mut smaller = with_smaller_vector.vectors[0].clone();
    smaller.vector_id = "strictly-smaller".into();
    smaller.evidence_sha256 = "b".repeat(64);
    smaller.shape = ProofShapeLimits::default();
    with_smaller_vector.vectors.push(smaller);
    refresh(&mut with_smaller_vector);
    assert!(with_smaller_vector.validate().is_ok());
}

#[test]
fn constant_time_equality_rejects_unequal_lengths_and_prefixes() {
    assert!(constant_time_eq("", ""));
    assert!(constant_time_eq("same", "same"));
    assert!(!constant_time_eq("", "x"));
    assert!(!constant_time_eq("x", ""));
    assert!(!constant_time_eq("prefix", "prefix-suffix"));
    assert!(!constant_time_eq("prefix-suffix", "prefix"));
    assert!(!constant_time_eq("same", "samf"));
}

#[test]
fn proof_job_validation_checks_every_required_and_optional_boundary() {
    let base = descriptor();
    assert!(base.validate().is_ok());

    let mut maximum = base.clone();
    maximum.transition_id = "x".repeat(256);
    maximum.input_state_root = Some("x".repeat(256));
    refresh_descriptor(&mut maximum);
    assert!(maximum.validate().is_ok());

    let required: [fn(&mut ProofJobDescriptor); 18] = [
        |job| job.transition_id.clear(),
        |job| job.protocol_version.clear(),
        |job| job.config_version.clear(),
        |job| job.prover_build_id.clear(),
        |job| job.chain_id.clear(),
        |job| job.exchange_address.clear(),
        |job| job.proof_program_address.clear(),
        |job| job.program_entrypoint.clear(),
        |job| job.proof_version.clear(),
        |job| job.program_variant.clear(),
        |job| job.virtual_program_hash.clear(),
        |job| job.starknet_os_output_version.clear(),
        |job| job.starknet_os_config_hash.clear(),
        |job| job.base_block_hash.clear(),
        |job| job.statement_commitment.clear(),
        |job| job.witness_hash.clear(),
        |job| job.request_hash.clear(),
        |job| job.transition_id = " ".into(),
    ];
    for mutate in required {
        let mut candidate = base.clone();
        mutate(&mut candidate);
        refresh_descriptor(&mut candidate);
        assert!(candidate.validate().is_err());
    }

    for mutate in [
        |job: &mut ProofJobDescriptor| job.input_state_root = Some(String::new()),
        |job: &mut ProofJobDescriptor| job.expected_output_state_root = Some(" ".into()),
        |job: &mut ProofJobDescriptor| job.expected_message = Some("x".repeat(257)),
    ] {
        let mut candidate = base.clone();
        mutate(&mut candidate);
        refresh_descriptor(&mut candidate);
        assert!(candidate.validate().is_err());
    }

    let mut candidate = base.clone();
    candidate.schema_version += 1;
    refresh_descriptor(&mut candidate);
    assert!(candidate.validate().is_err());

    let mut candidate = base.clone();
    candidate.schema_version = 0;
    refresh_descriptor(&mut candidate);
    assert!(candidate.validate().is_err());

    let mut candidate = base.clone();
    candidate.request_bytes = 0;
    refresh_descriptor(&mut candidate);
    assert!(candidate.validate().is_err());

    for mutate in [
        |job: &mut ProofJobDescriptor| job.witness_hash = "A".repeat(64),
        |job: &mut ProofJobDescriptor| job.request_hash = "g".repeat(64),
        |job: &mut ProofJobDescriptor| job.request_hash = "a".repeat(63),
    ] {
        let mut candidate = base.clone();
        mutate(&mut candidate);
        refresh_descriptor(&mut candidate);
        assert!(candidate.validate().is_err());
    }

    let mut candidate = base;
    candidate.job_id = "f".repeat(64);
    assert!(candidate.validate().is_err());
}

#[test]
fn proof_job_id_must_match_in_both_lexical_directions() {
    for replacement in ["0".repeat(64), "f".repeat(64)] {
        let mut candidate = descriptor();
        assert_ne!(candidate.job_id, replacement);
        candidate.job_id = replacement;
        assert!(candidate.validate().is_err());
    }
}

#[test]
fn worker_capabilities_require_exact_equality_for_every_pinned_field() {
    let descriptor = descriptor();
    let capabilities = zylith_proof_job::WorkerCapabilities {
        prover_build_id: descriptor.prover_build_id.clone(),
        proof_version: descriptor.proof_version.clone(),
        program_variant: descriptor.program_variant.clone(),
        virtual_program_hash: descriptor.virtual_program_hash.clone(),
        starknet_os_output_version: descriptor.starknet_os_output_version.clone(),
        starknet_os_config_hash: descriptor.starknet_os_config_hash.clone(),
    };
    assert!(capabilities.supports(&descriptor));

    let mutations: [fn(&mut ProofJobDescriptor, String); 6] = [
        |job, value| job.prover_build_id = value,
        |job, value| job.proof_version = value,
        |job, value| job.program_variant = value,
        |job, value| job.virtual_program_hash = value,
        |job, value| job.starknet_os_output_version = value,
        |job, value| job.starknet_os_config_hash = value,
    ];
    for mutate in mutations {
        for replacement in [String::new(), "\u{10ffff}".repeat(256)] {
            let mut mismatched = descriptor.clone();
            mutate(&mut mismatched, replacement);
            assert!(!capabilities.supports(&mismatched));
        }
    }
}

#[test]
fn hashes_reject_overlong_lowercase_hex() {
    assert!(!zylith_proof_job::is_hash(&"a".repeat(65)));
}

#[test]
fn proof_failure_validation_checks_all_closed_diagnostic_boundaries() {
    type FailureMutation = Box<dyn Fn(&mut ProofFailure)>;
    let valid = ProofFailure {
        class: ProofFailureClass::CapacityExceeded,
        code: "TRACE_DOMAIN_EXCEEDED".into(),
        component: Some("poseidon".into()),
        profile_id: Some("proof2-release-profile".into()),
        required: Some(21),
        available: Some(20),
    };
    assert!(valid.validate().is_ok());
    let mut maximum = valid.clone();
    maximum.code = "x".repeat(64);
    maximum.component = Some("x".repeat(64));
    maximum.profile_id = Some("x".repeat(128));
    assert!(maximum.validate().is_ok());

    let mutations: Vec<FailureMutation> = vec![
        Box::new(|failure| failure.code.clear()),
        Box::new(|failure| failure.code = "private message".into()),
        Box::new(|failure| failure.code = "x".repeat(65)),
        Box::new(|failure| failure.component = Some("invalid component".into())),
        Box::new(|failure| failure.component = Some("x".repeat(65))),
        Box::new(|failure| failure.profile_id = Some("invalid profile".into())),
        Box::new(|failure| failure.profile_id = Some("x".repeat(129))),
        Box::new(|failure| failure.required = None),
        Box::new(|failure| failure.available = None),
        Box::new(|failure| failure.required = Some(0)),
        Box::new(|failure| failure.available = Some(0)),
        Box::new(|failure| failure.required = Some(20)),
        Box::new(|failure| failure.required = Some(19)),
    ];
    for mutate in mutations {
        let mut candidate = valid.clone();
        mutate(&mut candidate);
        assert!(candidate.validate().is_err());
    }

    for class in [
        ProofFailureClass::CapacityExceeded,
        ProofFailureClass::UnsupportedBuiltin,
        ProofFailureClass::InvalidArtifact,
        ProofFailureClass::InvalidWitness,
        ProofFailureClass::PermanentProverRejection,
    ] {
        assert!(!class.is_retryable());
    }
    for class in [
        ProofFailureClass::TransientNetwork,
        ProofFailureClass::TransientProverUnavailable,
        ProofFailureClass::WorkerLost,
    ] {
        assert!(class.is_retryable());
    }
}

# base images are immutable; the release workflow may override them only by digest.
ARG RUST_IMAGE=rust:1.96.0-bookworm@sha256:5e2214abe154fe26e39f64488952e5c991eeed1d6d6da7cc8381ae83927f0cfc
FROM ${RUST_IMAGE} AS build
WORKDIR /src
COPY Cargo.toml Cargo.lock rust-toolchain.toml ./
COPY proof_job ./proof_job
COPY proof_worker ./proof_worker
ARG PROVER_BUILD_ID
ARG PROOF_VERSION
ARG VIRTUAL_PROGRAM_HASH
ARG STARKNET_OS_CONFIG_HASH
ARG PROVER_CPU_TARGET=x86-64-v3
RUN test -n "${PROVER_BUILD_ID}" \
    && test -n "${PROOF_VERSION}" \
    && test -n "${VIRTUAL_PROGRAM_HASH}" \
    && test -n "${STARKNET_OS_CONFIG_HASH}" \
    && test -n "${PROVER_CPU_TARGET}"
ENV ZYLITH_PROVER_BUILD_ID=${PROVER_BUILD_ID}
ENV ZYLITH_PROOF_VERSION=${PROOF_VERSION}
ENV ZYLITH_VIRTUAL_PROGRAM_HASH=${VIRTUAL_PROGRAM_HASH}
ENV ZYLITH_STARKNET_OS_CONFIG_HASH=${STARKNET_OS_CONFIG_HASH}
ENV RUSTFLAGS="-C target-cpu=${PROVER_CPU_TARGET}"
RUN cargo build --locked --release -p zylith-proof-worker

ARG RUNTIME_IMAGE=debian:bookworm-slim@sha256:3783cc01769c7b2b1b83a5c5ad96c815348e28ed7da68e2e3687004faa906251
FROM ${RUNTIME_IMAGE}
RUN useradd --system --uid 10001 --create-home zylith-proof-worker
COPY --from=build /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/ca-certificates.crt
COPY --from=build /src/target/release/zylith-proof-worker /usr/local/bin/zylith-proof-worker
USER 10001
ENTRYPOINT ["/usr/local/bin/zylith-proof-worker"]

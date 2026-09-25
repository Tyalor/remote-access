# Rendezvous / ID server image. Build: docker build -t ra-rendezvous .
FROM rust:1-bookworm AS build
WORKDIR /src
COPY Cargo.toml Cargo.lock ./
COPY crates ./crates
RUN cargo build --release --locked -p ra-rendezvous

FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates curl && rm -rf /var/lib/apt/lists/*
COPY --from=build /src/target/release/ra-rendezvous /usr/local/bin/ra-rendezvous
VOLUME /data
ENV RA_LISTEN=0.0.0.0:21114 RA_STATE_FILE=/data/hosts.json RUST_LOG=info
EXPOSE 21114
HEALTHCHECK CMD curl -fs http://127.0.0.1:21114/v1/health || exit 1
ENTRYPOINT ["ra-rendezvous"]

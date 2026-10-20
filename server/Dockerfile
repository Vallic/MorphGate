# Build from the repository root: docker build -f server/Dockerfile -t vault-sync-server .
FROM rust:1-bookworm AS build
WORKDIR /src
COPY . .
RUN cargo build --release -p vault-sync-server

FROM debian:bookworm-slim
RUN useradd --system --home /data vault-sync && mkdir -p /data && chown vault-sync /data
COPY --from=build /src/target/release/vault-sync-server /usr/local/bin/
USER vault-sync
ENV VAULT_SYNC_LISTEN=0.0.0.0:8443 VAULT_SYNC_DB=/data/vault-sync.sqlite3
EXPOSE 8443
VOLUME /data
ENTRYPOINT ["vault-sync-server"]

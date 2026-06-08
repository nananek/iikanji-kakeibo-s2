# syntax=docker/dockerfile:1
#
# 単一イメージ: iikanji-server が API と SPA(Trunk dist) を同一オリジンで配信する。
# ビルドは SPA(wasm) と server(native) を 1 つの builder で行い、slim runtime へ成果物を移す。
#
# 実行時の環境変数:
#   DATABASE_URL  (必須) postgres://...   起動時に migration を適用する
#   SERVER_SECRET (本番必須) ダミー salt / TOTP at-rest 鍵の素。未設定は dev 既定値 + warn
#   BIND_ADDR     (既定 0.0.0.0:8080)
#   STATIC_DIR    (既定 /app/dist) SPA 配信元

############################  builder  ############################
FROM rust:1.96-bookworm AS builder
WORKDIR /app

# フロントエンドツールチェーン (バージョン固定)。trunk 内蔵 DL は flaky なので prebuilt を
# PATH に置き、TRUNK_OFFLINE で使う。wasm-bindgen-cli は wasm-bindgen crate と版一致が必須。
ARG TRUNK_VERSION=0.21.14
ARG WASM_BINDGEN_VERSION=0.2.122
ARG BINARYEN_VERSION=version_123
# 各 release tarball の SHA256 を固定し supply-chain (CDN 改竄/MITM) を防ぐ。
# 版を上げる時はこの値も更新すること (公式 release 成果物の sha256)。
ARG TRUNK_SHA256=f2b4680cd239693a646a2795e4633c625328d7b2a044fbe749fa3a2fe9e7036b
ARG WASM_BINDGEN_SHA256=122a3fe2ea9c6e3e89b50e42dd1a346e499f3f65a54aae0b4eaeb658139d1e0e
ARG BINARYEN_SHA256=e959f2170af4c20c552e9de3a0253704d6a9d2766e8fdb88e4d6ac4bae9388fe
# github release-CDN は 504 で flaky なため、ファイルへ DL→SHA256 検証→展開 (pipe を避け set -e で捕捉)。
RUN set -eux; \
    rustup target add wasm32-unknown-unknown; \
    dl() { for i in $(seq 1 12); do curl -fsSL --retry 3 --retry-all-errors -o "$2" "$1" && return 0; echo "retry $i for $1" >&2; sleep 15; done; return 1; }; \
    dl "https://github.com/trunk-rs/trunk/releases/download/v${TRUNK_VERSION}/trunk-x86_64-unknown-linux-gnu.tar.gz" /tmp/trunk.tgz; \
    echo "${TRUNK_SHA256}  /tmp/trunk.tgz" | sha256sum -c -; \
    tar -xzf /tmp/trunk.tgz -C /usr/local/bin trunk; \
    dl "https://github.com/rustwasm/wasm-bindgen/releases/download/${WASM_BINDGEN_VERSION}/wasm-bindgen-${WASM_BINDGEN_VERSION}-x86_64-unknown-linux-musl.tar.gz" /tmp/wb.tgz; \
    echo "${WASM_BINDGEN_SHA256}  /tmp/wb.tgz" | sha256sum -c -; \
    tar -xzf /tmp/wb.tgz --strip-components=1 -C /usr/local/bin --wildcards '*/wasm-bindgen'; \
    dl "https://github.com/WebAssembly/binaryen/releases/download/${BINARYEN_VERSION}/binaryen-${BINARYEN_VERSION}-x86_64-linux.tar.gz" /tmp/bin.tgz; \
    echo "${BINARYEN_SHA256}  /tmp/bin.tgz" | sha256sum -c -; \
    tar -xzf /tmp/bin.tgz -C /opt; \
    rm -f /tmp/*.tgz
ENV PATH="/opt/binaryen-${BINARYEN_VERSION}/bin:${PATH}"

COPY . .

# SPA を dist/ へ (PATH の wasm-bindgen/wasm-opt を使い DL しない)。続けて server を release ビルド。
ENV TRUNK_OFFLINE=true
RUN trunk build --release
RUN cargo build --release -p iikanji-server

############################  runtime  ############################
FROM debian:bookworm-slim AS runtime
RUN apt-get update \
 && apt-get install -y --no-install-recommends ca-certificates \
 && rm -rf /var/lib/apt/lists/*
WORKDIR /app
COPY --from=builder /app/target/release/iikanji-server /usr/local/bin/iikanji-server
COPY --from=builder /app/dist /app/dist
ENV STATIC_DIR=/app/dist \
    BIND_ADDR=0.0.0.0:8080 \
    RUST_LOG=info
EXPOSE 8080
USER 1000:1000
CMD ["iikanji-server"]

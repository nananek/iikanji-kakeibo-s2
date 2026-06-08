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
# github release-CDN は 504 で flaky なため、ファイルへ DL してから展開 (pipe を避け set -e で捕捉)。
# 各 DL を長めにリトライして CDN の一時的な不調をやり過ごす。
RUN set -eux; \
    rustup target add wasm32-unknown-unknown; \
    dl() { for i in $(seq 1 12); do curl -fsSL --retry 3 --retry-all-errors -o "$2" "$1" && return 0; echo "retry $i for $1" >&2; sleep 15; done; return 1; }; \
    dl "https://github.com/trunk-rs/trunk/releases/download/v${TRUNK_VERSION}/trunk-x86_64-unknown-linux-gnu.tar.gz" /tmp/trunk.tgz; \
    tar -xzf /tmp/trunk.tgz -C /usr/local/bin trunk; \
    dl "https://github.com/rustwasm/wasm-bindgen/releases/download/${WASM_BINDGEN_VERSION}/wasm-bindgen-${WASM_BINDGEN_VERSION}-x86_64-unknown-linux-musl.tar.gz" /tmp/wb.tgz; \
    tar -xzf /tmp/wb.tgz --strip-components=1 -C /usr/local/bin; \
    dl "https://github.com/WebAssembly/binaryen/releases/download/${BINARYEN_VERSION}/binaryen-${BINARYEN_VERSION}-x86_64-linux.tar.gz" /tmp/bin.tgz; \
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

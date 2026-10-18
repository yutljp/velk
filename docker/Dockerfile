# 正本（canonical）のテスト環境。x86-64 の Linux で固定したバージョンを使う。
#
#   docker compose run --rm canonical      # compose.yml から
#   docker build -t velk-canonical docker  # 直接ビルドする場合
#
# ツールチェーンの版は ARG で固定する。変えたいときは compose.yml の
# build.args で上書きし、tests/out-canonical/toolchain.txt に記録された
# 実際の版をコミットメッセージに残す。
FROM ubuntu:24.04

ARG DEBIAN_FRONTEND=noninteractive
# 固定する版（compose.yml から上書きできる）
ARG CLANG_MAJOR=18
ARG RUST_VERSION=1.98.1
ARG GO_VERSION=1.23.4

# clang/lld/llvm は同一系列で揃える。llvm-strip と llvm-objcopy は
# llvm-<major> に入るので、その bin を PATH の先頭に置く。
RUN apt-get update \
 && apt-get install -y --no-install-recommends \
      clang-${CLANG_MAJOR} lld-${CLANG_MAJOR} llvm-${CLANG_MAJOR} \
      build-essential pkg-config ca-certificates curl xz-utils git python3 \
 && rm -rf /var/lib/apt/lists/*

ENV PATH=/usr/lib/llvm-${CLANG_MAJOR}/bin:/usr/local/bin:/usr/local/go/bin:/root/.cargo/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin

# `which` で見つかる名前に揃える（テストはこの名前で解決する）。
RUN for tool in clang clang++ ld.lld lld-link llvm-strip llvm-objcopy llvm-ar llvm-nm; do \
      target=/usr/lib/llvm-${CLANG_MAJOR}/bin/$tool; \
      [ -x "$target" ] && ln -sf "$target" "/usr/local/bin/$tool"; \
    done

# Rust は rustup で版を固定する（最小プロファイル）。
RUN curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs \
      | sh -s -- -y --no-modify-path --profile minimal --default-toolchain ${RUST_VERSION} \
 && rustc --version && cargo --version

# Go は公式 tarball で版を固定する。
RUN curl -fsSL "https://go.dev/dl/go${GO_VERSION}.linux-amd64.tar.gz" \
      | tar -C /usr/local -xz \
 && go version

WORKDIR /work

# 何も指定しなければ正本のスイートを回す。
CMD ["./tests/canonical.sh"]

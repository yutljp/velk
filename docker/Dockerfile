# Canonical test environment: pinned toolchain versions on x86-64 Linux.
#
#   docker compose run --rm canonical      # via compose.yml
#   docker build -t velk-canonical docker  # direct build
#
# Toolchain versions are pinned with ARGs. To change them, override build.args
# in compose.yml and put the actual versions recorded in
# tests/out-canonical/toolchain.txt in the commit message.
FROM ubuntu:24.04

COPY --from=ghcr.io/astral-sh/uv:0.10.12 /uv /usr/local/bin/uv

ARG DEBIAN_FRONTEND=noninteractive
# Pinned versions (overridable from compose.yml)
ARG CLANG_MAJOR=18
ARG RUST_VERSION=1.98.1
ARG GO_VERSION=1.23.4

# Keep clang/lld/llvm on the same major version. llvm-strip and llvm-objcopy
# ship in llvm-<major>, so its bin directory goes first on PATH.
RUN apt-get update \
 && apt-get install -y --no-install-recommends \
      clang-${CLANG_MAJOR} lld-${CLANG_MAJOR} llvm-${CLANG_MAJOR} \
      build-essential pkg-config ca-certificates curl xz-utils git python3 \
      mingw-w64 gcc-aarch64-linux-gnu libc6-dev-arm64-cross \
 && rm -rf /var/lib/apt/lists/*

ENV PATH=/usr/lib/llvm-${CLANG_MAJOR}/bin:/usr/local/bin:/usr/local/go/bin:/root/.cargo/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin

# Unversioned names so `which` finds them; the tests look tools up by these names.
RUN for tool in clang clang++ ld.lld lld-link llvm-strip llvm-objcopy llvm-ar llvm-nm; do \
      target=/usr/lib/llvm-${CLANG_MAJOR}/bin/$tool; \
      [ -x "$target" ] && ln -sf "$target" "/usr/local/bin/$tool"; \
    done

RUN curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs \
      | sh -s -- -y --no-modify-path --profile minimal --default-toolchain ${RUST_VERSION} \
 && rustc --version && cargo --version

RUN curl -fsSL "https://go.dev/dl/go${GO_VERSION}.linux-amd64.tar.gz" \
      | tar -C /usr/local -xz \
 && go version

WORKDIR /work

CMD ["./tests/canonical.sh"]

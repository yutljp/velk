# Canonical test environment: pinned toolchain versions on x86-64 Linux.
#
#   docker compose run --rm check          # via compose.yml
#   docker build -t velk-canonical docker  # direct build
#
# Toolchain versions are pinned with ARGs. To change them, override build.args
# in compose.yml and put the actual versions recorded in
# the output of the compiler version commands in the commit message.
ARG UBUNTU_VERSION=24.04
ARG UV_VERSION=0.10.12
FROM ghcr.io/astral-sh/uv:${UV_VERSION} AS uv
FROM ubuntu:${UBUNTU_VERSION}

COPY --from=uv /uv /usr/local/bin/uv

ARG DEBIAN_FRONTEND=noninteractive
# Pinned versions (overridable from compose.yml)
ARG CLANG_MAJOR=18
ARG RUST_VERSION=1.98.1
ARG GO_VERSION=1.23.4
ARG SIGNATURE_BUILD=0

# Keep clang/lld/llvm on the same major version. llvm-strip and llvm-objcopy
# ship in llvm-<major>, so its bin directory goes first on PATH.
# Release repositories retain the compiler package versions in the manifests.
RUN if [ "$SIGNATURE_BUILD" = 1 ]; then \
      rm /etc/apt/sources.list.d/ubuntu.sources \
      && printf 'deb http://archive.ubuntu.com/ubuntu resolute main universe\n' > /etc/apt/sources.list; \
    fi

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

RUN if [ "$SIGNATURE_BUILD" != 1 ]; then \
      curl -fsSL "https://go.dev/dl/go${GO_VERSION}.linux-amd64.tar.gz" \
        | tar -C /usr/local -xz \
      && go version; \
    fi

# The signature corpus records a separate compiler matrix in its manifests.
RUN if [ "$SIGNATURE_BUILD" = 1 ]; then \
      apt-get update \
      && apt-get install -y --no-install-recommends \
           gcc-arm-linux-gnueabihf libc6-dev-i386 lib32gcc-15-dev cmake perl python3-venv \
      && uv pip install --python /usr/bin/python3 --break-system-packages jinja2==3.1.6 \
      && rustup component add rust-src rust-docs \
      && rustup target add aarch64-unknown-linux-gnu i686-unknown-linux-gnu armv7-unknown-linux-gnueabihf \
      && rm -rf /var/lib/apt/lists/*; \
    fi

ARG UV_VERSION
RUN apt-get update \
 && apt-get install -y --no-install-recommends zlib1g-dev \
 && rm -rf /var/lib/apt/lists/* \
 && if [ "$SIGNATURE_BUILD" = 1 ]; then \
      curl -fsSL "https://github.com/astral-sh/uv/releases/download/${UV_VERSION}/uv-x86_64-unknown-linux-gnu.tar.gz" -o /tmp/uv.tar.gz \
      && printf 'f68d291c75783122dad58ab77def0e13f3233f358731db5d6d7e8715603b928f  /tmp/uv.tar.gz\n' | sha256sum -c - \
      && tar -xzf /tmp/uv.tar.gz --strip-components=1 -C /usr/local/bin uv-x86_64-unknown-linux-gnu/uv \
      && rm /tmp/uv.tar.gz; \
    fi

WORKDIR /work

CMD ["cargo", "test"]

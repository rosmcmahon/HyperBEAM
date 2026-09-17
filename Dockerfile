ARG ERLANG_VERSION=27

FROM --platform=linux/amd64 erlang:${ERLANG_VERSION} AS build

RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    ca-certificates \
    cmake \
    curl \
    git \
    libssl-dev \
    pkg-config \
    && rm -rf /var/lib/apt/lists/*

# Rust is needed for the `elmdb` NIF.
ENV RUSTUP_HOME=/usr/local/rustup \
    CARGO_HOME=/usr/local/cargo \
    PATH=/usr/local/cargo/bin:$PATH
RUN curl -sSf https://sh.rustup.rs \
    | sh -s -- -y --profile minimal --default-toolchain stable

WORKDIR /app
COPY . .

# `.git` is excluded from the context, so the commit is passed in for `buildinfo`.
ARG GIT_SHA=unknown
# The release overlay requires `config.flat`; runtime config comes from `HB_CONFIG`.
RUN touch config.flat \
    && BUILD_SOURCE="$GIT_SHA" \
    BUILD_SOURCE_SHORT="$(printf '%.7s' "$GIT_SHA")" \
    rebar3 release

FROM --platform=linux/amd64 debian:bookworm-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates \
    curl \
    libncurses6 \
    libssl3 \
    libstdc++6 \
    && rm -rf /var/lib/apt/lists/*

RUN useradd --system --create-home --home-dir /opt/hb --shell /usr/sbin/nologin hb

COPY --from=build --chown=hb:hb /app/_build/default/rel/hb /opt/hb

# Stores resolve relative to the release root, so link them into the data volume.
RUN mkdir -p /data/cache-mainnet /data/cache-priv \
    && ln -s /data/cache-mainnet /opt/hb/cache-mainnet \
    && ln -s /data/cache-priv /opt/hb/cache-priv \
    && chown -R hb:hb /data /opt/hb

ENV HB_KEY=/data/hyperbeam-key.json \
    HB_CONFIG=/data/config.flat \
    HB_PORT=8734

VOLUME /data
EXPOSE 8734
USER hb
WORKDIR /opt/hb

HEALTHCHECK --interval=30s --timeout=5s --start-period=60s --retries=3 \
    CMD curl -fsS "http://127.0.0.1:${HB_PORT}/~meta@1.0/info" > /dev/null || exit 1

ENTRYPOINT ["/opt/hb/bin/hb", "foreground"]

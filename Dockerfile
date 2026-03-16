# Multi-stage build per Verdaccio Docker docs.
# Stage 1: build plugin in a clean Node image.
# Stage 2: copy compiled output into the official Verdaccio image.
# Uses the standard Verdaccio entrypoint — no custom start script.
# @see https://verdaccio.org/docs/docker#adding-plugins-with-local-plugins-a-dockerfile
# @see https://github.com/verdaccio/verdaccio/blob/master/VERSIONS.md

# --- Stage 1: Build ---
FROM node:lts-alpine AS builder

WORKDIR /build

# Install deps first (layer cache)
COPY package.json package-lock.json ./
RUN npm ci

# Copy source and compile
COPY tsconfig.json ./
COPY src/ ./src/
COPY types/ ./types/

RUN npx tsc

# Prune to production deps only
RUN npm prune --omit=dev && \
    rm -rf src types tsconfig.json node_modules/.cache

# --- Stage 2: Runtime ---
FROM verdaccio/verdaccio:6

# Copy compiled plugin into the plugins directory
# Use $VERDACCIO_USER_UID:root per Verdaccio Docker docs
COPY --chown=$VERDACCIO_USER_UID:root --from=builder /build/lib /verdaccio/plugins/verdaccio-entra/lib
COPY --chown=$VERDACCIO_USER_UID:root --from=builder /build/node_modules /verdaccio/plugins/verdaccio-entra/node_modules
COPY --chown=$VERDACCIO_USER_UID:root --from=builder /build/package.json /verdaccio/plugins/verdaccio-entra/package.json

# Copy custom config
# Note: `listen` in config.yaml is ignored in Docker — use VERDACCIO_PORT env var
# @see https://verdaccio.org/docs/docker#docker-and-custom-port-configuration
COPY --chown=$VERDACCIO_USER_UID:root docker/config.yaml /verdaccio/conf/config.yaml

# Standard Verdaccio entrypoint handles: port, address, protocol, signals.
# All env vars (VERDACCIO_PORT, VERDACCIO_ADDRESS, VERDACCIO_PROTOCOL, etc.)
# are handled by the base image.
# @see https://verdaccio.org/docs/env#docker
EXPOSE 4873

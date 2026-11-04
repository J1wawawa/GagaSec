FROM docker.m.daocloud.io/library/rust:1-alpine AS build
WORKDIR /build
COPY Cargo.toml Cargo.lock ./
COPY src ./src
ADD vendor.tar.gz ./
COPY cargo-config.toml .cargo/config.toml
RUN cargo build --release --locked --offline
FROM node:22-alpine
WORKDIR /opt/gaga
COPY package.json package-lock.json ./
RUN npm ci --ignore-scripts --omit=dev --omit=optional && npm cache clean --force
COPY --from=build /build/target/release/gaga-static-worker /usr/local/bin/gaga-static-worker
COPY agent.mjs disassemble.mjs ./
LABEL team.j4.gaga.analysis="0.9.0"
USER 65534:65534
ENTRYPOINT ["gaga-static-worker"]

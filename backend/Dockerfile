# Backend API image: cached-dependency multi-stage build.
FROM rust:1.99-slim-bookworm AS build
WORKDIR /app
RUN apt-get update && apt-get install -y --no-install-recommends pkg-config libssl-dev ca-certificates \
    && rm -rf /var/lib/apt/lists
COPY Cargo.toml Cargo.lock ./
COPY src ./src
COPY migrations ./migrations
RUN cargo build --release --locked

FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates \
    && rm -rf /var/lib/apt/lists
COPY --from=build /app/target/release/nigrani /usr/local/bin/nigrani
EXPOSE 8080
CMD ["nigrani"]

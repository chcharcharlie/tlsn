# Use the official Rust image.
# https://hub.docker.com/_/rust
FROM rust:1.72.0

# Copy local code to the container image.
WORKDIR /usr/src/app
COPY . .

# Install production dependencies and build a release artifact.
# WORKDIR /usr/src/app/tlsn/examples
RUN cargo install --path .

EXPOSE 8080
EXPOSE 61288

# RUN chmod +x ./start-server.sh

# Run the web service on container startup.
CMD ["notary-server"]
# ENTRYPOINT ./start-server.sh
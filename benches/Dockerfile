# Use Rust base image
FROM rust:alpine3.22

# Install system dependencies
RUN apk add --no-cache \
    git \
    python3 \
    py3-pip \
    musl-dev \
    gcc \
    g++

# Create working directory
WORKDIR /app

# Copy Cargo configuration files
COPY Cargo.toml Cargo.lock ./
COPY crates/ ./crates/
COPY benches/ ./benches/
COPY examples/ ./examples/

# Run benchmarks
RUN cargo bench -p benches --bench analysis

COPY .git/ ./.git/

# Generate HTML index of results
RUN cargo run -p benches --bin bench_index

# Expose port 8080
EXPOSE 8080

# Default command: serve the results
CMD ["python3", "-m", "http.server", "8080", "--directory", "/app/target/criterion"]

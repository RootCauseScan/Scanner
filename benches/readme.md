# Benchmarks

These benchmarks use [Criterion](https://bheisler.github.io/criterion.rs/book/index.html) to
measure performance of various components.

## Run the analysis benchmark

```bash
cargo bench -p benches --bench analysis
```

Benchmark reports are written under `target/criterion/<bench_name>/`.

## Generate the HTML index

```bash
cargo run -p benches --bin bench_index
```

The index links to each benchmark's report. Open `target/criterion/index.html`
in a browser to navigate the results.

## Example

```bash
$ cargo bench -p benches --bench analysis
...
$ cargo run -p benches --bin bench_index
```

After running these commands, browse the generated reports in
`target/criterion/`.

## Docker Setup

To run benchmarks and serve the results:

```bash
# Build the image
docker build -f benches/Dockerfile -t rootcause-benchmarks .

# Run the container
docker run -p 8080:8080 rootcause-benchmarks
```

Results will be available at: http://localhost:8080/

To publish to your domain, simply copy the files from `target/criterion/` to your web server.


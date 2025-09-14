# Fuzzing

## Requirements
- `rustup install nightly`
- `cargo install cargo-fuzz`

## Run targets
Each target runs with:

```
cargo +nightly fuzz run <target> -- -max_total_time=60
```

Available targets:

- `yaml`: `cargo +nightly fuzz run yaml -- -max_total_time=60`
- `dockerfile`: `cargo +nightly fuzz run dockerfile -- -max_total_time=60`
- `python`: `cargo +nightly fuzz run python -- -max_total_time=60`

## Corpus
Seed files go in `fuzz/corpus/<target>/`.
Create the directory if it doesn't exist and add examples inside, for example `fuzz/corpus/yaml/`.

## Output and artifacts
Inputs that cause crashes or are minimized are saved in `fuzz/artifacts/<target>/`. Adjust the maximum time with `-- -max_total_time=60` to stop execution after 60 seconds.

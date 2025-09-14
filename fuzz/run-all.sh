#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")"

MAX="${MAX:-60}"

targets=$(grep -A1 '^\[\[bin\]\]' Cargo.toml | grep '^name' | cut -d'"' -f2)

for target in $targets; do
  echo "Running fuzz target: $target"
  cargo +nightly fuzz run "$target" -- -max_total_time="$MAX"
done


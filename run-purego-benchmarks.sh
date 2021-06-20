#!/bin/bash
set -euo pipefail

cd crypto
for i in $(seq 20); do
  go test -run=XXX -bench='BenchmarkVrfVerify.*|BenchmarkProveBytes.*' | tee bench-results
done

benchstat bench-results

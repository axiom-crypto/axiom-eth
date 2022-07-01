#!/bin/bash

if [ -z $PARAMS_DIR ]; then
    echo "PARAMS_DIR not set"
    exit 1
fi

repo_root=$(git rev-parse --show-toplevel)
cd $repo_root/axiom-query

set -e

rm -f data/test/*.pk
rm -f data/test/*.snark
export CARGO_PROFILE_DEV_DEBUG_ASSERTIONS=false
export RUST_LOG=debug
export RUST_BACKTRACE=1

cargo t test_mock_header_subquery
cargo t test_mock_results_root_header_only_for_agg -- --ignored
cargo t test_verify_compute_prepare_for_agg -- --ignored
cargo t test_merge_keccak_shards_for_agg -- --ignored

cargo t test_prover_subquery_agg -- --ignored --nocapture
cargo t test_verify_compute_prover_for_agg -- --ignored --nocapture
cargo t test_prover_axiom_agg1 -- --ignored --nocapture
cargo t test_prover_axiom_agg2 --features revm -- --ignored --nocapture

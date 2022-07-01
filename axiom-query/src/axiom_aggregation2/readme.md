To run all the tests leading up to the final `AxiomAggregation2` test, run the following in the `axiom-query` directory:

Remove any `data/test/*.snark` and `data/test/*.pk` files if you don't want caching.

```bash
cargo t test_prover_subquery_agg -- --ignored --nocapture
cargo t test_verify_compute_prover_for_agg -- --ignored --nocapture
cargo t test_prover_axiom_agg1 -- --ignored --nocapture
cargo t test_prover_axiom_agg2 --features revm -- --ignored --nocapture
```
If feature "keygen" is on, then you must run with `CARGO_PROFILE_DEV_DEBUG_ASSERTIONS=false` because we check keygen using dummy snarks  that do not pass debug assertions.

The final test will generate the EVM proof and try to run it against the snark verifier smart contract if you enable feature "revm". For the latter you need Solidity version 0.8.19 (the pragma is fixed to 0.8.19 in snark verifier).

Note the computeProof was generated using the trusted setup [here ](https://docs.axiom.xyz/transparency-and-security/kzg-trusted-setup) so for aggregation circuits to be consistent you will also need to download the same trusted setup and either put it in `axiom-query/params` or set `PARAMS_DIR` environmental variable.

## Regenerating test inputs
The tests above depend on certain pre-generated input files. To regenerate them and run all commands above, use the [integration_test.sh](./integration_test.sh) script.

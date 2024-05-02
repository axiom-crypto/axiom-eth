# AxiomV2Query ZK Circuits

# Proving and Verifying Key Generation

To generate the exact proving and verifying keys we use in production on Ethereum Mainnet and Base Mainnet, you can do the following:

1. Download the KZG trusted setup that we use with [this script](../trusted_setup_s3.sh).

```
bash ../trusted_setup_s3.sh
```

You can read more about the trusted setup we use and how it was generated [here](https://docs.axiom.xyz/docs/transparency-and-security/kzg-trusted-setup).

The trusted setup will be downloaded to a directory called `params/` by default. You can move the directory elsewhere. We'll refer to the directory as `$SRS_DIR` below.

2. Install `axiom-query-keygen` binary to your path via:

```bash
cargo install --path axiom-query --force
```

This builds the `axiom-query-keygen` binary in release mode and installs it to your path.
Additional details about the binary can be found [here](./src/bin/README.md).

3. Generate the proving and verifying keys for one of our production configurations.

We have multiple aggregation configurations that we use in production. These are specified by intent YAML files in the [`configs/production`](./configs/production/) directory.

The configurations that we have generated and use on all chains, ordered by the sum of generated proving key sizes, are:

- `all_small.yml`
- `all_32_each_default.yml`
- `all_128_each_default.yml`
- `all_large.yml`
- `all_max.yml`

The following configurations in [`configs/production/base_specific`](./configs/production/base_specific) are enabled and used **only** on Base Mainnet:

- `base_specific/all_32_each_rct_medium_st_depth_14.yml`
- `base_specific/all_128_each_default_st_depth_14.yml`
- `base_specific/all_large_st_depth_14.yml`
- `base_specific/all_max_st_depth_14.yml`

We will refer to one of these files as `$INTENT_NAME.yml` below. To generate all proving keys and verifying keys for the configuration corresponding to `$INTENT_NAME.yml`, run:

```bash

axiom-query-keygen --srs-dir $SRS_DIR --data-dir $CIRCUIT_DATA_DIR --intent configs/production/$INTENT_NAME.yml --tag $INTENT_NAME
```

where `$CIRCUIT_DATA_DIR` is the directory you want to store the output files. After the process is complete, a summary JSON containing the different circuit IDs created and the full aggregation tree of these circuit IDs will be output to `$CIRCUIT_DATA_DIR/$INTENT_NAME.tree`. At the top level of the JSON is an `"aggregate_vk_hash"` field, which commits to the aggregation configuration used in this particular `$INTENT_NAME`.

Check that the top level `"circuit_id"` in `$INTENT_NAME.tree` equals `e94efbee3e07ae4224ed1ae0a6389f5128d210ff7a2a743e459cff501e4379ab`, _regardless of which `$INTENT_NAME` you used_. This is the circuit ID of the final Axiom Aggregation 2 circuit, which is the same for all configurations because Axiom Aggregation 2 is a universal aggregation circuit. The `aggregate_vk_hash` commits to the aggregation configuration and is used to distinguish between them.

⚠️ **Special Note:** The `all_max.yml` and `all_max_st_depth_14` configurations are very large. The largest proving key generated is 200 GB. To run `axiom-query-keygen` on `all_max.yml`, you need a machine with at least 500 GB of RAM, or enough [swap](https://www.digitalocean.com/community/tutorials/how-to-add-swap-space-on-ubuntu-22-04) to make up the difference.

4. Rename and forge format the Solidity SNARK verifier file for the `AxiomV2QueryVerifier` smart contract:

Check that the top level `"circuit_id"` in `$INTENT_NAME.tree` equals `e94efbee3e07ae4224ed1ae0a6389f5128d210ff7a2a743e459cff501e4379ab`, _regardless of which `$INTENT_NAME` you used_. Then run

```bash
bash src/bin/rename_snark_verifier.sh $CIRCUIT_DATA_DIR/e94efbee3e07ae4224ed1ae0a6389f5128d210ff7a2a743e459cff501e4379ab.sol
```

The final Solidity file will be output to `AxiomV2QueryVerifier.sol`.

5. Compare the summary `*.tree` JSONs with the ones we use in production [here](./data/production/proof_trees/).

6. Check the top level aggregate vkey hashes in the `*.tree` JSONs match the ones we use in production:

**Ethereum Mainnet**

- The list we use in production on is provided [here](./data/production/aggregate_vk_hashes/eth_mainnet.json)
- These aggregate vkey hashes are part of the constructor arguments of our `AxiomV2Query` smart contract on Ethereum mainnet: see [logs](https://etherscan.io/tx/0xab7e570b6fbcc78841a0a5bde473e47737285aabf5fb9fb4876bd2b8043d9301#eventlog).

**Base Mainnet**

- The list we use in production on is provided [here](./data/production/aggregate_vk_hashes/base_mainnet.json)
- These aggregate vkey hashes are part of the constructor arguments of our `AxiomV2Query` smart contract on Base mainnet: see [logs](https://basescan.org/tx/0x8d71fee1e78bd62c43b5c79e16d04dae5e008e73ff0519a58c814dce88e7feda#eventlog).

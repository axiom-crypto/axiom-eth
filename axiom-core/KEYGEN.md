# AxiomV2Core ZK Circuits

# Proving and Verifying Key Generation

To generate the exact proving and verifying keys we use in production on Ethereum Mainnet, you can do the following:

1. Download the KZG trusted setup that we use with [this script](../trusted_setup_s3.sh).

```
bash ../trusted_setup_s3.sh
```

You can read more about the trusted setup we use and how it was generated [here](https://docs.axiom.xyz/docs/transparency-and-security/kzg-trusted-setup).

The trusted setup will be downloaded to a directory called `params/` by default. You can move the directory elsewhere. We'll refer to the directory as `$SRS_DIR` below.

2. Install `axiom-core-keygen` binary to your path via:

```bash
cargo install --path axiom-core --force
```

This builds the `axiom-core-keygen` binary in release mode and installs it to your path.
Additional details about the binary can be found [here](./src/bin/README.md).

3. Generate the proving and verifying keys for the `AxiomV2CoreVerifier` smart contract via:

```bash
axiom-core-keygen --srs-dir $SRS_DIR --intent configs/production/core.yml --tag v2.0.12 --data-dir $CIRCUIT_DATA_DIR
```

where `$CIRCUIT_DATA_DIR` is the directory you want to store the output files. After the process is complete, a summary JSON with the different circuit IDs created will be output to `$CIRCUIT_DATA_DIR/v2.0.12.cids`.

4. Rename and forge format the Solidity SNARK verifier file for `AxiomV2CoreVerifier`:

Check that in `$CIRCUIT_DATA_DIR/v2.0.12.cids` the final aggregation circuit with `"node_type": {"Evm":1}` has circuit ID `39cb264c605428fc752e90b6ac1b77427ab06b795419a759e237e283b95f377f`.
Then run

```bash
bash src/bin/rename_snark_verifier.sh $CIRCUIT_DATA_DIR/39cb264c605428fc752e90b6ac1b77427ab06b795419a759e237e283b95f377f.sol
```

The final Solidity file will be output to `AxiomV2CoreVerifier.sol`.

5. Generate the proving and verifying keys for the `AxiomV2CoreHistoricalVerifier` smart contract via:

```bash
axiom-core-keygen --srs-dir $SRS_DIR --intent configs/production/core_historical.yml --tag v2.0.12.historical --data-dir $CIRCUIT_DATA_DIR
```

where `$CIRCUIT_DATA_DIR` is the directory you want to store the output files. After the process is complete, a summary JSON with the different circuit IDs created will be output to `$CIRCUIT_DATA_DIR/v2.0.12.historical.cids`.

6. Rename and forge format the Solidity SNARK verifier file for `AxiomV2CoreHistoricalVerifier`:

Check that in `$CIRCUIT_DATA_DIR/v2.0.12.historical.cids` the final aggregation circuit with `"node_type": {"Evm":1}` has circuit ID `0379c723deafac09822de4f36da40a5595331c447a5cc7c342eb839cd199be02`.
Then run

```bash
bash src/bin/rename_snark_verifier.sh $CIRCUIT_DATA_DIR/0379c723deafac09822de4f36da40a5595331c447a5cc7c342eb839cd199be02.sol
```

The final Solidity file will be output to `AxiomV2CoreHistoricalVerifier.sol`.

7. Compare the summary JSONs `v2.0.12.cids` and `v2.0.12.historical.cids` with the ones we use in production [here](./data/production/).

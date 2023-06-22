# Binaries

## Setup

```bash
cd axiom-eth
# symlink existing params folder if you have one, otherwise a new one will automatically be created
mkdir data

# update Cargo
eval $(ssh-agent)
ssh-add
cargo update
```

Copy [`.env.example`](../../.env.example) to `.env` and add your INFURA ID. Then run

```bash
source .env
```

## Header chain

To create a single snark without aggregation for `2^7` block headers on mainnet:

```
cargo run --bin header_chain --release -- --start 0x765fb3 --end 0x766031 --max-depth 7
```

This will randomly generate trusted setup files (in `./params/*.srs`) and proving key, JSON-API call, snark (in `data/headers/`).

## Header chain with aggregation for EVM

To create a snark with TWO additional rounds of aggregation for `2^10` block headers on mainnet, to be submitted to EVM:

```
cargo run --bin header_chain --release -- --start 0 --end 1023 --max-depth 10 --initial-depth 7 --final evm --extra-rounds 1 --calldata --create-contract
```

The `--calldata` flag tells the binary to print out calldata instead of a binary snark.
The `--create-contract` flag generates the bytecode for the EVM verifier and submits the proof, printing the gas cost
if the transaction doesn't revert.

For full commandline usage, type

```
cargo run --bin header_chain --release -- --help
```

## Storage Proof

To prove a pre-specified number of storage slots for a given account at a given block number, fill in [`task.t.json`](../../data/storage/task.t.json) with the required information and run

```bash
cargo run --bin storage_proof --release -- --path data/storage/task.t.json --create-contract
```

Currently we only provide [configuration files](../../configs/storage/) for `10` storage slots.

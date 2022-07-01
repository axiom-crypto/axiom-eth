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

### Solc version

If order for the `--create-contract` flag to work, you must have solc installed. Furthermore, the contract creation from Yul code only works for versions `< 0.8.20`. We recommend using solc version `0.8.19`.

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

## Transaction and Receipts Proof

To prove up to `4` queries from arbitrary historical transaction data and up to `4` queries for arbitrary receipts data, fill in [`task.mainnet.json`](../../data/tx_receipts/task.mainnet.json) or [`task.goerli.json`](../../data/tx_receipts/task.goerli.json) with the required information and run one of:

These binaries require the environmental variable `JSON_RPC_URL` to be set the provider URL with the correct chain ID.

```bash
# mainnet
cargo run --bin tx_receipts --release -- --path data/tx_receipts/task.mainnet.json --create-contract
# goerli
cargo run --bin tx_receipts --release -- --network goerli --path data/tx_receipts/task.goerli.json --create-contract
```

See [solc version](#solc-version) if running into problems with contract creation. The SNARK verifier Yul code will be generated in `data/tx_receipts`, as will the calldata for your particular task.

## Only Receipts Proof

To prove up to `8` queries from arbitrary historical transaction receipts, fill in [`task.mainnet.json`](../../data/receipts/task.mainnet.json) or [`task.goerli.json`](../../data/receipts/task.goerli.json) with the required information and run one of:

These binaries require the environmental variable `JSON_RPC_URL` to be set the provider URL with the correct chain ID.

```bash
# mainnet
cargo run --bin only_receipts --release -- --path data/receipts/task.mainnet.json --create-contract
# goerli
cargo run --bin only_receipts --release -- --network goerli --path data/receipts/task.goerli.json --create-contract
```

See [solc version](#solc-version) if running into problems with contract creation. The SNARK verifier Yul code will be generated in `data/receipts`, as will the calldata for your particular task.

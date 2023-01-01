On a fresh machine:

```
cd axiom-eth
# symlink existing params folder if you have one, otherwise a new one will automatically be created
mkdir data

# update Cargo
eval $(ssh-agent)
ssh-add
cargo update
```

Place your Infura ID in a file named `axiom-eth/scripts/input_gen/INFURA_ID`

To create a single snark without aggregation for `2^7` block headers:
```
cargo run --bin header_chain --release -- --start 0x765fb3 --end 0x766031 --max-depth 7 
```

This will randomly generate trusted setup files (in `./params/*.srs`) and proving key, JSON-API call, snark (in `data/headers/`).

For full commandline usage, type
```
cargo run --bin header_chain --release -- --help
```

On a fresh machine:

```
cd halo2-mpt
mkdir params
mkdir data

# update Cargo
eval $(ssh-agent)
ssh-add
cargo update

cargo test --release -- bench_block_aggregation
```

This will generate the required SRS files (in `./params/*.srs`) and proving/verification keys (in `data/*.pkey`, `data/*.vkey`).

Currently we cache the proof after it's generated, so to do a fresh run on the same default blocks:

```
rm data/*.dat
cargo test --release -- bench_block_aggregation
```

Or alternatively to run on any arbitrary block chunk:

```
cargo run --bin bootstrap_history --release -- --last-block <LAST BLOCK>
```

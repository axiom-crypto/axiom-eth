# AxiomV1Query SNARK Verifier Circuits

# `AxiomV1Query` SNARK Verifier

This snark is created by calling

```bash
cargo test --release -- --nocapture test_scheduler_final_assembly_old
```

This will create several proving key files and a Yul file at `data/tests/batch_query/final_2.yul`.
It will also create a `final_*.calldata` file in the `data/tests/batch_query/` directory.

> **NOTE**: This command requires a machine with `400GB` of RAM to fully run. We recommend using a machine such as an AWS EC2 `r5.metal` or setting up [swap](https://www.digitalocean.com/community/tutorials/how-to-add-swap-space-on-ubuntu-22-04). The memory requirement is largely because this command keeps all intermediate proving keys in memory. On a machine with at least `100GB` combined RAM and swap, you can try re-running the above command after it is killed due to memory limits until the final proof calldata is created: the intermediate SNARKs are stored locally on disk, so re-running the command will not need to regenerate them from scratch.

Other tests that will generate different `final_*.calldata` proof calldata files, but create the same proving keys and Yul code, are:

```bash
cargo test --release -- --nocapture test_scheduler_final_assembly_recent
cargo test --release -- --nocapture test_scheduler_final_assembly_empty_slots
cargo test --release -- --nocapture test_scheduler_final_assembly_empty_accounts
cargo test --release -- --nocapture test_scheduler_final_assembly_resize
```

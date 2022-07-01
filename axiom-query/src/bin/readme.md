# Proving and Verifying Key Generation

To recursively run proving key generation on all circuits in an aggregation tree specified by an intent file, you can install the keygen binary to your path via:

```bash
cargo install --path axiom-query --force
```
This builds `axiom-query-keygen` binary in release mode and installs it to your path.
Then run:
```bash
axiom-query-keygen --srs-dir <directory with trusted setup files> --intent configs/templates/axiom_agg_2.yml --tag <optional tag> --data-dir <optional>
```
to actually generate the proving keys.

For faster compile times, you can run the keygen binary directly in dev mode (still with `opt-level=3`) via:
```bash
CARGO_PROFILE_DEV_DEBUG_ASSERTIONS=false cargo run --bin axiom-query-keygen -- --srs-dir <directory with trusted setup files> --intent configs/templates/axiom_agg_2.yml --tag <optional tag> --data-dir <optional>
```
Debug assertions needs to be **off** as we use dummy witnesses that do not pass certain debug assertions.

* A file with full aggregation tree of circuit IDs will be output to a `<tag>.tree` file as a JSON.
* `<tag>` defaults to `<root_circuit_id>` if not specified.

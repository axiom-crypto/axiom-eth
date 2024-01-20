# Proving and Verifying Key Generation

To recursively run proving key generation on all circuits in an aggregation tree specified by an intent file, you can install the keygen binary to your path via:

```bash
cargo install --path axiom-core --force
```
This builds `axiom-core-keygen` binary in release mode and installs it to your path.
Then run:
```bash
axiom-core-keygen --srs-dir <directory with trusted setup files> --intent configs/production/core.yml --tag <optional tag> --data-dir <optional>
```
to actually generate the proving keys.

For faster compile times, you can run the keygen binary directly in dev mode (still with `opt-level=3`) via:
```bash
CARGO_PROFILE_DEV_DEBUG_ASSERTIONS=false cargo run --bin axiom-core-keygen -- --srs-dir <directory with trusted setup files> --intent configs/production/core.yml --tag <optional tag> --data-dir <optional>
```
Debug assertions needs to be **off** as we use dummy witnesses that do not pass certain debug assertions.

* A file with the mapping of circuit types to circuit IDs will be output to a `<tag>.cids` file as a JSON.
* `<tag>` defaults to `<root_circuit_id>` if not specified.

To only get the raw list of circuit IDs from the `.cids` file, run:

```bash
jq -r '.[][1]' <tag>.cids > <tag>.txt
```
with `jq` installed.

Run the following to generate the data necessary for tests (too large to store in git):

```
cargo t test_beacon_state_and_validators_and_balances
cargo t get_all_validators_root
cargo t get_all_balances_root
```

You will need a [nodereal](nodereal.io) API key set to `NODEREAL_ID` env var.

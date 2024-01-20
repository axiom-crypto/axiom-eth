# Component Framework

We introduce a new circuit design concept of **Component Circuits** in this crate.

## Definition of Component Circuit

A component circuit is a circuit that is designed so that it can:

- Output a _virtual table_ of `(key, value)` pairs that can then be used by an external circuit
  - The output table is virtual because the circuit only outputs a commitment (some kind of hash) of the virtual table, and not the table itself
- Load the virtual output table from another component circuit and be able to look up the value for any given key in the table.
  - The loaded virtual table depends on the verification of the other component circuit that generated the table, so we call this loading and lookup process a **promise call**.
  - The circuit making the promise call is provided the virtual table as unconstrained private witnesses. It then commits to the table in exactly the same way as the circuit that generated the table, and exposes the commitment as a public instance. The aggregation circuit that verifies both the caller circuit and callee circuit must check that the **promise commitment** and **output commitment** are equal.
  - To actually use the loaded table in-circuit, the caller circuit must use a dynamic lookup table: the promise table is loaded into advice columns, and whenever one wants to use a `(key, value)` pair elsewhere in the circuit, a dynamic lookup must be done of `(key, value)` into the assigned advice table.

Concretely, any component circuit will have a corresponding struct `ComponentType{Name}` that implements the [`ComponentType`](./component/mod.rs) trait.

### Shards

The `ComponentType` only specifies the format of the virtual table output by the component circuit - it does not specify how the output commit of the virtual table should be computed. This is because we allow multiple concrete circuit implementations associated to a single component type.

Concretely, we implement a component circuit as either a **shard** circuit or an **aggregation** circuit. The shard circuit is what actually constrains the correctness of the virtual table. It then commits to the virtual table by performing a flat Poseidon hash of the entire concatenated table. Multiple shard circuits can be aggregated in an aggregation circuit, which will compute the merkle root of the output commitments of the shard circuits. We provide a generic aggregation circuit implementation that does this in [`merkle_aggregation`](./merkle_aggregation.rs).

In summary, in all of our concrete implementations of component circuits, the output commitment to the virtual table is always a Merkle root of flat hashes of subsections of the table.

### `component` module

The [component](./component/) module is designed to automate the above process as much as possible.

Above, we have not specified the types of `(key, value)`. We provide traits so that `key` can be a variable length array of field elements, and `value` is a fixed length array of field elements (fixed length known at compile time). If one were to directly assign such a virtual table of `(key, value)`s, one would need multiple columns for the length of each `key, value`. While the Halo2 backend will RLC these columns together in the prover backend before performing dynamic lookups, this is only worth it if your table size, or number of lookups performed, is comparable to the number of total rows in your circuit. For our use cases we have found that to rarely be the case, so instead we do not directly assign the virtual table to raw advice columns. We first RLC the `key, value` into a single value (using `RlcCircuitBuilder`) and then assign the RLCed value to a single raw advice column. Then when you need to look up a `(key, value)` pair, you must perform the same RLC on this pair and then dynamically look up the RLCed value into the previously assigned "table".

One creates a concrete Component Circuit implementation by creating a `ComponentCircuitImpl<F: Field, C: CoreBuilder<F>, P: PromiseBuilder<F>>` struct. One can think of this struct as a combination of three circuit builders (in the sense of the previous section):

1. `RlcCircuitBuilder`: we have enshrined this circuit builder in this crate as it is integral and used everywhere.
2. `CoreBuilder`: trait
3. `PromiseBuilder`: trait

### Promise Builder

The `PromiseBuilder` trait is an interface for any concrete implementation of the circuit builder that controls and automates the promise call process described above: the `PromiseBuilder` controls the process of actually loading the virtual table into this circuit, performing RLCs, and also adding dynamic lookups. It owns new circuit columns corresponding to both the lookup table and columns for values-to-lookup. Because `PromiseBuilder` needs to perform RLCs, the `virtual_assign_*` functions have access to `RlcCircuitBuilder`.

We have four concrete implementations of `PromiseBuilder` in this crate:

- `EmptyPromiseLoader`: does nothing, just so you have something to stick into `ComponentCircuitImpl`. This is for component circuits that do not need to make promise calls -- the component circuit only outputs a commitment.
- `PromiseLoader`: the most commonly used. Does exactly what is described above for the virtual promise table output by a _single_ component circuit.
- `MultiPromiseLoader`: if you load _multiple_ virtual tables from separate component circuits, with possibly different `(key, value)` types, but want to concatenate and assign all these tables into the same raw table (with some tag for the component type).
- `PromiseBuilderCombo`: boilerplate for combining two `PromiseBuilder`s and auto-implement `PromiseBuilder` again.

### Core Builder

The `CoreBuilder` is where you specify the main business logic of what your circuit should do.
In the main logic, you are also allowed to make promise calls to other component circuits: these requests are relayed to the `PromiseBuilder` via [`PromiseCaller`](./component/promise_collector.rs). We emphasize that `PromiseCaller` is **not** a circuit concept. The `PromiseCaller` is really just a struct that collects promise calls and relays them to the `PromiseBuilder` to actually adds the dynamic lookups. (This is necessary for example to _collect_ the requests that actually need to be sent as inputs to the called component circuit.)
The `PromiseCaller` is a shared thread-safe `PromiseCollector`.
The `PromiseCollector` implements another trait `PromiseCallsGetter`: this trait is exposed to `PromiseBuilder` as the way to get the promise calls to be looked up.

The `CoreBuilder::virtual_assign_*` gets access to `RlcCircuitBuilder` and `PromiseCaller`.
The `CoreBuilder` can own its own columns/gates, and it does have the ability to raw assign
to these columns, but a common use of `CoreBuilder` is to only specify the `virtual_assign_*`
logic using `RlcCircuitBuilder` and do no additional raw assignments of its own.

### Component Circuit Implementation

The synthesis of the above pieces is done in the actual [implementation](./component/circuit/mod.rs)
of the Halo2 `Circuit` trait for `ComponentCircuitImpl`. This will call `virtual_assign_*` for both
`CoreBuilder` and `PromiseBuilder`, and then it will call `raw_synthesize_*` for `CoreBuilder`, `PromiseBuilder`, **and** `RlcCircuitBuilder`.

In addition, `ComponentCircuitImpl` controls the assignment of public instances, because there are special instances (2, one output commitment, one promise commitment) reserved for Component Circuit usage. The `CoreBuilder` can specify additional public instances to be exposed in the return of `CoreBuilder::virtual_assign_phase0`.

## Notes

Many parts of the implementation of the Component Circuit framework (and circuit builders in general) could likely be streamlined with the use of runtime `dyn` and type inference. One main blocker to this is that many circuit related traits are not object-safe, so one cannot use `dyn` on them. In particular, the `Circuit` trait itself is not object safe because one needs to specify `Circuit::Config`. Moreover, there is no way to create `Circuit::Config` without access to a `ConstraintSystem` object.

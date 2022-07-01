# Axiom Components

To use `axiom-eth-working` with ssh,

```bash
mkdir .cargo
```
Add the following to `.cargo/config.toml`:
```toml
[net]
git-fetch-with-cli = true
```

## `BasicComponentScaffold`

The scaffold provides an streamlined to implement component circuits for the [component framework](https://github.com/axiom-crypto/axiom-eth-working/blob/develop/axiom-eth/src/utils/README.md). At the moment, the scaffold only supports `RlcCircuitBuilder` circuits that have fix-len inputs and do not make calls to other component circuits. 

To implement the `BasicComponentScaffold` trait (for some struct `ExampleComponent`), the following structs must first be specified:

* `ExampleComponentParams` -- to specify any config options of the component. This struct should include `pub capacity: usize,`, specifying the max number of calls that can be made, for the `ComponentParams` derive macro to work.
* `ExampleComponentInput`/`ExampleComponentOutput` -- the input/output structs of a *single* component call. See all the traits that must be derived for these structs [here](https://github.com/axiom-crypto/axiom-components/blob/2fe9dacdf9bd06d6f9949c7b3738f1c6a562fe9b/src/example/mod.rs#L29). We use the `ComponentIO` derive macro to auto-implement some of the component traits for IO values/witnesses. This macro requires that all fields within the struct implement the `InputFlatten` trait, which has been implemented for some primitive types in [./src/utils/flatten.rs](./src/utils/flatten.rs).

Once you specify these structs, using the `component!` macro on your component name (ie. `component!(Example)`) will create the following:

* `ExampleComponent` -- the struct on which the `BasicComponentScaffold` trait must be implemented on. **Note: without implementing the `BasicComponentScaffold` trait on this struct, the macro may give some errors**
* `ComponentTypeExample` -- a wrapper type around `BasicComponentScaffoldImpl<F, ExampleComponent<F>>` (which implements the `ComponentType<F>` trait) for identifying the component when making calls from other circuits.
* `ExampleComponentCall` -- a wrapper around `ExampleComponentInput` that implements `PromiseCallWitness`, for making calls to the `ExampleComponent` from other circuits.

The `component!` macro requires adhering to the naming convention specified above. The easiest way to start writing your own `BasicComponentScaffold` is by forking [./src/example/mod.rs](./src/example/mod.rs), replacing `Example` with your own component name, changing the input/output structs for your use case, and then adding your circuit logic to the `BasicComponentScaffold` trait impl.

The scaffold implements the `CoreBuilder` and `ComponentBuilder` traits on `BasicComponentScaffoldImpl<F, ExampleComponent<F>>`. To create the component circuit, simply construct `ComponentCircuitImpl<F, C: BasicComponentScaffoldImpl<F, ExampleComponent<F>>, P: EmptyPromiseLoader<F>>` using its [constructor](https://github.com/axiom-crypto/axiom-eth-working/blob/6c88fa354eabf5c26a87255f693127553893639f/axiom-eth/src/utils/component/circuit/comp_circuit_impl.rs#L57):

```
pub fn new(
    core_builder_params: C::Params,
    promise_builder_params: P::Params,
    prompt_rlc_params: RlcCircuitParams,
) -> Self
```

### Testing

To test the IO proc macro flattening, use `fix_len_logical_input_test`. To test that the output of your component is what you expect for some given input, use `basic_component_outputs_test`. To test that circuit keygen/proving work for your circuit, use `basic_component_test_prove`. All of these testing functions can be found in [./src/utils/testing.rs](./src/utils/testing.rs) and example usage is in [./src/example/test.rs](./src/example/test.rs).

## Notes

Each component lives in its own folder. 

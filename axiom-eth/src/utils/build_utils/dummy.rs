/// Generates a dummy of this type from a seed.
/// This is used to generate dummy inputs for the circuit.
pub trait DummyFrom<S> {
    /// Dummy from a seed.
    fn dummy_from(seed: S) -> Self;
}

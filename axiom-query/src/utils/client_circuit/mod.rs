pub mod default_circuit;
/// Client circuit metadata type and encoding/decoding
pub mod metadata;
pub mod vkey;

// Notes:

// - USER_MAX_OUTPUTS is the number of logical outputs from the user
// - each output is assumed to consist of USER_RESULT_BYTES bytes, this is the format they get it in solidity
// - in ZK circuit, each output is represented using USER_RESULT_FIELD_ELEMENTS field elements
// - this means the user outputs take up `USER_MAX_OUTPUTS * USER_RESULT_FIELD_ELEMENTS` public instance cells
// - currently there may be hardcoded assumptions that results are bytes32, represented as 2 field elements in HiLo form, but the idea is the use the generic constants as much as possible

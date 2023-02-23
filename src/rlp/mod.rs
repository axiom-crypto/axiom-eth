use crate::halo2_proofs::plonk::ConstraintSystem;
use halo2_base::{
    gates::{
        flex_gate::FlexGateConfig,
        range::{RangeConfig, RangeStrategy},
        GateChip, GateInstructions, RangeChip, RangeInstructions,
    },
    utils::{bit_length, ScalarField},
    AssignedValue, Context,
    QuantumCell::{Constant, Existing},
};
use std::iter;

pub mod builder;
pub mod rlc;
#[cfg(test)]
mod tests;

use rlc::{RlcChip, RlcConfig, RlcTrace};

use self::rlc::RlcContextPair;

pub fn max_rlp_len_len(max_len: usize) -> usize {
    if max_len > 55 {
        (bit_length(max_len as u64) + 7) / 8
    } else {
        0
    }
}

/// Returns array whose first `sub_len` cells are
///     `array[start_idx..start_idx + sub_len]`
/// and whose last cells are `0`.
///
/// These cells are witnessed but _NOT_ constrained
pub fn witness_subarray<F: ScalarField>(
    ctx: &mut Context<F>,
    array: &[AssignedValue<F>],
    start_id: &F,
    sub_len: &F,
    max_len: usize,
) -> Vec<AssignedValue<F>> {
    // `u32` should be enough for array indices
    let [start_id, sub_len] = [start_id, sub_len].map(|fe| fe.get_lower_32() as usize);
    debug_assert!(sub_len <= max_len);
    ctx.assign_witnesses(
        array[start_id..start_id + sub_len]
            .iter()
            .map(|a| *a.value())
            .chain(iter::repeat(F::zero()))
            .take(max_len),
    )
}

/// Evaluate a variable length byte array `array[..len]` to a big endian number
pub fn evaluate_byte_array<F: ScalarField>(
    ctx: &mut Context<F>,
    gate: &impl GateInstructions<F>,
    array: &[AssignedValue<F>],
    len: AssignedValue<F>,
) -> AssignedValue<F> {
    let f_256 = gate.get_field_element(256);
    if !array.is_empty() {
        let incremental_evals =
            gate.accumulated_product(ctx, iter::repeat(Constant(f_256)), array.iter().copied());
        let len_minus_one = gate.sub(ctx, len, Constant(F::one()));
        // if `len = 0` then `len_minus_one` will be very large, so `select_from_idx` will return 0.
        gate.select_from_idx(ctx, incremental_evals.iter().copied(), len_minus_one)
    } else {
        ctx.load_zero()
    }
}

#[derive(Clone, Debug)]
pub struct RlpFieldPrefixParsed<F: ScalarField> {
    is_not_literal: AssignedValue<F>,
    is_big: AssignedValue<F>,

    next_len: AssignedValue<F>,
    len_len: AssignedValue<F>,
}

#[derive(Clone, Debug)]
pub struct RlpArrayPrefixParsed<F: ScalarField> {
    // is_empty: AssignedValue<F>,
    is_big: AssignedValue<F>,

    next_len: AssignedValue<F>,
    len_len: AssignedValue<F>,
}

#[derive(Clone, Debug)]
pub struct RlpFieldWitness<F: ScalarField> {
    prefix: AssignedValue<F>, // value of the prefix
    prefix_len: AssignedValue<F>,
    len_len: AssignedValue<F>,
    len_cells: Vec<AssignedValue<F>>,
    max_len_len: usize,

    pub field_len: AssignedValue<F>,
    pub field_cells: Vec<AssignedValue<F>>,
    max_field_len: usize,
}

#[derive(Clone, Debug)]
/// All witnesses involved in the RLP decoding of a byte string (non-list).
pub struct RlpFieldTraceWitness<F: ScalarField> {
    /// This contains the assigned witnesses of the raw byte string after RLP decoding.
    pub witness: RlpFieldWitness<F>,
    /// This is the original raw RLP encoding byte string, padded with zeros to a known fixed maximum length
    pub rlp_field: Vec<AssignedValue<F>>,
    /// This is length of `rlp_field` in bytes, which can be variable.
    pub rlp_len: AssignedValue<F>,
    // We need to keep the raw `rlp_field, rlp_len` because we still need to compute their variable length RLC in SecondPhase
}

#[derive(Clone, Debug)]
/// The outputed values after RLP decoding a byte string (non-list) in SecondPhase.
/// This contains RLC of substrings from the decomposition.
pub struct RlpFieldTrace<F: ScalarField> {
    pub prefix: AssignedValue<F>, // value of the prefix
    pub prefix_len: AssignedValue<F>,
    pub len_trace: RlcTrace<F>,
    pub field_trace: RlcTrace<F>,
    // to save memory maybe we don't need this
    // pub rlp_trace: RlcTrace<F>,
}

#[derive(Clone, Debug)]
pub struct RlpArrayTraceWitness<F: ScalarField> {
    pub field_witness: Vec<RlpFieldWitness<F>>,

    pub len_len: AssignedValue<F>,
    pub len_cells: Vec<AssignedValue<F>>,

    pub rlp_len: AssignedValue<F>,
    pub rlp_array: Vec<AssignedValue<F>>,
}

#[derive(Clone, Debug)]
pub struct RlpArrayTrace<F: ScalarField> {
    pub len_trace: RlcTrace<F>,
    pub field_trace: Vec<RlpFieldTrace<F>>,
    // to save memory we don't need this
    // pub array_trace: RlcTrace<F>,
}

#[derive(Clone, Debug)]
pub struct RlcGateConfig<F: ScalarField> {
    pub rlc: RlcConfig<F>,
    pub gate: FlexGateConfig<F>,
}

#[derive(Clone, Debug)]
pub struct RlpConfig<F: ScalarField> {
    pub rlc: RlcConfig<F>,
    pub range: RangeConfig<F>,
}

impl<F: ScalarField> RlpConfig<F> {
    pub fn configure(
        meta: &mut ConstraintSystem<F>,
        num_rlc_columns: usize,
        num_advice: &[usize],
        num_lookup_advice: &[usize],
        num_fixed: usize,
        lookup_bits: usize,
        circuit_degree: usize,
    ) -> Self {
        let mut range = RangeConfig::configure(
            meta,
            RangeStrategy::Vertical,
            num_advice,
            num_lookup_advice,
            num_fixed,
            lookup_bits,
            circuit_degree,
        );
        let rlc = RlcConfig::configure(meta, num_rlc_columns);
        // blinding factors may have changed
        range.gate.max_rows = (1 << circuit_degree) - meta.minimum_rows();
        Self { rlc, range }
    }
}

#[derive(Debug)]
pub struct RlpChip<'range, F: ScalarField> {
    pub rlc: Option<&'range RlcChip<F>>, // We use this chip in FirstPhase when there is no RlcChip
    pub range: &'range RangeChip<F>,
}

impl<'range, F: ScalarField> RlpChip<'range, F> {
    pub fn new(range: &'range RangeChip<F>, rlc: Option<&'range RlcChip<F>>) -> Self {
        Self { rlc, range }
    }

    pub fn gate(&self) -> &GateChip<F> {
        self.range.gate()
    }

    pub fn range(&self) -> &RangeChip<F> {
        self.range
    }

    pub fn rlc(&self) -> &RlcChip<F> {
        self.rlc.as_ref().expect("RlcChip should be constructed and used only in SecondPhase")
    }

    /// Gets field element either from cache (for speed) or recalculates.
    pub fn field_element(&self, n: u64) -> F {
        self.gate().get_field_element(n)
    }

    /// Parse a byte by interpreting it as the first byte in the RLP encoding of a byte string.
    /// Constrains that the byte is valid for RLP encoding of byte strings (not a list).
    ///
    /// `ctx` can be in any phase but this is usually called in phase 0.
    ///
    /// https://ethereum.org/en/developers/docs/data-structures-and-encoding/rlp/
    /// * For a single byte whose value is in the [0x00, 0x7f] (decimal [0, 127]) range, that byte is its own RLP encoding.
    /// * Otherwise, if a string is 0-55 bytes long, the RLP encoding consists of a single byte with value 0x80 (dec. 128) plus the length of the string followed by the string. The range of the first byte is thus [0x80, 0xb7] (dec. [128, 183]).
    /// * If a string is more than 55 bytes long, the RLP encoding consists of a single byte with value 0xb7 (dec. 183) plus the length in bytes of the length of the string in binary form, followed by the length of the string, followed by the string.
    pub fn parse_rlp_field_prefix(
        &self,
        ctx: &mut Context<F>,
        prefix: AssignedValue<F>,
    ) -> RlpFieldPrefixParsed<F> {
        let is_not_literal =
            self.range.is_less_than(ctx, Constant(self.field_element(127)), prefix, 8);
        let is_len_or_literal =
            self.range.is_less_than(ctx, prefix, Constant(self.field_element(184)), 8);
        // is valid
        self.range.check_less_than(ctx, prefix, Constant(self.field_element(192)), 8);

        let field_len = self.gate().sub(ctx, prefix, Constant(self.field_element(128)));
        let len_len = self.gate().sub(ctx, prefix, Constant(self.field_element(183)));

        let is_big = self.gate().not(ctx, is_len_or_literal);

        // length of the next RLP field
        let next_len = self.gate().select(ctx, len_len, field_len, is_big);
        let next_len = self.gate().select(ctx, next_len, Constant(F::one()), is_not_literal);
        let len_len = self.gate().mul(ctx, len_len, is_big);
        let len_len = self.gate().mul(ctx, is_not_literal, len_len);
        RlpFieldPrefixParsed { is_not_literal, is_big, next_len, len_len }
    }

    /// Parse a byte by interpreting it as the first byte in the RLP encoding of a list.
    /// Constrains that the byte is valid for RLP encoding of lists (and is not a byte string).
    ///
    /// `ctx` can be in any phase but this is usually called in phase 0.
    ///
    /// https://ethereum.org/en/developers/docs/data-structures-and-encoding/rlp/
    /// * If the total payload of a list (i.e. the combined length of all its items being RLP encoded) is 0-55 bytes long, the RLP encoding consists of a single byte with value 0xc0 plus the length of the list followed by the concatenation of the RLP encodings of the items. The range of the first byte is thus [0xc0, 0xf7] (dec. [192, 247]).
    /// * If the total payload of a list is more than 55 bytes long, the RLP encoding consists of a single byte with value 0xf7 plus the length in bytes of the length of the payload in binary form, followed by the length of the payload, followed by the concatenation of the RLP encodings of the items. The range of the first byte is thus [0xf8, 0xff] (dec. [248, 255]).
    pub fn parse_rlp_array_prefix(
        &self,
        ctx: &mut Context<F>,
        prefix: AssignedValue<F>,
    ) -> RlpArrayPrefixParsed<F> {
        // is valid
        self.range.check_less_than(ctx, Constant(self.field_element(191)), prefix, 8);

        let is_big = self.range.is_less_than(ctx, Constant(self.field_element(247)), prefix, 8);

        let array_len = self.gate().sub(ctx, prefix, Constant(self.field_element(192)));
        let len_len = self.gate().sub(ctx, prefix, Constant(self.field_element(247)));
        let next_len = self.gate().select(ctx, len_len, array_len, is_big);
        let len_len = self.gate().mul(ctx, len_len, is_big);

        RlpArrayPrefixParsed { is_big, next_len, len_len }
    }

    /// Given a full RLP encoding `rlp_cells` string, and the length in bytes of the length of the payload, `len_len`, parse the length of the payload.
    ///
    /// Assumes that it is known that `len_len <= max_len_len`.
    ///
    /// Returns the *witness* for the length of the payload in bytes, together with the BigInt value of this length, which is constrained assuming that the witness is valid. (The witness for the length as byte string is checked later in an RLC concatenation.)
    fn parse_rlp_len(
        &self,
        ctx: &mut Context<F>,
        rlp_cells: &[AssignedValue<F>],
        len_len: AssignedValue<F>,
        max_len_len: usize,
    ) -> (Vec<AssignedValue<F>>, AssignedValue<F>) {
        let len_cells = witness_subarray(
            ctx,
            rlp_cells,
            &F::one(), // the 0th index is the prefix byte, and is skipped
            len_len.value(),
            max_len_len,
        );
        let len_val = evaluate_byte_array(ctx, self.gate(), &len_cells, len_len);
        (len_cells, len_val)
    }

    /// Given a byte string `rlp_field`, this function together with [`Self::decompose_rlp_field_phase1`]
    /// constrains that the byte string is the RLP encoding of a byte string (and not a list).
    ///
    /// In the present function, the witnesses for the RLP decoding are computed and assigned. This decomposition is NOT yet constrained.
    ///
    /// Witnesses MUST be generated in `FirstPhase` to be able to compute RLC of them in `SecondPhase`
    pub fn decompose_rlp_field_phase0(
        &self,
        ctx: &mut Context<F>, // context for GateChip
        rlp_field: Vec<AssignedValue<F>>,
        max_field_len: usize,
    ) -> RlpFieldTraceWitness<F> {
        let max_len_len = max_rlp_len_len(max_field_len);
        debug_assert_eq!(rlp_field.len(), 1 + max_len_len + max_field_len);

        // Witness consists of
        // * prefix_parsed
        // * len_rlc
        // * field_rlc
        // * rlp_field_rlc
        //
        // check that:
        // * len_rlc.rlc_len in [0, max_len_len]
        // * field_rlc.rlc_len in [0, max_field_len]
        // * rlp_field_rlc.rlc_len in [0, max_rlp_field_len]
        //
        // * rlp_field_rlc.rlc_len = 1 + len_rlc.rlc_len + field_rlc.rlc_len
        // * len_rlc.rlc_len = prefix_parsed.is_big * prefix_parsed.next_len
        // * field_rlc.rlc_len = prefix_parsed.is_big * prefix_parsed.next_len
        //                       + (1 - prefix_parsed.is_big) * byte_value(len)
        //
        // * rlp_field_rlc = accumulate(
        //                       [(prefix, 1),
        //                        (len_rlc.rlc_val, len_rlc.rlc_len),
        //                        (field_rlc.rlc_val, field_rlc.rlc_len)])

        let prefix_parsed = self.parse_rlp_field_prefix(ctx, rlp_field[0]);
        let prefix = self.gate().mul(ctx, rlp_field[0], prefix_parsed.is_not_literal);

        let len_len = prefix_parsed.len_len;
        self.range.check_less_than_safe(ctx, len_len, (max_len_len + 1) as u64);
        let (len_cells, len_byte_val) = self.parse_rlp_len(ctx, &rlp_field, len_len, max_len_len);

        let field_len =
            self.gate().select(ctx, len_byte_val, prefix_parsed.next_len, prefix_parsed.is_big);
        self.range.check_less_than_safe(ctx, field_len, (max_field_len + 1) as u64);

        let field_cells = witness_subarray(
            ctx,
            &rlp_field,
            &(*prefix_parsed.is_not_literal.value() + len_len.value()),
            field_len.value(),
            max_field_len,
        );

        let rlp_len = self.gate().sum(ctx, [prefix_parsed.is_not_literal, len_len, field_len]);

        RlpFieldTraceWitness {
            witness: RlpFieldWitness {
                prefix,
                prefix_len: prefix_parsed.is_not_literal,
                len_len,
                len_cells,
                max_len_len,
                field_len,
                field_cells,
                max_field_len,
            },
            rlp_len,
            rlp_field,
        }
    }

    /// Use RLC to constrain the parsed RLP field witness. This MUST be done in `SecondPhase`.
    pub fn decompose_rlp_field_phase1(
        &self,
        (ctx_gate, ctx_rlc): RlcContextPair<F>,
        rlp_field_witness: RlpFieldTraceWitness<F>,
    ) -> RlpFieldTrace<F> {
        let RlpFieldTraceWitness { witness, rlp_len, rlp_field } = rlp_field_witness;
        let RlpFieldWitness {
            prefix,
            prefix_len,
            len_len,
            len_cells,
            max_len_len,
            field_len,
            field_cells,
            max_field_len,
        } = witness;
        let rlc = self.rlc();
        let len_rlc = rlc.compute_rlc((ctx_gate, ctx_rlc), self.gate(), len_cells, len_len);
        let field_rlc = rlc.compute_rlc((ctx_gate, ctx_rlc), self.gate(), field_cells, field_len);
        let rlp_field_rlc = rlc.compute_rlc((ctx_gate, ctx_rlc), self.gate(), rlp_field, rlp_len);

        rlc.constrain_rlc_concat(
            (ctx_gate, ctx_rlc),
            self.gate(),
            [
                (prefix, prefix_len, 1),
                (len_rlc.rlc_val, len_rlc.len, max_len_len),
                (field_rlc.rlc_val, field_rlc.len, max_field_len),
            ],
            (&rlp_field_rlc.rlc_val, &rlp_field_rlc.len),
        );

        RlpFieldTrace { prefix, prefix_len, len_trace: len_rlc, field_trace: field_rlc }
    }

    /// Compute and assign witnesses for deserializing an RLP list of byte strings. Does not support nested lists.
    ///
    /// In the present function, the witnesses for the RLP decoding are computed and assigned. This decomposition is NOT yet constrained.
    /// Witnesses MUST be generated in `FirstPhase` to be able to compute RLC of them in `SecondPhase`
    ///
    /// * If `is_variable_len = false`, then the circuit will constrain that the list has number of items exactly equal to `max_field_lens.len()`.
    /// * Otherwise if `is_variable_len = true`, then `max_field_lens.len()` is assumed to be the maximum number of items of any list represented by this RLP encoding.
    /// * `max_field_lens` is the maximum length of each field in the list.
    ///
    /// In order for the circuit to pass, the excess witness values in `rlp_array` beyond the actual RLP sequence should all be `0`s.
    pub fn decompose_rlp_array_phase0(
        &self,
        ctx: &mut Context<F>, // context for GateChip
        rlp_array: Vec<AssignedValue<F>>,
        max_field_lens: &[usize],
        is_variable_len: bool,
    ) -> RlpArrayTraceWitness<F> {
        let max_rlp_array_len = rlp_array.len();
        let max_len_len = max_rlp_len_len(max_rlp_array_len);

        // Witness consists of
        // * prefix_parsed
        // * len_rlc
        // * field_rlcs: Vec<RlpFieldTrace>
        // * rlp_array_rlc
        //
        // check that:
        // * len_rlc.len in [0, max_len_len]
        // * field_rlcs[idx].len in [0, max_field_len[idx]]
        // * rlp_field_rlc.len in [0, max_rlp_field_len]
        //
        // * rlp_field_rlc.len = 1 + len_rlc.rlc_len + field_rlc.rlc_len
        // * len_rlc.len = prefix_parsed.is_big * prefix_parsed.next_len
        // * field_rlc.len = prefix_parsed.is_big * prefix_parsed.next_len
        //                       + (1 - prefix_parsed.is_big) * byte_value(len)
        //
        // * rlp_field_rlc = accumulate(
        //                       [(prefix, 1),
        //                        (len_rlc.rlc_val, len_rlc.rlc_len),
        //                        (field_rlc.rlc_val, field_rlc.rlc_len)])

        let prefix = rlp_array[0];
        let prefix_parsed = self.parse_rlp_array_prefix(ctx, prefix);

        let len_len = prefix_parsed.len_len;
        self.range.check_less_than_safe(ctx, len_len, (max_len_len + 1) as u64);

        let (len_cells, len_byte_val) = self.parse_rlp_len(ctx, &rlp_array, len_len, max_len_len);

        let list_payload_len =
            self.gate().select(ctx, len_byte_val, prefix_parsed.next_len, prefix_parsed.is_big);
        self.range.check_less_than_safe(
            ctx,
            list_payload_len,
            (max_rlp_array_len - max_len_len) as u64,
        );

        // this is automatically <= max_rlp_array_len
        let rlp_len = self
            .gate()
            .sum(ctx, [Constant(F::one()), Existing(len_len), Existing(list_payload_len)]);

        let mut field_witness = Vec::with_capacity(max_field_lens.len());

        let mut prefix_idx = self.gate().add(ctx, Constant(F::one()), Existing(len_len));
        let mut running_max_len = max_len_len + 1;

        for &max_field_len in max_field_lens {
            let mut prefix = self.gate().select_from_idx(
                ctx,
                // selecting from the whole array is wasteful: we only select from the max range currently possible
                rlp_array.iter().copied().take(running_max_len + 1),
                prefix_idx,
            );
            let prefix_parsed = self.parse_rlp_field_prefix(ctx, prefix);

            let mut len_len = prefix_parsed.len_len;
            let max_field_len_len = max_rlp_len_len(max_field_len);
            self.range.check_less_than_safe(ctx, len_len, (max_field_len_len + 1) as u64);

            let len_start_id = *prefix_parsed.is_not_literal.value() + prefix_idx.value();
            let len_cells = witness_subarray(
                ctx,
                &rlp_array,
                &len_start_id,
                len_len.value(),
                max_field_len_len,
            );

            let field_byte_val = evaluate_byte_array(ctx, self.gate(), &len_cells, len_len);
            let mut field_len = self.gate().select(
                ctx,
                field_byte_val,
                prefix_parsed.next_len,
                prefix_parsed.is_big,
            );
            self.range.check_less_than_safe(ctx, field_len, (max_field_len + 1) as u64);

            let field_cells = witness_subarray(
                ctx,
                &rlp_array,
                &(len_start_id + len_len.value()),
                field_len.value(),
                max_field_len,
            );
            running_max_len += 1 + max_field_len_len + max_field_len;

            // prefix_len is either 0 or 1
            let mut prefix_len = prefix_parsed.is_not_literal;
            if is_variable_len {
                // If `prefix_idx >= rlp_len`, that means we are done
                let field_in_list = self.range.is_less_than(
                    ctx,
                    prefix_idx,
                    rlp_len,
                    bit_length(max_rlp_array_len as u64),
                );
                // In cases where the RLP sequence is a list of unknown variable length, we keep track
                // of whether the corresponding index actually is a list item by constraining that
                // all of `prefix_len, len_len, field_len` are 0 when the current field should be treated
                // as a dummy and not actually in the list
                prefix_len = self.gate().mul(ctx, prefix_len, field_in_list);
                len_len = self.gate().mul(ctx, len_len, field_in_list);
                field_len = self.gate().mul(ctx, field_len, field_in_list);
            }
            prefix = self.gate().mul(ctx, prefix, prefix_len);
            prefix_idx = self.gate().sum(ctx, [prefix_idx, prefix_len, len_len, field_len]);

            let witness = RlpFieldWitness {
                prefix,
                prefix_len,
                len_len,
                len_cells,
                max_len_len: max_field_len_len,
                field_len,
                field_cells,
                max_field_len,
            };
            field_witness.push(witness);
        }
        RlpArrayTraceWitness { field_witness, len_len, len_cells, rlp_len, rlp_array }
    }

    /// Use RLC to constrain the parsed RLP array witness. This MUST be done in `SecondPhase`.
    ///
    /// We do not make any guarantees on the values in the original RLP sequence beyond the parsed length for the total payload
    pub fn decompose_rlp_array_phase1(
        &self,
        (ctx_gate, ctx_rlc): RlcContextPair<F>,
        rlp_array_witness: RlpArrayTraceWitness<F>,
        _is_variable_len: bool,
    ) -> RlpArrayTrace<F> {
        let RlpArrayTraceWitness { field_witness, len_len, len_cells, rlp_len, rlp_array } =
            rlp_array_witness;
        let rlc = self.rlc();
        let len_trace = rlc.compute_rlc((ctx_gate, ctx_rlc), self.gate(), len_cells, len_len);

        let mut field_trace = Vec::with_capacity(field_witness.len());
        for field_witness in field_witness {
            let len_rlc = rlc.compute_rlc(
                (ctx_gate, ctx_rlc),
                self.gate(),
                field_witness.len_cells,
                field_witness.len_len,
            );
            let field_rlc = rlc.compute_rlc(
                (ctx_gate, ctx_rlc),
                self.gate(),
                field_witness.field_cells,
                field_witness.field_len,
            );
            field_trace.push(RlpFieldTrace {
                prefix: field_witness.prefix,
                prefix_len: field_witness.prefix_len,
                len_trace: len_rlc,
                field_trace: field_rlc,
            });
        }

        let prefix = rlp_array[0];
        let one = ctx_gate.load_constant(F::one());
        let rlp_rlc = rlc.compute_rlc((ctx_gate, ctx_rlc), self.gate(), rlp_array, rlp_len);

        let inputs = iter::empty()
            .chain([(prefix, one, 1), (len_trace.rlc_val, len_trace.len, len_trace.max_len)])
            .chain(field_trace.iter().flat_map(|trace| {
                [
                    (trace.prefix, trace.prefix_len, 1),
                    (trace.len_trace.rlc_val, trace.len_trace.len, trace.len_trace.max_len),
                    (trace.field_trace.rlc_val, trace.field_trace.len, trace.field_trace.max_len),
                ]
            }));

        rlc.constrain_rlc_concat(
            (ctx_gate, ctx_rlc),
            self.gate(),
            inputs,
            (&rlp_rlc.rlc_val, &rlp_rlc.len),
        );

        // We do not constrain the witness values of trailing elements in `rlp_array` beyond `rlp_len`. To do so, uncomment below:
        /*
        let unused_array_len =
            self.gate().sub(ctx, Constant(F::from(rlp_array.len() as u64)), Existing(&rlp_rlc.len));
        let suffix_pow = self.rlc.rlc_pow(
            ctx,
            self.gate(),
            &unused_array_len,
            bit_length(rlp_rlc.values.len() as u64),
        );
        let suffix_check = self.gate().mul(ctx,
                Existing(&suffix_pow),
                Existing(&rlp_rlc.rlc_val));
        ctx.region.constrain_equal(suffix_check.cell(), rlp_rlc.rlc_max.cell());
        */

        RlpArrayTrace { len_trace, field_trace }
    }
}

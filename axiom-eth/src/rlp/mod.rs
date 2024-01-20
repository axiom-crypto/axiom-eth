use std::iter;

use crate::{
    rlc::{chip::RlcChip, circuit::builder::RlcContextPair, types::RlcTrace},
    utils::circuit_utils::constrain_no_leading_zeros,
};

use halo2_base::{
    gates::{GateChip, GateInstructions, RangeChip, RangeInstructions},
    utils::{bit_length, ScalarField},
    AssignedValue, Context,
    QuantumCell::{Constant, Existing},
};

use self::types::{
    RlpArrayPrefixParsed, RlpArrayTrace, RlpArrayWitness, RlpFieldPrefixParsed, RlpFieldTrace,
    RlpFieldWitness, RlpPrefixParsed,
};

#[cfg(test)]
mod tests;
pub mod types;

pub const fn max_rlp_len_len(max_len: usize) -> usize {
    if max_len > 55 {
        (bit_length(max_len as u64) + 7) / 8
    } else {
        0
    }
}

pub const fn max_rlp_encoding_len(payload_len: usize) -> usize {
    1 + max_rlp_len_len(payload_len) + payload_len
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
    let [start_id, sub_len] = [start_id, sub_len].map(|fe| fe.get_lower_64() as usize);
    debug_assert!(sub_len <= max_len, "{sub_len} > {max_len}");
    ctx.assign_witnesses(
        array[start_id..start_id + sub_len]
            .iter()
            .map(|a| *a.value())
            .chain(iter::repeat(F::ZERO))
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
    if !array.is_empty() {
        let incremental_evals = gate.accumulated_product(
            ctx,
            iter::repeat(Constant(F::from(256))),
            array.iter().copied(),
        );
        let len_minus_one = gate.sub(ctx, len, Constant(F::ONE));
        // if `len = 0` then `len_minus_one` will be very large, so `select_from_idx` will return 0.
        gate.select_from_idx(ctx, incremental_evals.iter().copied(), len_minus_one)
    } else {
        ctx.load_zero()
    }
}

/// Chip for proving RLP decoding. This only contains references to other chips, so it can be freely copied.
/// This will only contain [RlcChip] after [SecondPhase].
#[derive(Clone, Copy, Debug)]
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

    /// Parse a byte by interpreting it as the first byte in the RLP encoding of a byte string.
    /// Constrains that the byte is valid for RLP encoding of byte strings (not a list).
    ///
    /// `ctx` can be in any phase but this is usually called in phase 0.
    ///
    /// https://ethereum.org/en/developers/docs/data-structures-and-encoding/rlp/
    /// * For a single byte whose value is in the [0x00, 0x7f] (decimal [0, 127]) range, that byte is its own RLP encoding.
    /// * Otherwise, if a string is 0-55 bytes long, the RLP encoding consists of a single byte with value 0x80 (dec. 128) plus the length of the string followed by the string. The range of the first byte is thus [0x80, 0xb7] (dec. [128, 183]).
    /// * If a string is more than 55 bytes long, the RLP encoding consists of a single byte with value 0xb7 (dec. 183) plus the length in bytes of the length of the string in binary form, followed by the length of the string, followed by the string.
    ///
    /// ## Warning
    /// This function does not constrain that if `is_big == true` then the string length must be greater than 55 bytes. This is done separately in `parse_rlp_len`.
    fn parse_rlp_field_prefix(
        &self,
        ctx: &mut Context<F>,
        prefix: AssignedValue<F>,
    ) -> RlpFieldPrefixParsed<F> {
        let is_not_literal = self.range.is_less_than(ctx, Constant(F::from(127)), prefix, 8);
        let is_len_or_literal = self.range.is_less_than(ctx, prefix, Constant(F::from(184)), 8);
        // is valid
        self.range.check_less_than(ctx, prefix, Constant(F::from(192)), 8);

        let field_len = self.gate().sub(ctx, prefix, Constant(F::from(128)));
        let len_len = self.gate().sub(ctx, prefix, Constant(F::from(183)));

        let is_big = self.gate().not(ctx, is_len_or_literal);

        // length of the next RLP field
        let next_len = self.gate().select(ctx, len_len, field_len, is_big);
        let next_len = self.gate().select(ctx, next_len, Constant(F::ONE), is_not_literal);
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
    ///
    /// ## Warning
    /// This function does not constrain that if `is_big == true` then the total payload length of the list must be greater than 55 bytes. This is done separately in `parse_rlp_len`.
    fn parse_rlp_array_prefix(
        &self,
        ctx: &mut Context<F>,
        prefix: AssignedValue<F>,
    ) -> RlpArrayPrefixParsed<F> {
        // is valid
        self.range.check_less_than(ctx, Constant(F::from(191)), prefix, 8);

        let is_big = self.range.is_less_than(ctx, Constant(F::from(247)), prefix, 8);

        let array_len = self.gate().sub(ctx, prefix, Constant(F::from(192)));
        let len_len = self.gate().sub(ctx, prefix, Constant(F::from(247)));
        let next_len = self.gate().select(ctx, len_len, array_len, is_big);
        let len_len = self.gate().mul(ctx, len_len, is_big);

        RlpArrayPrefixParsed { is_big, next_len, len_len }
    }

    /// Parse a byte by interpreting it as the first byte in the RLP encoding (either a byte string or a list).
    /// Output should be identical to `parse_rlp_field_prefix` when `prefix` is a byte string.
    /// Output should be identical to `parse_rlp_array_prefix` when `prefix` is a list.
    ///
    /// Assumes that `prefix` has already been range checked to be a byte
    ///
    /// ## Warning
    /// This function does not constrain that if `is_big == true` then the total payload length must be greater than 55 bytes. This is done separately in `parse_rlp_len`.
    fn parse_rlp_prefix(
        &self,
        ctx: &mut Context<F>,
        prefix: AssignedValue<F>,
    ) -> RlpPrefixParsed<F> {
        let is_not_literal = self.range.is_less_than(ctx, Constant(F::from(127)), prefix, 8);
        let is_field = self.range.is_less_than(ctx, prefix, Constant(F::from(192)), 8);

        let is_big_if_field = self.range.is_less_than(ctx, Constant(F::from(183)), prefix, 8);
        let is_big_if_array = self.range.is_less_than(ctx, Constant(F::from(247)), prefix, 8);

        let is_big = self.gate().select(ctx, is_big_if_field, is_big_if_array, is_field);

        let field_len = self.gate().sub(ctx, prefix, Constant(F::from(128)));
        let field_len_len = self.gate().sub(ctx, prefix, Constant(F::from(183)));
        let next_field_len = self.gate().select(ctx, field_len_len, field_len, is_big_if_field);
        let next_field_len =
            self.gate().select(ctx, next_field_len, Constant(F::ONE), is_not_literal);

        let array_len = self.gate().sub(ctx, prefix, Constant(F::from(192)));
        let array_len_len = self.gate().sub(ctx, prefix, Constant(F::from(247)));
        let next_array_len = self.gate().select(ctx, array_len_len, array_len, is_big_if_array);

        let next_len = self.gate().select(ctx, next_field_len, next_array_len, is_field);
        let len_len = self.gate().select(ctx, field_len_len, array_len_len, is_field);
        let len_len = self.gate().mul(ctx, len_len, is_big);

        RlpPrefixParsed { is_not_literal, is_big, next_len, len_len }
    }

    /// Given a full RLP encoding `rlp_cells` string, and the length in bytes of the length of the payload, `len_len`, parse the length of the payload.
    ///
    /// Assumes that it is known that `len_len <= max_len_len`.
    ///
    /// Returns the *witness* for the length of the payload in bytes, together with the BigInt value of this length, which is constrained assuming that the witness is valid. (The witness for the length as byte string is checked later in an RLC concatenation.)
    ///
    /// The BigInt value of the length is returned as `len_val`.
    /// We constrain that `len_val > 55` if and only if `is_big == true`.
    ///
    /// ## Assumptions
    /// * `rlp_cells` have already been constrained to be bytes.
    fn parse_rlp_len(
        &self,
        ctx: &mut Context<F>,
        rlp_cells: &[AssignedValue<F>],
        len_len: AssignedValue<F>,
        max_len_len: usize,
        is_big: AssignedValue<F>,
    ) -> (Vec<AssignedValue<F>>, AssignedValue<F>) {
        let len_cells = witness_subarray(
            ctx,
            rlp_cells,
            &F::ONE, // the 0th index is the prefix byte, and is skipped
            len_len.value(),
            max_len_len,
        );
        // The conversion from length as BigInt to bytes must have no leading zeros
        constrain_no_leading_zeros(ctx, self.gate(), &len_cells, len_len);
        let len_val = evaluate_byte_array(ctx, self.gate(), &len_cells, len_len);
        // Constrain that `len_val > 55` if and only if `is_big == true`.
        // `len_val` has at most `max_len_len * 8` bits, and `55` is 6 bits.
        let len_is_big = self.range.is_less_than(
            ctx,
            Constant(F::from(55)),
            len_val,
            std::cmp::max(8 * max_len_len, 6),
        );
        ctx.constrain_equal(&len_is_big, &is_big);
        (len_cells, len_val)
    }

    /// Given a byte string `rlp_field`, this function together with [`Self::decompose_rlp_field_phase1`]
    /// constrains that the byte string is the RLP encoding of a byte string (and not a list).
    ///
    /// In the present function, the witnesses for the RLP decoding are computed and assigned. This decomposition is NOT yet constrained.
    ///
    /// Witnesses MUST be generated in `FirstPhase` to be able to compute RLC of them in `SecondPhase`
    ///
    /// # Assumptions
    /// - `rlp_field` elements are already range checked to be bytes
    // TODO: use SafeByte
    pub fn decompose_rlp_field_phase0(
        &self,
        ctx: &mut Context<F>, // context for GateChip
        rlp_field: Vec<AssignedValue<F>>,
        max_field_len: usize,
    ) -> RlpFieldWitness<F> {
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
        // * field_rlc.rlc_len = (1 - prefix_parsed.is_big) * prefix_parsed.next_len
        //                       + prefix_parsed.is_big * byte_value(len)
        //
        // * rlp_field_rlc = accumulate(
        //                       [(prefix, 1),
        //                        (len_rlc.rlc_val, len_rlc.rlc_len),
        //                        (field_rlc.rlc_val, field_rlc.rlc_len)])

        let prefix_parsed = self.parse_rlp_field_prefix(ctx, rlp_field[0]);
        let prefix = self.gate().mul(ctx, rlp_field[0], prefix_parsed.is_not_literal);

        let len_len = prefix_parsed.len_len;
        self.range.check_less_than_safe(ctx, len_len, (max_len_len + 1) as u64);
        let (len_cells, len_byte_val) =
            self.parse_rlp_len(ctx, &rlp_field, len_len, max_len_len, prefix_parsed.is_big);

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

        RlpFieldWitness {
            prefix,
            prefix_len: prefix_parsed.is_not_literal,
            len_len,
            len_cells,
            field_len,
            field_cells,
            max_field_len,
            encoded_item: rlp_field,
            encoded_item_len: rlp_len,
        }
    }

    /// Use RLC to constrain the parsed RLP field witness. This MUST be done in `SecondPhase`.
    pub fn decompose_rlp_field_phase1(
        &self,
        (ctx_gate, ctx_rlc): RlcContextPair<F>,
        witness: RlpFieldWitness<F>,
    ) -> RlpFieldTrace<F> {
        let RlpFieldWitness {
            prefix,
            prefix_len,
            len_len,
            len_cells,
            field_len,
            field_cells,
            max_field_len,
            encoded_item: rlp_field,
            encoded_item_len: rlp_field_len,
        } = witness;
        assert_eq!(max_rlp_len_len(max_field_len), len_cells.len());
        assert_eq!(max_field_len, field_cells.len());

        let rlc = self.rlc();
        // Disabling as it should be called globally to avoid concurrency issues:
        // rlc.load_rlc_cache((ctx_gate, ctx_rlc), self.gate(), bit_length(rlp_field.len() as u64));

        let len_rlc = rlc.compute_rlc((ctx_gate, ctx_rlc), self.gate(), len_cells, len_len);
        let field_rlc = rlc.compute_rlc((ctx_gate, ctx_rlc), self.gate(), field_cells, field_len);
        let rlp_field_rlc =
            rlc.compute_rlc((ctx_gate, ctx_rlc), self.gate(), rlp_field, rlp_field_len);

        rlc.constrain_rlc_concat(
            ctx_gate,
            self.gate(),
            [RlcTrace::new(prefix, prefix_len, 1), len_rlc, field_rlc],
            &rlp_field_rlc,
            None,
        );

        RlpFieldTrace {
            prefix,
            prefix_len,
            len_trace: len_rlc,
            field_trace: field_rlc,
            rlp_trace: rlp_field_rlc,
        }
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
    /// # Assumptions
    /// * In order for the circuit to pass, the excess witness values in `rlp_array` beyond the actual RLP sequence should all be `0`s.
    /// * `rlp_array` should be an array of `AssignedValue`s that are range checked to be bytes
    ///
    /// For each item in the array, we must decompose its prefix and length to determine how long the item is.
    ///
    pub fn decompose_rlp_array_phase0(
        &self,
        ctx: &mut Context<F>, // context for GateChip
        rlp_array: Vec<AssignedValue<F>>,
        max_field_lens: &[usize],
        is_variable_len: bool,
    ) -> RlpArrayWitness<F> {
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
        let next_len = prefix_parsed.next_len;
        let is_big = prefix_parsed.is_big;

        self.range.check_less_than_safe(ctx, len_len, (max_len_len + 1) as u64);

        let (len_cells, len_byte_val) =
            self.parse_rlp_len(ctx, &rlp_array, len_len, max_len_len, is_big);

        let list_payload_len = self.gate().select(ctx, len_byte_val, next_len, is_big);
        self.range.check_less_than_safe(
            ctx,
            list_payload_len,
            (max_rlp_array_len - max_len_len) as u64,
        );

        // this is automatically <= max_rlp_array_len
        let rlp_len =
            self.gate().sum(ctx, [Constant(F::ONE), Existing(len_len), Existing(list_payload_len)]);

        let mut field_witness = Vec::with_capacity(max_field_lens.len());

        let mut prefix_idx = self.gate().add(ctx, Constant(F::ONE), len_len);
        let mut running_max_len = max_len_len + 1;

        let mut list_len = ctx.load_zero();

        for &max_field_len in max_field_lens {
            let mut prefix = self.gate().select_from_idx(
                ctx,
                // selecting from the whole array is wasteful: we only select from the max range currently possible
                rlp_array.iter().copied().take(running_max_len + 1),
                prefix_idx,
            );

            let prefix_parsed = self.parse_rlp_prefix(ctx, prefix);
            let mut len_len = prefix_parsed.len_len;

            let max_field_len_len = max_rlp_len_len(max_field_len);
            self.range.check_less_than_safe(
                ctx,
                prefix_parsed.len_len,
                (max_field_len_len + 1) as u64,
            );

            let len_start_id = *prefix_parsed.is_not_literal.value() + prefix_idx.value();
            let len_cells = witness_subarray(
                ctx,
                &rlp_array,
                &len_start_id,
                prefix_parsed.len_len.value(),
                max_field_len_len,
            );

            let field_len_byte_val = evaluate_byte_array(ctx, self.gate(), &len_cells, len_len);
            let mut field_len = self.gate().select(
                ctx,
                field_len_byte_val,
                prefix_parsed.next_len,
                prefix_parsed.is_big,
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
                list_len = self.gate().add(ctx, list_len, field_in_list);
                // In cases where the RLP sequence is a list of unknown variable length, we keep track
                // of whether the corresponding index actually is a list item by constraining that
                // all of `prefix_len, len_len, field_len` are 0 when the current field should be treated
                // as a dummy and not actually in the list
                prefix_len = self.gate().mul(ctx, prefix_len, field_in_list);
                len_len = self.gate().mul(ctx, prefix_parsed.len_len, field_in_list);
                field_len = self.gate().mul(ctx, field_len, field_in_list);
            }

            self.range.check_less_than_safe(ctx, field_len, (max_field_len + 1) as u64);

            let field_cells = witness_subarray(
                ctx,
                &rlp_array,
                &(len_start_id + len_len.value()),
                field_len.value(),
                max_field_len,
            );

            let encoded_item_len =
                self.gate().sum(ctx, [prefix_parsed.is_not_literal, len_len, field_len]);
            let encoded_item = witness_subarray(
                ctx,
                &rlp_array,
                prefix_idx.value(),
                encoded_item_len.value(),
                max_rlp_encoding_len(max_field_len),
            ); // *** unconstrained

            prefix = self.gate().mul(ctx, prefix, prefix_len);
            prefix_idx =
                self.gate().sum(ctx, [prefix_idx, prefix_len, prefix_parsed.len_len, field_len]);

            let witness = RlpFieldWitness {
                prefix,     // 0 if phantom or literal, 1st byte otherwise
                prefix_len, // 0 if phantom or literal, 1 otherwise
                len_len,
                len_cells,   // have not constrained this subarray
                field_len,   // have not constrained the copy used to make this
                field_cells, // have not constrained this subarray
                max_field_len,
                encoded_item, // have not constrained this subarray
                encoded_item_len,
            };
            field_witness.push(witness);
        }
        let list_len = is_variable_len.then_some(list_len);
        RlpArrayWitness { field_witness, len_len, len_cells, rlp_len, rlp_array, list_len }
    }

    /// Use RLC to constrain the parsed RLP array witness. This MUST be done in `SecondPhase`.
    ///
    /// We do not make any guarantees on the values in the original RLP sequence beyond the parsed length for the total payload
    pub fn decompose_rlp_array_phase1(
        &self,
        (ctx_gate, ctx_rlc): RlcContextPair<F>,
        rlp_array_witness: RlpArrayWitness<F>,
        _is_variable_len: bool,
    ) -> RlpArrayTrace<F> {
        let RlpArrayWitness { field_witness, len_len, len_cells, rlp_len, rlp_array, .. } =
            rlp_array_witness;
        let rlc = self.rlc();
        // we only need rlc_pow up to the maximum length in a fragment of `constrain_rlc_concat`
        // let max_item_rlp_len =
        //     field_witness.iter().map(|w| max_rlp_encoding_len(w.max_field_len)).max().unwrap();
        // Disabling this as it should be called once globally:
        // rlc.load_rlc_cache((ctx_gate, ctx_rlc), self.gate(), bit_length(max_item_rlp_len as u64));

        let len_trace = rlc.compute_rlc((ctx_gate, ctx_rlc), self.gate(), len_cells, len_len);

        let mut field_trace = Vec::with_capacity(field_witness.len());
        for w in field_witness {
            let len_rlc = rlc.compute_rlc((ctx_gate, ctx_rlc), self.gate(), w.len_cells, w.len_len);
            let field_rlc =
                rlc.compute_rlc((ctx_gate, ctx_rlc), self.gate(), w.field_cells, w.field_len);
            // RLC of the entire RLP encoded item
            let rlp_trace = rlc.compute_rlc(
                (ctx_gate, ctx_rlc),
                self.gate(),
                w.encoded_item,
                w.encoded_item_len,
            );
            // We need to constrain that the `encoded_item` is the concatenation of the prefix, the length, and the payload
            rlc.constrain_rlc_concat(
                ctx_gate,
                self.gate(),
                [RlcTrace::new(w.prefix, w.prefix_len, 1), len_rlc, field_rlc],
                &rlp_trace,
                None,
            );
            field_trace.push(RlpFieldTrace {
                prefix: w.prefix,
                prefix_len: w.prefix_len,
                len_trace: len_rlc,
                field_trace: field_rlc,
                rlp_trace,
            });
        }

        let prefix = rlp_array[0];
        let one = ctx_gate.load_constant(F::ONE);
        let rlp_rlc = rlc.compute_rlc((ctx_gate, ctx_rlc), self.gate(), rlp_array, rlp_len);
        let inputs = iter::empty()
            .chain([RlcTrace::new(prefix, one, 1), len_trace])
            .chain(field_trace.iter().map(|trace| trace.rlp_trace));

        rlc.constrain_rlc_concat(ctx_gate, self.gate(), inputs, &rlp_rlc, None);

        RlpArrayTrace { len_trace, field_trace }
    }
}

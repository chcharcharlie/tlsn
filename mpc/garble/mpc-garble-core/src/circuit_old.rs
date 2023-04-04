use aes::{Aes128, NewBlockCipher};
use cipher::{consts::U16, BlockCipher, BlockEncrypt};
use std::{collections::HashSet, ops::Index, sync::Arc};

use crate::{
    error::Error,
    generator::{garble, GarbleError},
    label::{state as label_state, DecodingInfo, Delta, EncodedValue, EncodingCommitment},
};

// use crate::{
//     evaluator::evaluate,
//     generator::garble,
//     label::{
//         encoded::{decode_active_labels, extract_active_labels, extract_full_labels},
//         ActiveEncodedInput, ActiveEncodedOutput, ActiveInputSet, ActiveOutputSet, FullEncodedInput,
//         FullEncodedOutput, FullOutputSet, InputDecodingInfo, DecodingInfo,
//         EncodingCommitment,
//     },
//     Delta, EncodingError, Error,
// };
use mpc_circuits::Circuit;
use mpc_core::{utils::blake3, Block};

/// Encrypted gate truth table
///
/// For the half-gate garbling scheme a truth table will typically have 2 rows, except for in
/// privacy-free garbling mode where it will be reduced to 1
#[derive(Debug, Clone, PartialEq)]
pub struct EncryptedGate(pub(crate) [Block; 2]);

impl EncryptedGate {
    pub(crate) fn new(inner: [Block; 2]) -> Self {
        Self(inner)
    }
}

impl Index<usize> for EncryptedGate {
    type Output = Block;

    fn index(&self, index: usize) -> &Self::Output {
        &self.0[index]
    }
}

fn gates_digest(encrypted_gates: &[EncryptedGate]) -> Vec<u8> {
    blake3(
        &encrypted_gates
            .iter()
            .map(|gate| gate.0)
            .flatten()
            .map(|gate| gate.to_be_bytes())
            .flatten()
            .collect::<Vec<u8>>(),
    )
    .to_vec()
}

/// All the various states of a garbled circuit
pub mod state {
    use super::*;

    mod sealed {
        use super::*;

        pub trait Sealed {}

        impl Sealed for Full {}
        impl Sealed for FullSummary {}
        impl Sealed for Partial {}
        impl Sealed for Evaluated {}
        impl Sealed for EvaluatedSummary {}
        impl Sealed for Compressed {}
        impl Sealed for Output {}
    }

    /// Marker trait for the state of a garbled circuit
    pub trait State: sealed::Sealed {}

    /// Full garbled circuit data. This includes all wire label pairs, encrypted gates and delta.
    #[derive(Debug)]
    pub struct Full {
        pub(crate) inputs: Vec<EncodedValue<label_state::Full>>,
        pub(crate) outputs: Vec<EncodedValue<label_state::Full>>,
        /// Encrypted gates sorted ascending by id
        pub(crate) encrypted_gates: Vec<EncryptedGate>,
        #[allow(dead_code)]
        pub(crate) delta: Delta,
    }

    /// Summary of full garbled circuit data, only including input/output labels and decoding info.
    #[derive(Debug, Clone)]
    pub struct FullSummary {
        pub(crate) inputs: Vec<EncodedValue<label_state::Full>>,
        pub(crate) outputs: Vec<EncodedValue<label_state::Full>>,
        /// Output labels decoding sorted ascending by id
        pub(crate) decoding: Vec<DecodingInfo>,
        pub(crate) delta: Delta,
    }

    /// Garbled circuit data, optionally including the output decoding
    /// and or output label commitments.
    #[derive(Debug)]
    pub struct Partial {
        /// Encrypted gates sorted ascending by id
        pub(crate) encrypted_gates: Vec<EncryptedGate>,
        /// Output labels decoding sorted ascending by id
        pub(crate) decoding: Option<Vec<DecodingInfo>>,
        /// Output label commitments sorted ascending by id
        pub(crate) commitments: Option<Vec<EncodingCommitment>>,
    }

    /// Evaluated garbled circuit data
    #[derive(Debug, Clone)]
    pub struct Evaluated {
        pub(crate) inputs: Vec<EncodedValue<label_state::Active>>,
        pub(crate) outputs: Vec<EncodedValue<label_state::Active>>,
        /// Encrypted gates sorted ascending by id
        pub(crate) encrypted_gates: Vec<EncryptedGate>,
        /// Output labels decoding sorted ascending by id
        pub(crate) decoding: Option<Vec<DecodingInfo>>,
        /// Output label commitments sorted ascending by id
        pub(crate) commitments: Option<Vec<EncodingCommitment>>,
    }

    /// Summary of evaluated garbled circuit data
    #[derive(Debug, Clone)]
    pub struct EvaluatedSummary {
        pub(crate) inputs: Vec<EncodedValue<label_state::Active>>,
        pub(crate) outputs: Vec<EncodedValue<label_state::Active>>,
        /// Output labels decoding sorted ascending by id
        pub(crate) decoding: Option<Vec<DecodingInfo>>,
    }

    /// Evaluated garbled circuit that has been compressed to minimize memory footprint
    #[derive(Debug, Clone)]
    pub struct Compressed {
        pub(crate) inputs: Vec<EncodedValue<label_state::Active>>,
        pub(crate) outputs: Vec<EncodedValue<label_state::Active>>,
        /// Input labels plus the encrypted gates is what constitutes a garbled circuit (GC).
        /// In scenarios where we expect the generator to prove their honest GC generation,
        /// even after performing the evaluation, we want the evaluator to keep the GC around
        /// in order to compare it against an honestly generated circuit. To reduce the memory
        /// footprint, we keep a hash digest of the encrypted gates.
        pub(crate) gates_digest: Vec<u8>,
        /// Output labels decoding sorted ascending by id
        pub(crate) decoding: Option<Vec<DecodingInfo>>,
        /// Output label commitments sorted ascending by id
        pub(crate) commitments: Option<Vec<EncodingCommitment>>,
    }

    /// Evaluated garbled circuit output data
    #[derive(Debug)]
    pub struct Output {
        pub(crate) outputs: Vec<EncodedValue<label_state::Active>>,
        /// Output labels decoding sorted ascending by id
        pub(crate) decoding: Option<Vec<DecodingInfo>>,
    }

    impl State for Full {}
    impl State for FullSummary {}
    impl State for Partial {}
    impl State for Evaluated {}
    impl State for EvaluatedSummary {}
    impl State for Compressed {}
    impl State for Output {}
}

use state::*;

/// Primary data structure for a garbled circuit with typed states found in [`state`]
#[derive(Debug, Clone)]
pub struct GarbledCircuit<S: State> {
    pub circ: Arc<Circuit>,
    pub(crate) state: S,
}

/// Data used for opening a garbled circuit (GC) to the evaluator.
/// To enable the evaluator to check that a GC was generated correctly, the generator
/// "opens" the GC.
/// We rely on the property of the "half-gates" garbling scheme that given the input
/// label pairs and the delta, a GC will always be generated deterministically.
/// We assume that the evaluator is already in possession of all active input labels.
///
/// Note that instead of `input_decoding`, the circuit generator could just provide
/// his actual input to the circuit. But this would have a slightly larger cost when
/// sending the serialized input type over the wire. With the current approach we
/// require an extra step of decoding the generator's active input labels to get the
/// generator's input to the circuit.
#[derive(Debug, Clone)]
pub struct CircuitOpening {
    pub(crate) delta: Delta,
    pub(crate) input_decoding: Vec<DecodingInfo>,
}

impl CircuitOpening {
    /// Returns delta
    pub fn get_delta(&self) -> Delta {
        self.delta
    }

    /// Returns reference to input labels decoding info
    pub fn get_decoding(&self) -> &[DecodingInfo] {
        &self.input_decoding
    }
}

impl GarbledCircuit<Full> {
    /// Generate a garbled circuit with the provided input labels and delta.
    pub fn generate<C: BlockCipher<BlockSize = U16> + BlockEncrypt>(
        cipher: &C,
        circ: Arc<Circuit>,
        inputs: &[EncodedValue<label_state::Full>],
    ) -> Result<Self, GarbleError> {
        let delta = inputs[0].delta();
        let (outputs, encrypted_gates) = garble(cipher, &circ, delta, inputs)?;

        Ok(Self {
            circ,
            state: Full {
                inputs: inputs.to_vec(),
                outputs,
                encrypted_gates,
                delta,
            },
        })
    }

    /// Returns output decoding info
    pub(crate) fn decoding(&self) -> Vec<DecodingInfo> {
        self.output_labels()
            .iter()
            .map(|value| value.decoding())
            .collect()
    }

    /// Returns output commitments. To protect against the Evaluator using these
    /// commitments to decode their output, we shuffle them.
    pub(crate) fn output_commitments(&self) -> Vec<EncodingCommitment> {
        self.output_labels()
            .iter()
            .map(|labels| labels.commit())
            .collect()
    }

    /// Returns reference to input labels set
    pub fn input_labels(&self) -> &[EncodedValue<label_state::Full>] {
        &self.state.inputs
    }

    /// Returns reference to output labels set
    pub fn output_labels(&self) -> &[EncodedValue<label_state::Full>] {
        &self.state.outputs
    }

    /// Returns [`GarbledCircuit<Partial>`] which is safe to send an evaluator
    ///
    /// `reveal` flag determines whether the output decoding will be included
    /// `commit` flag determines whether commitments to the output labels will be included
    pub fn get_partial(&self, reveal: bool, commit: bool) -> GarbledCircuit<Partial> {
        GarbledCircuit {
            circ: self.circ.clone(),
            state: Partial {
                encrypted_gates: self.state.encrypted_gates.clone(),
                decoding: reveal.then(|| self.decoding()),
                commitments: commit.then(|| self.output_commitments()),
            },
        }
    }

    /// Summarizes garbled circuit data to reduce memory footprint
    pub fn get_summary(&self) -> GarbledCircuit<FullSummary> {
        let decoding = self.decoding();
        let inputs = self.state.inputs.clone();
        let outputs = self.state.outputs.clone();
        let delta = self.state.delta;

        GarbledCircuit {
            circ: self.circ.clone(),
            state: FullSummary {
                inputs,
                outputs,
                decoding,
                delta,
            },
        }
    }

    /// Summarizes garbled circuit data to reduce memory footprint
    pub fn into_summary(self) -> GarbledCircuit<FullSummary> {
        let decoding = self.decoding();
        let inputs = self.state.inputs;
        let outputs = self.state.outputs;
        let delta = self.state.delta;

        GarbledCircuit {
            circ: self.circ,
            state: FullSummary {
                inputs,
                outputs,
                decoding,
                delta,
            },
        }
    }

    /// Returns circuit opening
    pub fn open(&self) -> CircuitOpening {
        CircuitOpening {
            delta: self.state.delta,
            input_decoding: self
                .input_labels()
                .iter()
                .map(|labels| labels.decoding())
                .collect(),
        }
    }
}

// impl GarbledCircuit<FullSummary> {
//     /// Returns reference to input labels set
//     pub fn input_labels(&self) -> &[EncodedValue<label_state::Full>] {
//         &self.state.inputs
//     }

//     /// Returns reference to output labels set
//     pub fn output_labels(&self) -> &[] {
//         &self.state.outputs
//     }

//     /// Returns output label decoding info if available
//     pub fn decoding(&self) -> &[DecodingInfo] {
//         &self.state.decoding
//     }

//     /// Returns circuit opening
//     pub fn open(&self) -> CircuitOpening {
//         CircuitOpening {
//             delta: self.state.delta,
//             input_decoding: self
//                 .state
//                 .input_labels
//                 .get_groups()
//                 .iter()
//                 .map(|labels| labels.decoding())
//                 .collect(),
//         }
//     }
// }

// impl GarbledCircuit<Partial> {
//     /// Returns whether or not output decoding info is available
//     pub fn has_decoding(&self) -> bool {
//         self.state.decoding.is_some()
//     }

//     /// Returns whether or not output label commitments were provided
//     pub fn has_output_commitments(&self) -> bool {
//         self.state.commitments.is_some()
//     }

//     /// Evaluates a garbled circuit using provided input labels. These labels are combined with labels sent by the generator
//     /// and checked for correctness using the circuit spec.
//     pub fn evaluate<C: BlockCipher<BlockSize = U16> + BlockEncrypt>(
//         self,
//         cipher: &C,
//         input_labels: ActiveInputSet,
//     ) -> Result<GarbledCircuit<Evaluated>, Error> {
//         let labels = evaluate(
//             cipher,
//             &self.circ,
//             input_labels.clone(),
//             &self.state.encrypted_gates,
//         )?;

//         let outputs = extract_active_labels(self.circ.outputs(), &labels);

//         // Always check output labels against commitments if they're available
//         if let Some(output_commitments) = self.state.commitments.as_ref() {
//             output_commitments
//                 .iter()
//                 .zip(&output_labels)
//                 .map(|(commitment, labels)| commitment.validate(&labels))
//                 .collect::<Result<(), EncodingError>>()?;
//         }

//         Ok(GarbledCircuit {
//             circ: self.circ.clone(),
//             state: Evaluated {
//                 input_labels,
//                 encrypted_gates: self.state.encrypted_gates,
//                 output_labels: ActiveOutputSet::new(output_labels)?,
//                 decoding: self.state.decoding,
//                 commitments: self.state.commitments,
//             },
//         })
//     }
// }

// impl GarbledCircuit<Evaluated> {
//     /// Returns all active inputs labels used to evaluate the circuit
//     pub fn input_labels(&self) -> &ActiveInputSet {
//         &self.state.inputs
//     }

//     /// Returns all active output labels which are the result of circuit evaluation
//     pub fn output_labels(&self) -> &ActiveOutputSet {
//         &self.state.outputs
//     }

//     /// Returns whether or not output decoding info is available
//     pub fn has_decoding(&self) -> bool {
//         self.state.decoding.is_some()
//     }

//     /// Returns whether or not output label commitments were provided
//     pub fn has_output_commitments(&self) -> bool {
//         self.state.commitments.is_some()
//     }

//     /// Returns garbled circuit output
//     pub fn get_output(&self) -> GarbledCircuit<Output> {
//         GarbledCircuit {
//             circ: self.circ.clone(),
//             state: Output {
//                 output_labels: self.state.outputs.clone(),
//                 decoding: self.state.decoding.clone(),
//             },
//         }
//     }

//     /// Returns garbled circuit output, consumes self
//     pub fn into_output(self) -> GarbledCircuit<Output> {
//         GarbledCircuit {
//             circ: self.circ.clone(),
//             state: Output {
//                 output_labels: self.state.outputs,
//                 decoding: self.state.decoding,
//             },
//         }
//     }

//     /// Returns a compressed evaluated circuit to reduce memory utilization
//     pub fn into_compressed(self) -> GarbledCircuit<Compressed> {
//         GarbledCircuit {
//             circ: self.circ,
//             state: Compressed {
//                 input_labels: self.state.inputs,
//                 gates_digest: gates_digest(&self.state.encrypted_gates),
//                 output_labels: self.state.outputs,
//                 decoding: self.state.decoding,
//                 commitments: self.state.commitments,
//             },
//         }
//     }

//     /// Returns a summary of the evaluated circuit to reduce memory utilization
//     pub fn get_summary(&self) -> GarbledCircuit<EvaluatedSummary> {
//         GarbledCircuit {
//             circ: self.circ.clone(),
//             state: EvaluatedSummary {
//                 input_labels: self.state.inputs.clone(),
//                 output_labels: self.state.outputs.clone(),
//                 decoding: self.state.decoding.clone(),
//             },
//         }
//     }

//     /// Returns a summary of the evaluated circuit to reduce memory utilization,
//     /// consumes self
//     pub fn into_summary(self) -> GarbledCircuit<EvaluatedSummary> {
//         GarbledCircuit {
//             circ: self.circ,
//             state: EvaluatedSummary {
//                 input_labels: self.state.inputs,
//                 output_labels: self.state.outputs,
//                 decoding: self.state.decoding,
//             },
//         }
//     }

//     /// Returns decoded circuit outputs
//     pub fn decode(&self) -> Result<Vec<OutputValue>, Error> {
//         let decoding = self.state.decoding.as_ref().ok_or(Error::MissingDecoding)?;
//         decode_active_labels(self.output_labels().get_groups(), decoding).map_err(Error::from)
//     }

//     /// Validates circuit using [`CircuitOpening`]
//     pub fn validate(&self, opening: CircuitOpening) -> Result<(), Error> {
//         validate_circuit(
//             &Aes128::new_from_slice(&[0; 16]).unwrap(),
//             &self.circ,
//             opening,
//             &self.state.inputs.get_groups(),
//             Some(self.state.encrypted_gates.as_slice()),
//             None,
//             self.state.decoding.as_ref().map(Vec::as_slice),
//             self.state.commitments.as_ref().map(Vec::as_slice),
//         )
//     }
// }

// impl GarbledCircuit<EvaluatedSummary> {
//     /// Returns reference to input labels set
//     pub fn input_labels(&self) -> &ActiveInputSet {
//         &self.state.inputs
//     }

//     /// Returns reference to output labels set
//     pub fn output_labels(&self) -> &ActiveOutputSet {
//         &self.state.outputs
//     }

//     /// Returns whether or not output decoding info is available
//     pub fn has_decoding(&self) -> bool {
//         self.state.decoding.is_some()
//     }

//     /// Returns decoded circuit outputs
//     pub fn decode(&self) -> Result<Vec<OutputValue>, Error> {
//         let decoding = self.state.decoding.as_ref().ok_or(Error::MissingDecoding)?;
//         decode_active_labels(self.output_labels().get_groups(), decoding).map_err(Error::from)
//     }
// }

// impl GarbledCircuit<Compressed> {
//     /// Returns all active inputs labels used to evaluate the circuit
//     pub fn input_labels(&self) -> &ActiveInputSet {
//         &self.state.inputs
//     }

//     /// Returns all active output labels which are the result of circuit evaluation
//     pub fn output_labels(&self) -> &ActiveOutputSet {
//         &self.state.outputs
//     }

//     /// Returns whether or not output decoding info is available
//     pub fn has_decoding(&self) -> bool {
//         self.state.decoding.is_some()
//     }

//     /// Returns garbled circuit output
//     pub fn get_output(&self) -> GarbledCircuit<Output> {
//         GarbledCircuit {
//             circ: self.circ.clone(),
//             state: Output {
//                 output_labels: self.state.outputs.clone(),
//                 decoding: self.state.decoding.clone(),
//             },
//         }
//     }

//     /// Returns decoded circuit outputs
//     pub fn decode(&self) -> Result<Vec<OutputValue>, Error> {
//         let decoding = self.state.decoding.as_ref().ok_or(Error::MissingDecoding)?;
//         decode_active_labels(self.output_labels().get_groups(), decoding).map_err(Error::from)
//     }

//     /// Validates circuit using [`CircuitOpening`]
//     pub fn validate(&self, opening: CircuitOpening) -> Result<(), Error> {
//         validate_circuit(
//             &Aes128::new_from_slice(&[0; 16]).unwrap(),
//             &self.circ,
//             opening,
//             &self.state.inputs.get_groups(),
//             None,
//             Some(self.state.gates_digest.clone()),
//             self.state.decoding.as_ref().map(Vec::as_slice),
//             self.state.commitments.as_ref().map(Vec::as_slice),
//         )
//     }
// }

// impl GarbledCircuit<Output> {
//     /// Returns all output labels
//     pub fn output_labels(&self) -> &ActiveOutputSet {
//         &self.state.outputs
//     }

//     /// Returns whether or not output decoding info is available
//     pub fn has_decoding(&self) -> bool {
//         self.state.decoding.is_some()
//     }

//     /// Returns output label decoding info if available
//     pub fn decoding(&self) -> Option<Vec<DecodingInfo>> {
//         self.state.decoding.clone()
//     }

//     /// Returns decoded circuit outputs
//     pub fn decode(&self) -> Result<Vec<OutputValue>, Error> {
//         let decoding = self.state.decoding.as_ref().ok_or(Error::MissingDecoding)?;
//         decode_active_labels(self.output_labels().get_groups(), decoding).map_err(Error::from)
//     }
// }

// fn validate_circuit<C: BlockCipher<BlockSize = U16> + BlockEncrypt>(
//     cipher: &C,
//     circ: &Circuit,
//     opening: CircuitOpening,
//     input_labels: &[ActiveEncodedInput],
//     encrypted_gates: Option<&[EncryptedGate]>,
//     digest: Option<Vec<u8>>,
//     output_decoding: Option<&[DecodingInfo]>,
//     output_commitments: Option<&[EncodingCommitment]>,
// ) -> Result<(), Error> {
//     let CircuitOpening {
//         delta,
//         input_decoding,
//         ..
//     } = opening;

//     let full_input_labels = input_labels
//         .iter()
//         .zip(input_decoding)
//         .map(|(labels, decoding)| FullEncodedInput::from_decoding(labels.clone(), delta, decoding))
//         .collect::<Result<Vec<_>, EncodingError>>()?;

//     let full_input_labels = FullInputSet::new(full_input_labels)?;

//     let digest = if let Some(encrypted_gates) = encrypted_gates {
//         // If gates are passed in, hash them
//         gates_digest(encrypted_gates)
//     } else if let Some(digest) = digest {
//         // Otherwise if the digest was already computed, use that instead.
//         digest
//     } else {
//         return Err(Error::General(
//             "Must provide encrypted gates or digest".to_string(),
//         ));
//     };

//     // Re-garble circuit using input labels.
//     // We rely on the property of the "half-gates" garbling scheme that given the input
//     // labels, the encrypted gates will always be computed deterministically.
//     let (labels, encrypted_gates) = garble(cipher, circ, full_input_labels)?;

//     // Compute the expected gates digest
//     let expected_digest = gates_digest(&encrypted_gates);

//     // If hashes don't match circuit wasn't garbled correctly
//     if expected_digest != digest {
//         return Err(Error::CorruptedGarbledCircuit);
//     }

//     // Check output decoding info if it was sent
//     if let Some(output_decoding) = output_decoding {
//         let expected_output_decoding: Vec<DecodingInfo> =
//             extract_full_labels(circ.outputs(), delta, &labels)
//                 .into_iter()
//                 .map(|labels| labels.decoding())
//                 .collect();

//         if &expected_output_decoding != output_decoding {
//             return Err(Error::CorruptedGarbledCircuit);
//         }
//     }

//     // Check output commitments if they were sent
//     if let Some(output_commitments) = output_commitments {
//         let expected_output_commitments: Vec<EncodingCommitment> =
//             extract_full_labels(circ.outputs(), delta, &labels)
//                 .into_iter()
//                 .map(|labels| labels.commit())
//                 .collect();

//         if &expected_output_commitments != output_commitments {
//             return Err(Error::CorruptedGarbledCircuit);
//         }
//     }

//     Ok(())
// }

pub(crate) mod unchecked {
    use utils::iter::DuplicateCheckBy;

    use super::*;

    /// Partial garbled circuit which has not been validated against a circuit spec
    #[derive(Debug, Clone)]
    pub struct UncheckedGarbledCircuit {
        pub(crate) encrypted_gates: Vec<Block>,
        pub(crate) decoding: Option<Vec<DecodingInfo>>,
        pub(crate) commitments: Option<Vec<EncodingCommitment>>,
    }

    #[cfg(test)]
    impl From<GarbledCircuit<Partial>> for UncheckedGarbledCircuit {
        fn from(gc: GarbledCircuit<Partial>) -> Self {
            Self {
                encrypted_gates: gc
                    .state
                    .encrypted_gates
                    .into_iter()
                    .map(|gate| gate.0)
                    .flatten()
                    .collect(),
                decoding: gc.state.decoding,
                commitments: gc.state.commitments,
            }
        }
    }

    impl GarbledCircuit<Partial> {
        pub fn from_unchecked(
            circ: Arc<Circuit>,
            unchecked: UncheckedGarbledCircuit,
        ) -> Result<Self, Error> {
            // Make sure the expected number of gates is present. In half-gates garbling each
            // AND gate is encrypted into 2 block-sized ciphertexts.
            if unchecked.encrypted_gates.len() != 2 * circ.and_count() {
                return Err(Error::ValidationError(
                    "Incorrect number of encrypted gates".to_string(),
                ));
            }

            // Convert encrypted gates to typed version
            let encrypted_gates = unchecked
                .encrypted_gates
                .chunks_exact(2)
                .into_iter()
                .map(|gate| EncryptedGate::new([gate[0], gate[1]]))
                .collect();

            // Validate output decoding info
            let decoding = match unchecked.decoding {
                Some(mut decoding) => {
                    // Check that all output decodings are present
                    // NOTE: we may relax this requirement in the future
                    if decoding.len() != circ.outputs().len() {
                        return Err(Error::ValidationError(
                            "Incorrect number of output decodings".to_string(),
                        ));
                    }

                    Some(decoding)
                }
                None => None,
            };

            let commitments = match unchecked.commitments {
                Some(mut commitments) => {
                    // Check for duplicates
                    if commitments
                        .iter()
                        .contains_dups_by(|commitment| &commitment.id)
                    {
                        return Err(Error::ValidationError("Duplicate commitments".to_string()));
                    }

                    // Make sure decodings are sorted by id
                    commitments.sort_by_key(|decoding| decoding.id);

                    // Check for unexpected output ids
                    if !commitments
                        .iter()
                        .map(|commitment| commitment.id)
                        .all(|id| circ.is_input_id(id))
                    {
                        return Err(Error::ValidationError(
                            "Invalid commitment output id".to_string(),
                        ));
                    }

                    // Check that all output commitments are present
                    // NOTE: we may relax this requirement in the future
                    if commitments.len() != circ.output_count() {
                        return Err(Error::ValidationError(
                            "Incorrect number of output decodings".to_string(),
                        ));
                    }

                    Some(
                        commitments
                            .into_iter()
                            .zip(circ.outputs())
                            .map(|(unchecked, output)| {
                                EncodingCommitment::from_unchecked(output.clone(), unchecked)
                            })
                            .collect::<Result<Vec<_>, Error>>()?,
                    )
                }
                None => None,
            };

            Ok(Self {
                circ,
                state: Partial {
                    encrypted_gates,
                    decoding,
                    commitments,
                },
            })
        }
    }

    /// Output of a garbled circuit which has not been validated
    #[derive(Debug, Clone)]
    pub struct UncheckedOutput {
        pub(crate) circ_id: String,
        pub(crate) output_labels: Vec<UncheckedOutputLabels>,
    }

    #[cfg(test)]
    impl From<GarbledCircuit<Output>> for UncheckedOutput {
        fn from(gc: GarbledCircuit<Output>) -> Self {
            Self {
                circ_id: gc.circ.id().clone().to_string(),
                output_labels: gc
                    .state
                    .output_labels
                    .to_inner()
                    .into_iter()
                    .map(UncheckedOutputLabels::from)
                    .collect(),
            }
        }
    }

    impl UncheckedOutput {
        /// Validates and decodes output using circuit spec and full output labels
        pub fn decode(
            mut self,
            circ: &Circuit,
            full_output_labels: &[FullEncodedOutput],
        ) -> Result<Vec<OutputValue>, Error> {
            let circ_id = CircuitId::new(self.circ_id)?;
            // Validate circuit id
            if &circ_id != circ.id() {
                return Err(Error::ValidationError(format!(
                    "Received garbled output with wrong id: expected {}, received {}",
                    circ.id().as_ref(),
                    circ_id.to_string()
                )));
            }

            // Check for duplicates
            let output_ids: HashSet<usize> =
                self.output_labels.iter().map(|output| output.id).collect();

            if output_ids.len() != self.output_labels.len() {
                return Err(Error::ValidationError(
                    "Received garbled output with duplicates".to_string(),
                ));
            }

            // Make sure outputs are sorted
            self.output_labels
                .sort_by_key(|output_label| output_label.id);

            // Check all outputs were received
            if self.output_labels.len() != circ.output_count() {
                return Err(Error::ValidationError(format!(
                    "Received garbled output with wrong number of outputs: expected {}, received {}",
                    circ.output_count(),
                    self.output_labels.len()
                )));
            }

            let outputs = self
                .output_labels
                .into_iter()
                .map(|labels| ActiveEncodedOutput::from_unchecked(&circ, labels))
                .collect::<Result<Vec<_>, _>>()?;

            // Validates that each output label is authentic then decodes them
            full_output_labels
                .iter()
                .zip(&output_labels)
                .map(|(full, ev)| {
                    full.validate(ev)?;
                    ev.decode(full.decoding().clone())
                })
                .collect::<Result<Vec<_>, EncodingError>>()
                .map_err(Error::from)
        }
    }

    /// Unchecked variant of [`CircuitOpening`]
    #[derive(Debug, Clone)]
    pub struct UncheckedCircuitOpening {
        pub(crate) delta: Delta,
        pub(crate) input_decoding: Vec<UncheckedLabelsDecodingInfo>,
    }

    #[cfg(test)]
    impl From<CircuitOpening> for UncheckedCircuitOpening {
        fn from(opening: CircuitOpening) -> Self {
            Self {
                delta: opening.delta,
                input_decoding: opening
                    .input_decoding
                    .into_iter()
                    .map(UncheckedLabelsDecodingInfo::from)
                    .collect(),
            }
        }
    }

    impl CircuitOpening {
        /// Validates opening data and converts to checked variant [`CircuitOpening`]
        pub fn from_unchecked(
            circ: &Circuit,
            unchecked: UncheckedCircuitOpening,
        ) -> Result<Self, Error> {
            let UncheckedCircuitOpening {
                delta,
                mut input_decoding,
            } = unchecked;

            // Sort by input id
            input_decoding.sort_by_key(|decoding| decoding.id);

            // 1. Check for duplicates
            // 2. Check all decodings are present
            // 3. Check all input ids are valid
            if input_decoding
                .iter()
                .contains_dups_by(|decoding| &decoding.id)
                || input_decoding.len() != circ.input_count()
                || !input_decoding
                    .iter()
                    .all(|decoding| circ.is_input_id(decoding.id))
            {
                return Err(Error::InvalidOpening);
            }

            // Convert unchecked decodings to checked variant
            let input_decoding = input_decoding
                .into_iter()
                .zip(circ.inputs())
                .map(|(unchecked, input)| {
                    InputDecodingInfo::from_unchecked(input.clone(), unchecked)
                })
                .collect::<Result<Vec<_>, EncodingError>>()?;

            Ok(CircuitOpening {
                delta,
                input_decoding,
            })
        }
    }

    #[cfg(test)]
    mod tests {
        use super::*;
        use aes::{Aes128, NewBlockCipher};
        use rand_chacha::ChaCha12Rng;
        use rand_core::SeedableRng;
        use rstest::*;

        use mpc_circuits::{Circuit, Input, WireGroup, ADDER_64, AES_128};

        #[fixture]
        fn circ() -> Arc<Circuit> {
            ADDER_64.clone()
        }

        #[fixture]
        fn input(circ: Arc<Circuit>, #[default(0)] id: usize) -> Input {
            circ.input(id).unwrap()
        }

        #[fixture]
        fn garbled_circuit(circ: Arc<Circuit>) -> GarbledCircuit<Full> {
            let inputs = FullInputSet::generate(&mut ChaCha12Rng::seed_from_u64(0), &circ, None);
            GarbledCircuit::generate(
                &Aes128::new_from_slice(&[0; 16]).unwrap(),
                circ,
                input_labels,
            )
            .unwrap()
        }

        #[fixture]
        fn unchecked_garbled_circuit(
            garbled_circuit: GarbledCircuit<Full>,
        ) -> UncheckedGarbledCircuit {
            garbled_circuit.get_partial(true, true).unwrap().into()
        }

        #[fixture]
        fn unchecked_garbled_output(
            #[default(&[(0, 0), (1, 0)])] inputs: &[(usize, u64)],
            garbled_circuit: GarbledCircuit<Full>,
        ) -> UncheckedOutput {
            let outputs = garbled_circuit.output_labels().get_groups().to_vec();
            let circ = garbled_circuit.circ;

            let input_values: Vec<_> = inputs
                .iter()
                .copied()
                .map(|(id, value)| circ.input(id).unwrap().to_value(value).unwrap())
                .collect();

            let output_values = circ.evaluate(&input_values).unwrap();

            UncheckedOutput {
                circ_id: circ.id().clone().to_string(),
                output_labels: output_labels
                    .into_iter()
                    .zip(&output_values)
                    .map(|(labels, value)| labels.select(value.value()).unwrap().into())
                    .collect(),
            }
        }

        #[fixture]
        fn unchecked_opening(garbled_circuit: GarbledCircuit<Full>) -> UncheckedCircuitOpening {
            garbled_circuit.open().into()
        }

        #[rstest]
        fn test_unchecked_garbled_circuit(
            unchecked_garbled_circuit: UncheckedGarbledCircuit,
            circ: Arc<Circuit>,
        ) {
            GarbledCircuit::from_unchecked(circ, unchecked_garbled_circuit).unwrap();
        }

        #[rstest]
        fn test_unchecked_garbled_circuit_wrong_id(
            mut unchecked_garbled_circuit: UncheckedGarbledCircuit,
            circ: Arc<Circuit>,
        ) {
            unchecked_garbled_circuit.id = AES_128.clone().id().clone().to_string();
            let err = GarbledCircuit::from_unchecked(circ, unchecked_garbled_circuit.clone())
                .unwrap_err();

            assert!(matches!(err, Error::ValidationError(_)));
        }

        #[rstest]
        fn test_unchecked_garbled_circuit_wrong_gate_count(
            mut unchecked_garbled_circuit: UncheckedGarbledCircuit,
            circ: Arc<Circuit>,
        ) {
            let circ = circ;
            unchecked_garbled_circuit
                .encrypted_gates
                .push(Block::new(0));
            let err =
                GarbledCircuit::from_unchecked(circ.clone(), unchecked_garbled_circuit.clone())
                    .unwrap_err();

            assert!(matches!(err, Error::ValidationError(_)));

            unchecked_garbled_circuit.encrypted_gates.pop();
            unchecked_garbled_circuit.encrypted_gates.pop();
            let err = GarbledCircuit::from_unchecked(circ, unchecked_garbled_circuit).unwrap_err();

            assert!(matches!(err, Error::ValidationError(_)));
        }

        #[rstest]
        fn test_unchecked_garbled_circuit_wrong_decoding_count(
            mut unchecked_garbled_circuit: UncheckedGarbledCircuit,
            circ: Arc<Circuit>,
        ) {
            let circ = circ;
            let dup = unchecked_garbled_circuit.decoding.as_ref().unwrap()[0].clone();
            unchecked_garbled_circuit
                .decoding
                .as_mut()
                .unwrap()
                .push(dup);

            let err =
                GarbledCircuit::from_unchecked(circ.clone(), unchecked_garbled_circuit.clone())
                    .unwrap_err();

            assert!(matches!(err, Error::ValidationError(_)));

            unchecked_garbled_circuit.decoding.as_mut().unwrap().pop();
            unchecked_garbled_circuit.decoding.as_mut().unwrap().pop();

            let err = GarbledCircuit::from_unchecked(circ, unchecked_garbled_circuit).unwrap_err();

            assert!(matches!(err, Error::ValidationError(_)));
        }

        #[rstest]
        fn test_unchecked_garbled_circuit_wrong_commitment_count(
            mut unchecked_garbled_circuit: UncheckedGarbledCircuit,
            circ: Arc<Circuit>,
        ) {
            let circ = circ;
            let dup = unchecked_garbled_circuit.commitments.as_ref().unwrap()[0].clone();
            unchecked_garbled_circuit
                .commitments
                .as_mut()
                .unwrap()
                .push(dup);

            let err =
                GarbledCircuit::from_unchecked(circ.clone(), unchecked_garbled_circuit.clone())
                    .unwrap_err();

            assert!(matches!(err, Error::ValidationError(_)));

            unchecked_garbled_circuit
                .commitments
                .as_mut()
                .unwrap()
                .pop();
            unchecked_garbled_circuit
                .commitments
                .as_mut()
                .unwrap()
                .pop();

            let err = GarbledCircuit::from_unchecked(circ, unchecked_garbled_circuit).unwrap_err();

            assert!(matches!(err, Error::ValidationError(_)));
        }

        #[rstest]
        fn test_unchecked_garbled_output(
            unchecked_garbled_output: UncheckedOutput,
            garbled_circuit: GarbledCircuit<Full>,
        ) {
            unchecked_garbled_output
                .decode(
                    &garbled_circuit.circ,
                    garbled_circuit.output_labels().get_groups(),
                )
                .unwrap();
        }

        #[rstest]
        fn test_unchecked_garbled_output_wrong_id(
            mut unchecked_garbled_output: UncheckedOutput,
            garbled_circuit: GarbledCircuit<Full>,
        ) {
            unchecked_garbled_output.circ_id = AES_128.clone().id().clone().to_string();
            let err = unchecked_garbled_output
                .decode(
                    &garbled_circuit.circ,
                    garbled_circuit.output_labels().get_groups(),
                )
                .unwrap_err();

            assert!(matches!(err, Error::ValidationError(_)));
        }

        #[rstest]
        fn test_unchecked_garbled_output_corrupt_label(
            mut unchecked_garbled_output: UncheckedOutput,
            garbled_circuit: GarbledCircuit<Full>,
        ) {
            unchecked_garbled_output.output_labels[0].labels[0] = Block::new(0);
            let err = unchecked_garbled_output
                .decode(
                    &garbled_circuit.circ,
                    garbled_circuit.output_labels().get_groups(),
                )
                .unwrap_err();

            assert!(matches!(err, Error::LabelError(_)));
        }

        #[rstest]
        fn test_unchecked_garbled_output_wrong_label_count(
            mut unchecked_garbled_output: UncheckedOutput,
            garbled_circuit: GarbledCircuit<Full>,
        ) {
            unchecked_garbled_output.output_labels[0].labels.pop();
            let err = unchecked_garbled_output
                .decode(
                    &garbled_circuit.circ,
                    garbled_circuit.output_labels().get_groups(),
                )
                .unwrap_err();

            assert!(matches!(err, Error::LabelError(_)));
        }

        #[rstest]
        fn test_unchecked_garbled_output_wrong_output_count(
            mut unchecked_garbled_output: UncheckedOutput,
            garbled_circuit: GarbledCircuit<Full>,
        ) {
            unchecked_garbled_output.output_labels.pop();
            let err = unchecked_garbled_output
                .decode(
                    &garbled_circuit.circ,
                    garbled_circuit.output_labels().get_groups(),
                )
                .unwrap_err();

            assert!(matches!(err, Error::ValidationError(_)));
        }

        #[rstest]
        fn test_unchecked_garbled_output_duplicates(
            mut unchecked_garbled_output: UncheckedOutput,
            garbled_circuit: GarbledCircuit<Full>,
        ) {
            let dup = unchecked_garbled_output.output_labels[0].clone();
            unchecked_garbled_output.output_labels.push(dup);
            let err = unchecked_garbled_output
                .decode(
                    &garbled_circuit.circ,
                    garbled_circuit.output_labels().get_groups(),
                )
                .unwrap_err();

            assert!(matches!(err, Error::ValidationError(_)));
        }

        #[rstest]
        fn test_unchecked_opening(circ: Arc<Circuit>, unchecked_opening: UncheckedCircuitOpening) {
            CircuitOpening::from_unchecked(&circ, unchecked_opening).unwrap();
        }

        #[rstest]
        fn test_unchecked_opening_wrong_decoding_count(
            circ: Arc<Circuit>,
            mut unchecked_opening: UncheckedCircuitOpening,
        ) {
            unchecked_opening.input_decoding.pop();
            let err = CircuitOpening::from_unchecked(&circ, unchecked_opening).unwrap_err();

            assert!(matches!(err, Error::InvalidOpening))
        }
    }
}

// #[cfg(test)]
// mod tests {
//     use aes::{Aes128, NewBlockCipher};
//     use mpc_circuits::{WireGroup, AES_128};
//     use rand_chacha::ChaCha12Rng;
//     use rand_core::SeedableRng;

//     use crate::{Label, LabelPair};

//     use super::*;

//     #[test]
//     fn test_circuit_validation_pass() {
//         let cipher = Aes128::new_from_slice(&[0u8; 16]).unwrap();
//         let mut rng = ChaCha12Rng::seed_from_u64(0);
//         let circ = AES_128.clone();

//         let key = circ.input(0).unwrap().to_value(vec![0u8; 16]).unwrap();
//         let msg = circ.input(1).unwrap().to_value(vec![0u8; 16]).unwrap();
//         let inputs = FullInputSet::generate(&mut rng, &circ, None);

//         let gc = GarbledCircuit::generate(&cipher, circ.clone(), input_labels.clone()).unwrap();
//         let opening = gc.open();

//         let key_labels = input_labels[0].select(key.value()).unwrap();
//         let msg_labels = input_labels[1].select(msg.value()).unwrap();

//         let partial_gc = gc.get_partial(true, false).unwrap();
//         let ev_gc = partial_gc
//             .evaluate(
//                 &cipher,
//                 ActiveInputSet::new(vec![key_labels, msg_labels]).unwrap(),
//             )
//             .unwrap();

//         ev_gc.validate(opening.clone()).unwrap();
//         ev_gc.into_compressed().validate(opening).unwrap();
//     }

//     #[test]
//     fn test_circuit_validation_fail_bad_gate() {
//         let cipher = Aes128::new_from_slice(&[0u8; 16]).unwrap();
//         let mut rng = ChaCha12Rng::seed_from_u64(0);
//         let circ = AES_128.clone();

//         let key = circ.input(0).unwrap().to_value(vec![0u8; 16]).unwrap();
//         let msg = circ.input(1).unwrap().to_value(vec![0u8; 16]).unwrap();
//         let inputs = FullInputSet::generate(&mut rng, &circ, None);

//         let mut gc = GarbledCircuit::generate(&cipher, circ.clone(), input_labels.clone()).unwrap();
//         let opening = gc.open();

//         // set bogus gate
//         gc.state.encrypted_gates[0].0[0] = Block::new(0);

//         let key_labels = input_labels[0].select(key.value()).unwrap();
//         let msg_labels = input_labels[1].select(msg.value()).unwrap();

//         let partial_gc = gc.get_partial(true, false).unwrap();
//         let ev_gc = partial_gc
//             .evaluate(
//                 &cipher,
//                 ActiveInputSet::new(vec![key_labels, msg_labels]).unwrap(),
//             )
//             .unwrap();

//         let err = ev_gc.validate(opening.clone()).unwrap_err();

//         assert!(matches!(err, Error::CorruptedGarbledCircuit));

//         let cmp_gc = ev_gc.into_compressed();

//         let err = cmp_gc.validate(opening).unwrap_err();

//         assert!(matches!(err, Error::CorruptedGarbledCircuit));
//     }

//     #[test]
//     fn test_circuit_validation_fail_bad_input_label() {
//         let cipher = Aes128::new_from_slice(&[0u8; 16]).unwrap();
//         let mut rng = ChaCha12Rng::seed_from_u64(0);
//         let circ = AES_128.clone();

//         let key = circ.input(0).unwrap().to_value(vec![0u8; 16]).unwrap();
//         let msg = circ.input(1).unwrap().to_value(vec![0u8; 16]).unwrap();
//         let mut input_labels = FullInputSet::generate(&mut rng, &circ, None);

//         let gc = GarbledCircuit::generate(&cipher, circ.clone(), input_labels.clone()).unwrap();
//         let opening = gc.open();

//         // set bogus label
//         input_labels[0].set(
//             0,
//             LabelPair::new(Label::new(Block::new(0)), Label::new(Block::new(0))),
//         );

//         let key_labels = input_labels[0].select(key.value()).unwrap();
//         let msg_labels = input_labels[1].select(msg.value()).unwrap();

//         let partial_gc = gc.get_partial(true, false).unwrap();
//         let ev_gc = partial_gc
//             .evaluate(
//                 &cipher,
//                 ActiveInputSet::new(vec![key_labels, msg_labels]).unwrap(),
//             )
//             .unwrap();

//         let err = ev_gc.validate(opening.clone()).unwrap_err();

//         assert!(matches!(err, Error::CorruptedGarbledCircuit));

//         let cmp_gc = ev_gc.into_compressed();

//         let err = cmp_gc.validate(opening).unwrap_err();

//         assert!(matches!(err, Error::CorruptedGarbledCircuit));
//     }

//     #[test]
//     /// The Generator sends invalid output label decoding info which causes the evaluator to
//     /// derive incorrect output. Testing that this will be detected during validation.
//     fn test_circuit_validation_fail_bad_output_decoding() {
//         let cipher = Aes128::new_from_slice(&[0u8; 16]).unwrap();
//         let mut rng = ChaCha12Rng::seed_from_u64(0);
//         let circ = AES_128.clone();

//         let key = circ.input(0).unwrap().to_value(vec![0u8; 16]).unwrap();
//         let msg = circ.input(1).unwrap().to_value(vec![0u8; 16]).unwrap();
//         let inputs = FullInputSet::generate(&mut rng, &circ, None);

//         let mut gc = GarbledCircuit::generate(&cipher, circ.clone(), input_labels.clone()).unwrap();
//         let opening = gc.open();

//         // Flip output labels. This will cause the generator to compute
//         // corrupted decoding info.
//         gc.state.output_labels[0].flip(0);

//         let key_labels = input_labels[0].select(key.value()).unwrap();
//         let msg_labels = input_labels[1].select(msg.value()).unwrap();

//         let partial_gc = gc.get_partial(true, true).unwrap();

//         let ev_gc = partial_gc
//             .evaluate(
//                 &cipher,
//                 ActiveInputSet::new(vec![key_labels, msg_labels]).unwrap(),
//             )
//             .unwrap();

//         let err = ev_gc.validate(opening.clone()).unwrap_err();

//         assert!(matches!(err, Error::CorruptedGarbledCircuit));

//         let cmp_gc = ev_gc.into_compressed();

//         let err = cmp_gc.validate(opening).unwrap_err();

//         assert!(matches!(err, Error::CorruptedGarbledCircuit));
//     }

//     #[test]
//     fn test_circuit_validation_fail_bad_output_commitment() {
//         let cipher = Aes128::new_from_slice(&[0u8; 16]).unwrap();
//         let mut rng = ChaCha12Rng::seed_from_u64(0);
//         let circ = AES_128.clone();

//         let key = circ.input(0).unwrap().to_value(vec![0u8; 16]).unwrap();
//         let msg = circ.input(1).unwrap().to_value(vec![0u8; 16]).unwrap();
//         let mut input_labels = FullInputSet::generate(&mut rng, &circ, None);

//         let gc = GarbledCircuit::generate(&cipher, circ.clone(), input_labels.clone()).unwrap();
//         let opening = gc.open();

//         // set bogus label (the opposite label the evaluator receives)
//         // evaluation should pass but the circuit validation should fail because the commitment is bad
//         let target_label = input_labels[0].get(0);
//         input_labels[0].set(
//             0,
//             LabelPair::new(target_label.low(), Label::new(Block::new(0))),
//         );

//         let key_labels = input_labels[0].select(key.value()).unwrap();
//         let msg_labels = input_labels[1].select(msg.value()).unwrap();

//         let partial_gc = gc.get_partial(true, true).unwrap();
//         let ev_gc = partial_gc
//             .evaluate(
//                 &cipher,
//                 ActiveInputSet::new(vec![key_labels, msg_labels]).unwrap(),
//             )
//             .unwrap();

//         let err = ev_gc.validate(opening.clone()).unwrap_err();

//         assert!(matches!(err, Error::CorruptedGarbledCircuit));

//         let cmp_gc = ev_gc.into_compressed();

//         let err = cmp_gc.validate(opening).unwrap_err();

//         assert!(matches!(err, Error::CorruptedGarbledCircuit));
//     }
// }

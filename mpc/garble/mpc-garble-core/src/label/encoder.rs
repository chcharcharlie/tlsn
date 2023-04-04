use std::collections::HashMap;

use mpc_circuits::types::{BinaryLength, ValueType};
use mpc_core::Block;
use rand::{CryptoRng, RngCore, SeedableRng};
use rand_chacha::ChaCha20Rng;

use super::{state, value::Encode, Delta, EncodedValue, Label};

const DELTA_STREAM_ID: u64 = u64::MAX;
const PADDING_STREAM_ID: u64 = u64::MAX - 1;

pub trait EncoderRng: RngCore + CryptoRng {}

impl<T> EncoderRng for T where T: RngCore + CryptoRng {}

/// This trait is used to encode wire labels using a global offset (delta).
///
/// Implementations of this trait *must* preserve the state of each stream between
/// calls to `encode`. This is required to ensure that duplicate labels are never
/// generated.
pub trait Encoder: Send + Sync {
    /// Returns encoder's rng seed
    fn get_seed(&self) -> Vec<u8>;

    /// Returns encoder's global offset
    fn get_delta(&self) -> Delta;

    /// Encodes a type using the provided stream id
    ///
    /// * `stream_id` - Stream id
    fn encode<T: Encode + BinaryLength>(&mut self, stream_id: u32) -> T::Encoded;

    /// Encodes a type using the provided stream id
    ///
    /// * `stream_id` - Stream id
    /// * `ty` - Type of value
    fn encode_by_type(&mut self, stream_id: u32, ty: ValueType) -> EncodedValue<state::Full>;

    /// Encodes an array using the provided stream id
    ///
    /// * `stream_id` - Stream id
    fn encode_array<T: Encode + BinaryLength, const N: usize>(
        &mut self,
        stream_id: u32,
    ) -> [T::Encoded; N];

    /// Encodes a vector using the provided stream id
    ///
    /// * `stream_id` - Stream id
    /// * `len` - Length of vector
    /// * `pad` - Number of padding values to generate
    fn encode_vec<T: Encode + BinaryLength>(
        &mut self,
        stream_id: u32,
        len: usize,
        pad: usize,
    ) -> Vec<T::Encoded>;

    /// Returns a mutable reference to the encoder's rng stream
    ///
    /// * `stream_id` - Stream id
    fn get_stream(&mut self, stream_id: u32) -> &mut dyn EncoderRng;
}

/// Encodes wires into labels using the ChaCha algorithm.
#[derive(Debug)]
pub struct ChaChaEncoder {
    seed: [u8; 32],
    rng: ChaCha20Rng,
    stream_state: HashMap<u64, u128>,
    delta: Delta,
}

impl ChaChaEncoder {
    /// Creates a new encoder with the provided seed
    ///
    /// * `seed` - 32-byte seed for ChaChaRng
    /// * `bit_order` - Bit order of labels generated from stream
    pub fn new(seed: [u8; 32]) -> Self {
        let mut rng = ChaCha20Rng::from_seed(seed);

        // Stream id u64::MAX is reserved to generate delta.
        // This way there is only ever 1 delta per seed
        rng.set_stream(DELTA_STREAM_ID);
        let delta = Delta::random(&mut rng);

        Self {
            seed,
            rng,
            stream_state: HashMap::default(),
            delta,
        }
    }

    /// Sets the selected stream id, restoring word position if a stream
    /// has been used before.
    ///
    /// * `id` - Stream id
    fn set_stream(&mut self, id: u64) {
        let current_id = self.rng.get_stream();

        // noop if stream already set
        if id == current_id {
            return;
        }

        // Store word position for current stream
        self.stream_state
            .insert(current_id, self.rng.get_word_pos());

        // Update stream id
        self.rng.set_stream(id);

        // Get word position if stored, otherwise default to 0
        let word_pos = self.stream_state.get(&id).copied().unwrap_or(0);

        // Update word position
        self.rng.set_word_pos(word_pos);
    }
}

impl Encoder for ChaChaEncoder {
    fn get_seed(&self) -> Vec<u8> {
        self.seed.to_vec()
    }

    fn get_delta(&self) -> Delta {
        self.delta
    }

    fn encode<T: Encode + BinaryLength>(&mut self, stream_id: u32) -> T::Encoded {
        self.set_stream(stream_id as u64);

        let labels = Block::random_vec(&mut self.rng, T::LEN)
            .into_iter()
            .map(|block| Label::new(block))
            .collect::<Vec<_>>();

        T::encode(self.delta, &labels).expect("encoding should not fail")
    }

    fn encode_by_type(&mut self, stream_id: u32, ty: ValueType) -> EncodedValue<state::Full> {
        match ty {
            ValueType::Bit => self.encode::<bool>(stream_id).into(),
            ValueType::U8 => self.encode::<u8>(stream_id).into(),
            ValueType::U16 => self.encode::<u16>(stream_id).into(),
            ValueType::U32 => self.encode::<u32>(stream_id).into(),
            ValueType::U64 => self.encode::<u64>(stream_id).into(),
            ValueType::U128 => self.encode::<u128>(stream_id).into(),
            ValueType::Array(ty, len) => EncodedValue::Array(
                (0..len)
                    .map(|_| self.encode_by_type(stream_id, *ty.clone()))
                    .collect(),
            ),
            _ => unimplemented!("encoding of type {:?} is not implemented", ty),
        }
    }

    fn encode_array<T: Encode + BinaryLength, const N: usize>(
        &mut self,
        stream_id: u32,
    ) -> [T::Encoded; N] {
        self.set_stream(stream_id as u64);

        std::array::from_fn(|_| {
            T::encode(
                self.delta,
                &Block::random_vec(&mut self.rng, T::LEN)
                    .into_iter()
                    .map(Label::new)
                    .collect::<Vec<_>>(),
            )
            .expect("encoding should not fail")
        })
    }

    fn encode_vec<T: Encode + BinaryLength>(
        &mut self,
        stream_id: u32,
        len: usize,
        pad: usize,
    ) -> Vec<T::Encoded> {
        self.set_stream(stream_id as u64);

        let left = (0..len)
            .map(|_| {
                T::encode(
                    self.delta,
                    &Block::random_vec(&mut self.rng, T::LEN)
                        .into_iter()
                        .map(Label::new)
                        .collect::<Vec<_>>(),
                )
                .expect("encoding should not fail")
            })
            .collect::<Vec<_>>();

        self.set_stream(PADDING_STREAM_ID);

        let right = (0..pad)
            .map(|_| {
                T::encode(
                    self.delta,
                    &Block::random_vec(&mut self.rng, T::LEN)
                        .into_iter()
                        .map(Label::new)
                        .collect::<Vec<_>>(),
                )
                .expect("encoding should not fail")
            })
            .collect::<Vec<_>>();

        left.into_iter().chain(right).collect()
    }

    fn get_stream(&mut self, stream_id: u32) -> &mut dyn EncoderRng {
        self.set_stream(stream_id as u64);
        &mut self.rng
    }
}

#[cfg(test)]
mod test {
    use crate::label::{state, EncodedValue};
    use mpc_circuits::types::Value;
    use std::marker::PhantomData;

    use super::*;
    use rstest::*;

    #[rstest]
    #[case::bit(PhantomData::<bool>)]
    #[case::u8(PhantomData::<u8>)]
    #[case::u16(PhantomData::<u16>)]
    #[case::u32(PhantomData::<u32>)]
    #[case::u64(PhantomData::<u64>)]
    #[case::u128(PhantomData::<u128>)]
    fn test_encoder<T: Encode + BinaryLength + Default>(#[case] _pd: PhantomData<T>)
    where
        T: Into<Value>,
        T::Encoded: Into<EncodedValue<state::Full>>,
    {
        let mut encoder = ChaChaEncoder::new([0u8; 32]);

        let encoded: EncodedValue<_> = encoder.encode::<T>(0).into();
        let decoding = encoded.decoding();
        let commit = encoded.commit();
        let active = encoded.select(T::default()).unwrap();
        commit.verify(&active).unwrap();
        let value = active.decode(&decoding).unwrap();

        assert_eq!(value, T::default().into());
    }

    #[rstest]
    #[case::bit(PhantomData::<bool>)]
    #[case::u8(PhantomData::<u8>)]
    #[case::u16(PhantomData::<u16>)]
    #[case::u32(PhantomData::<u32>)]
    #[case::u64(PhantomData::<u64>)]
    #[case::u128(PhantomData::<u128>)]
    fn test_encoder_array<T: Encode + BinaryLength + Default>(#[case] _pd: PhantomData<T>)
    where
        [T; 16]: Into<Value>,
        [T::Encoded; 16]: Into<EncodedValue<state::Full>>,
    {
        let mut encoder = ChaChaEncoder::new([0u8; 32]);

        let encoded: EncodedValue<_> = encoder.encode_array::<T, 16>(0).into();
        let decoding = encoded.decoding();
        let commit = encoded.commit();
        let active = encoded
            .select(std::array::from_fn::<_, 16, _>(|_| T::default()))
            .unwrap();
        commit.verify(&active).unwrap();
        let value = active.decode(&decoding).unwrap();

        assert_eq!(
            value,
            std::array::from_fn::<_, 16, _>(|_| T::default()).into()
        );
    }
}

// #[cfg(test)]
// mod test {
//     use std::sync::Arc;

//     use super::*;
//     use rstest::*;

//     #[rstest]
//     #[case::u8(ValueType::U8, 8)]
//     #[case::u16(ValueType::U16, 16)]
//     #[case::u32(ValueType::U32, 32)]
//     #[case::u64(ValueType::U64, 64)]
//     #[case::u128(ValueType::U128, 128)]
//     #[case::bytes(ValueType::Bytes, 32)]
//     fn test_encoder_bit_order(#[case] value_type: ValueType, #[case] len: usize) {
//         let mut enc = ChaChaEncoder::new([0u8; 32], BitOrder::Msb0);

//         let group = TestGroup {
//             len,
//             bit_order: BitOrder::Msb0,
//             value_type,
//         };

//         let encoded_0 = enc.encode(0, &group);

//         let mut enc = ChaChaEncoder::new([0u8; 32], BitOrder::Lsb0);

//         let encoded_1 = enc.encode(0, &group);

//         let encoded_0 = encoded_0.iter().collect::<Vec<_>>();
//         let mut encoded_1 = encoded_1.iter().collect::<Vec<_>>();

//         match value_type {
//             ValueType::Bytes => {
//                 encoded_1
//                     .chunks_exact_mut(8)
//                     .for_each(|byte| byte.reverse());
//             }
//             _ => encoded_1.reverse(),
//         }

//         assert_eq!(encoded_0, encoded_1)
//     }

//     #[rstest]
//     fn test_encoder_pad_bytes_msb0() {
//         let mut enc = ChaChaEncoder::new([0u8; 32], BitOrder::Msb0);

//         let group = TestGroup {
//             len: 64,
//             bit_order: BitOrder::Msb0,
//             value_type: ValueType::Bytes,
//         };

//         let encoded_0 = enc.encode_padded(0, &group, 32);
//         let encoded_1 = enc.encode_padded(0, &group, 32);

//         let mut enc = ChaChaEncoder::new([0u8; 32], BitOrder::Msb0);

//         let group2 = TestGroup {
//             len: 32,
//             bit_order: BitOrder::Msb0,
//             value_type: ValueType::Bytes,
//         };

//         let encoded_2 = enc.encode(0, &group2);
//         let encoded_3 = enc.encode(0, &group2);

//         let labels_0 = encoded_0.iter().collect::<Vec<_>>();
//         let labels_1 = encoded_1.iter().collect::<Vec<_>>();
//         let labels_2 = encoded_2.iter().collect::<Vec<_>>();
//         let labels_3 = encoded_3.iter().collect::<Vec<_>>();

//         assert_eq!(labels_0[..32], labels_2[..]);
//         assert_eq!(labels_1[..32], labels_3[..]);
//     }

//     #[rstest]
//     fn test_encoder_pad_bytes_lsb0() {
//         let mut enc = ChaChaEncoder::new([0u8; 32], BitOrder::Lsb0);

//         let group = TestGroup {
//             len: 64,
//             bit_order: BitOrder::Lsb0,
//             value_type: ValueType::Bytes,
//         };

//         let encoded_0 = enc.encode_padded(0, &group, 32);
//         let encoded_1 = enc.encode_padded(0, &group, 32);

//         let mut enc = ChaChaEncoder::new([0u8; 32], BitOrder::Lsb0);

//         let group2 = TestGroup {
//             len: 32,
//             bit_order: BitOrder::Lsb0,
//             value_type: ValueType::Bytes,
//         };

//         let encoded_2 = enc.encode(0, &group2);
//         let encoded_3 = enc.encode(0, &group2);

//         let labels_0 = encoded_0.iter().collect::<Vec<_>>();
//         let labels_1 = encoded_1.iter().collect::<Vec<_>>();
//         let labels_2 = encoded_2.iter().collect::<Vec<_>>();
//         let labels_3 = encoded_3.iter().collect::<Vec<_>>();

//         assert_eq!(labels_0[32..], labels_2[..]);
//         assert_eq!(labels_1[32..], labels_3[..]);
//     }

//     #[rstest]
//     fn test_encoder_no_duplicates() {
//         let group = TestGroup {
//             len: 64,
//             bit_order: BitOrder::Msb0,
//             value_type: ValueType::Bytes,
//         };

//         let mut enc = ChaChaEncoder::new([0u8; 32], BitOrder::Msb0);

//         // Pull from stream 0
//         let a = enc.encode(0, &group);

//         // Pull from a different stream
//         let c = enc.encode(1, &group);

//         // Pull from stream 0 again
//         let b = enc.encode(0, &group);

//         // Switching back to the same stream should preserve the word position
//         assert_ne!(a, b);
//         // Different stream ids should produce different labels
//         assert_ne!(a, c);
//     }
// }

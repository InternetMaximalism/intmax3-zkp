/*
The MIT License (MIT)

Copyright (c) 2023 Succinct Labs

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in
all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
THE SOFTWARE.
 */

use core::fmt;
use std::{error::Error, marker::PhantomData};

use ff::{Field as ff_Field, PrimeField};
use num::BigUint;
use plonky2::{
    field::{
        extension::quadratic::QuadraticExtension, goldilocks_field::GoldilocksField, types::Field,
    },
    hash::{
        hash_types::RichField,
        poseidon::{PoseidonHash, PoseidonPermutation},
    },
    plonk::config::{GenericConfig, GenericHashOut, Hasher},
};
use serde::{Deserialize, Deserializer, Serialize, Serializer, de::Visitor};

use crate::wrapper_config::{
    poseidon_bn128::{GOLDILOCKS_ELEMENTS, RATE, permution},
    utils::{Fr, FrRepr},
};

/// Configuration using Poseidon BN128 over the Goldilocks field.
#[derive(Debug, Copy, Clone, Eq, PartialEq, Serialize)]
pub struct PoseidonBN128GoldilocksConfig;
impl GenericConfig<2> for PoseidonBN128GoldilocksConfig {
    type F = GoldilocksField;
    type FE = QuadraticExtension<Self::F>;
    type Hasher = PoseidonBN128Hash;
    type InnerHasher = PoseidonHash;
}

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct PoseidonBN128HashOut<F: Field> {
    pub value: Fr,
    _phantom: PhantomData<F>,
}

fn hash_out_to_bytes<F: Field>(hash: PoseidonBN128HashOut<F>) -> Vec<u8> {
    let binding = hash.value.to_repr();
    let limbs = binding.as_ref();
    limbs.to_vec()
}

/// Why a BN128 hash could not be decoded (review C08, 2026-10-16). Every variant used to be an
/// `unwrap()` panic, which on a `panic = "abort"` native build terminates the process that
/// deserializes untrusted proof/fixture material.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BN128HashDecodeError {
    /// The byte string is not exactly 32 bytes.
    WrongLength(usize),
    /// The decimal string is not a base-10 integer.
    NotDecimal,
    /// The integer does not fit in 32 little-endian bytes.
    TooLarge,
    /// The 32-byte value is not a canonical scalar (`>= r`).
    NonCanonical,
}

impl fmt::Display for BN128HashDecodeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::WrongLength(n) => write!(f, "BN128 hash must be 32 bytes, got {n}"),
            Self::NotDecimal => write!(f, "BN128 hash must be a base-10 integer string"),
            Self::TooLarge => write!(f, "BN128 hash integer does not fit in 32 bytes"),
            Self::NonCanonical => write!(f, "BN128 hash is not a canonical scalar (>= r)"),
        }
    }
}

impl std::error::Error for BN128HashDecodeError {}

impl<F: RichField> PoseidonBN128HashOut<F> {
    /// Fallible decoding of a 32-byte little-endian canonical scalar (review C08).
    pub fn try_from_bytes(bytes: &[u8]) -> Result<Self, BN128HashDecodeError> {
        let sized_bytes: [u8; 32] = bytes
            .try_into()
            .map_err(|_| BN128HashDecodeError::WrongLength(bytes.len()))?;
        let fr_repr = FrRepr(sized_bytes);
        // `from_repr` yields an empty `CtOption` for a non-canonical representation (>= r).
        let fr = Option::<Fr>::from(Fr::from_repr(fr_repr)).ok_or(BN128HashDecodeError::NonCanonical)?;
        Ok(Self {
            value: fr,
            _phantom: PhantomData,
        })
    }

    /// Fallible decoding of the base-10 string form `Serialize` emits (review C08).
    pub fn try_from_decimal_str(s: &str) -> Result<Self, BN128HashDecodeError> {
        let big_int = BigUint::parse_bytes(s.as_bytes(), 10).ok_or(BN128HashDecodeError::NotDecimal)?;
        let mut bytes = big_int.to_bytes_le();
        if bytes.len() > 32 {
            return Err(BN128HashDecodeError::TooLarge);
        }
        bytes.resize(32, 0);
        Self::try_from_bytes(&bytes)
    }
}

impl<F: RichField> GenericHashOut<F> for PoseidonBN128HashOut<F> {
    fn to_bytes(&self) -> Vec<u8> {
        hash_out_to_bytes(*self)
    }

    /// The trait method is infallible by signature. Callers decoding UNTRUSTED bytes must use
    /// [`PoseidonBN128HashOut::try_from_bytes`] first; this method panics with a named reason on
    /// a wrong length or a non-canonical scalar (review C08).
    fn from_bytes(bytes: &[u8]) -> Self {
        match Self::try_from_bytes(bytes) {
            Ok(hash) => hash,
            Err(e) => panic!("PoseidonBN128HashOut::from_bytes on invalid input: {e}"),
        }
    }

    fn to_vec(&self) -> Vec<F> {
        let bytes = hash_out_to_bytes(*self);
        bytes
            // Chunks of 7 bytes since 8 bytes would allow collisions.
            .chunks(7)
            .map(|bytes| {
                let mut arr = [0; 8];
                arr[..bytes.len()].copy_from_slice(bytes);
                F::from_canonical_u64(u64::from_le_bytes(arr))
            })
            .collect()
    }
}

impl<F: RichField> Serialize for PoseidonBN128HashOut<F> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        // Output the hash as a bigint string.
        let binding = self.value.to_repr();
        let limbs = binding.as_ref();

        let big_int = BigUint::from_bytes_le(limbs);
        serializer.serialize_str(big_int.to_str_radix(10).as_str())
    }
}

impl<'de, F: RichField> Deserialize<'de> for PoseidonBN128HashOut<F> {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct PoseidonBN128HashOutVisitor;

        impl Visitor<'_> for PoseidonBN128HashOutVisitor {
            type Value = String;

            fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
                formatter.write_str("a string with integer value within BN128 scalar field")
            }

            fn visit_str<E>(self, v: &str) -> Result<Self::Value, E>
            where
                E: Error,
            {
                Ok(v.to_string())
            }
        }

        // Review C08: every failure is reported through serde instead of panicking — a wrong
        // JSON type, a non-decimal string, an integer wider than 32 bytes, or a value >= r.
        let deserialized_str = deserializer.deserialize_str(PoseidonBN128HashOutVisitor)?;
        Self::try_from_decimal_str(&deserialized_str).map_err(serde::de::Error::custom)
    }
}

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct PoseidonBN128Hash;
impl<F: RichField> Hasher<F> for PoseidonBN128Hash {
    const HASH_SIZE: usize = 32; // Hash output is 4 limbs of u64
    type Hash = PoseidonBN128HashOut<F>;
    type Permutation = PoseidonPermutation<F>;

    fn hash_no_pad(input: &[F]) -> Self::Hash {
        let mut state = [Fr::ZERO; 4];

        state[0] = Fr::ZERO;
        for rate_chunk in input.chunks(RATE * 3) {
            for (j, bn128_chunk) in rate_chunk.chunks(3).enumerate() {
                let mut bytes = bn128_chunk[0].to_canonical_u64().to_le_bytes().to_vec();

                for gl_element in bn128_chunk.iter().skip(1) {
                    let chunk_bytes = gl_element.to_canonical_u64().to_le_bytes();
                    bytes.extend_from_slice(&chunk_bytes);
                }

                for _i in bytes.len()..32 {
                    bytes.push(0);
                }

                let sized_bytes: [u8; 32] = bytes.try_into().unwrap();
                let fr_repr = FrRepr(sized_bytes);
                state[j + 1] = Fr::from_repr(fr_repr).unwrap();
            }
            permution(&mut state);
        }

        PoseidonBN128HashOut {
            value: state[0],
            _phantom: PhantomData,
        }
    }

    fn hash_pad(input: &[F]) -> Self::Hash {
        let mut padded_input = input.to_vec();
        padded_input.push(F::ONE);
        while (padded_input.len() + 1) % (RATE * GOLDILOCKS_ELEMENTS) != 0 {
            padded_input.push(F::ZERO);
        }
        padded_input.push(F::ONE);
        Self::hash_no_pad(&padded_input)
    }

    fn hash_or_noop(inputs: &[F]) -> Self::Hash {
        if inputs.len() * 8 <= GOLDILOCKS_ELEMENTS * 8 {
            let mut inputs_bytes = vec![0u8; 32];
            for i in 0..inputs.len() {
                inputs_bytes[i * 8..(i + 1) * 8]
                    .copy_from_slice(&inputs[i].to_canonical_u64().to_le_bytes());
            }
            Self::Hash::from_bytes(&inputs_bytes)
        } else {
            Self::hash_no_pad(inputs)
        }
    }

    fn two_to_one(left: Self::Hash, right: Self::Hash) -> Self::Hash {
        let mut state = [Fr::ZERO, Fr::ZERO, left.value, right.value];
        permution(&mut state);

        PoseidonBN128HashOut {
            value: state[0],
            _phantom: PhantomData,
        }
    }
}

#[cfg(test)]
pub mod tests {
    use super::*;

    const BN254_SCALAR_MODULUS: &str =
        "21888242871839275222246405745257275088548364400416034343698204186575808495617";
    const BN254_SCALAR_MODULUS_MINUS_ONE: &str =
        "21888242871839275222246405745257275088548364400416034343698204186575808495616";

    /// Review C08 (2026-10-16): every malformed encoding is an ordinary error. Before the fix the
    /// four invalid cases below panicked inside `Deserialize` / `from_bytes`.
    #[test]
    fn invalid_bn128_hash_encodings_are_errors_not_panics() {
        type H = PoseidonBN128HashOut<GoldilocksField>;
        // Valid boundary values round-trip through the decimal form.
        for s in ["0", BN254_SCALAR_MODULUS_MINUS_ONE] {
            let hash: H = serde_json::from_str(&format!("\"{s}\"")).expect("canonical value decodes");
            let again: H = serde_json::from_str(&serde_json::to_string(&hash).unwrap()).unwrap();
            assert_eq!(hash, again);
        }
        // A JSON integer instead of a string.
        assert!(serde_json::from_str::<H>("7").is_err());
        // A non-decimal string.
        assert!(serde_json::from_str::<H>("\"0x1f\"").is_err());
        // Exactly the modulus: 32 bytes but not canonical.
        assert_eq!(
            H::try_from_decimal_str(BN254_SCALAR_MODULUS),
            Err(BN128HashDecodeError::NonCanonical)
        );
        assert!(serde_json::from_str::<H>(&format!("\"{BN254_SCALAR_MODULUS}\"")).is_err());
        // Wider than 32 bytes.
        assert_eq!(
            H::try_from_decimal_str(&format!("{BN254_SCALAR_MODULUS}000")),
            Err(BN128HashDecodeError::TooLarge)
        );
        // Binary: all-0xff is non-canonical; a short slice is the wrong length.
        assert_eq!(H::try_from_bytes(&[0xffu8; 32]), Err(BN128HashDecodeError::NonCanonical));
        assert_eq!(H::try_from_bytes(&[0u8; 31]), Err(BN128HashDecodeError::WrongLength(31)));
        assert!(H::try_from_bytes(&[0u8; 32]).is_ok());
    }

    #[test]
    fn test_byte_methods() {
        type F = GoldilocksField;

        let fr = Fr::from_str_vartime(
            "11575173631114898451293296430061690731976535592475236587664058405912382527658",
        )
        .unwrap();
        let hash = PoseidonBN128HashOut::<F> {
            value: fr,
            _phantom: PhantomData,
        };

        let bytes = hash.to_bytes();

        let hash_from_bytes = PoseidonBN128HashOut::<F>::from_bytes(&bytes);
        assert_eq!(hash, hash_from_bytes);
    }

    #[test]
    fn test_serialization() {
        let fr = Fr::from_str_vartime(
            "11575173631114898451293296430061690731976535592475236587664058405912382527658",
        )
        .unwrap();
        let hash = PoseidonBN128HashOut::<GoldilocksField> {
            value: fr,
            _phantom: PhantomData,
        };

        let serialized = serde_json::to_string(&hash).unwrap();
        let deserialized: PoseidonBN128HashOut<GoldilocksField> =
            serde_json::from_str(&serialized).unwrap();
        assert_eq!(hash, deserialized);
    }
}

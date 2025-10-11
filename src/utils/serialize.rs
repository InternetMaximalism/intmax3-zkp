use std::marker::PhantomData;

use crate::utils::error::{Result, SerializeError};
use plonky2::{
    field::extension::Extendable,
    gadgets::{
        arithmetic::EqualityGenerator,
        arithmetic_extension::QuotientGeneratorExtension,
        range_check::LowHighGenerator,
        split_base::BaseSumGenerator,
        split_join::{SplitGenerator, WireSplitGenerator},
    },
    gates::{
        arithmetic_base::{ArithmeticBaseGenerator, ArithmeticGate},
        arithmetic_extension::{ArithmeticExtensionGate, ArithmeticExtensionGenerator},
        base_sum::{BaseSplitGenerator, BaseSumGate},
        constant::ConstantGate,
        coset_interpolation::{CosetInterpolationGate, InterpolationGenerator},
        exponentiation::{ExponentiationGate, ExponentiationGenerator},
        lookup::{LookupGate, LookupGenerator},
        lookup_table::{LookupTableGate, LookupTableGenerator},
        multiplication_extension::{MulExtensionGate, MulExtensionGenerator},
        noop::NoopGate,
        poseidon::{PoseidonGate, PoseidonGenerator},
        poseidon_mds::{PoseidonMdsGate, PoseidonMdsGenerator},
        public_input::PublicInputGate,
        random_access::{RandomAccessGate, RandomAccessGenerator},
        reducing::{ReducingGate, ReducingGenerator},
        reducing_extension::{
            ReducingExtensionGate, ReducingGenerator as ReducingExtensionGenerator,
        },
    },
    get_gate_tag_impl, get_generator_tag_impl,
    hash::hash_types::RichField,
    impl_gate_serializer, impl_generator_serializer,
    iop::generator::{
        ConstantGenerator, CopyGenerator, NonzeroTestGenerator, RandomValueGenerator,
    },
    plonk::{
        circuit_data::VerifierCircuitData,
        config::{AlgebraicHasher, GenericConfig},
    },
    read_gate_impl, read_generator_impl,
    recursion::dummy_circuit::DummyProofGenerator,
    util::serialization::{GateSerializer, WitnessGeneratorSerializer},
};
use plonky2_u32::gates::{
    add_many_u32::{U32AddManyGate, U32AddManyGenerator},
    comparison::{ComparisonGate, ComparisonGenerator},
    subtraction_u32::{U32SubtractionGate, U32SubtractionGenerator},
};

#[derive(Debug)]
pub struct AllGateSerializer;
impl<F: RichField + Extendable<D>, const D: usize> GateSerializer<F, D> for AllGateSerializer {
    impl_gate_serializer! {
        DefaultGateSerializer,
        ArithmeticGate,
        ArithmeticExtensionGate<D>,
        BaseSumGate<2>,
        ConstantGate,
        CosetInterpolationGate<F, D>,
        ExponentiationGate<F, D>,
        LookupGate,
        LookupTableGate,
        MulExtensionGate<D>,
        NoopGate,
        PoseidonMdsGate<F, D>,
        PoseidonGate<F, D>,
        PublicInputGate,
        RandomAccessGate<F, D>,
        ReducingExtensionGate<D>,
        ReducingGate<D>,
        ComparisonGate<F, D>,
        U32AddManyGate<F, D>,
        U32SubtractionGate<F, D>
    }
}

#[derive(Debug)]
pub struct AllGeneratorSerializer<C: GenericConfig<D>, const D: usize> {
    pub _phantom: PhantomData<C>,
}

impl<C: GenericConfig<D>, const D: usize> Default for AllGeneratorSerializer<C, D> {
    fn default() -> Self {
        Self {
            _phantom: PhantomData,
        }
    }
}

impl<F, C, const D: usize> WitnessGeneratorSerializer<F, D> for AllGeneratorSerializer<C, D>
where
    F: RichField + Extendable<D>,
    C: GenericConfig<D, F = F> + 'static,
    C::Hasher: AlgebraicHasher<F>,
{
    impl_generator_serializer! {
        DefaultGeneratorSerializer,
        ArithmeticBaseGenerator<F, D>,
        ArithmeticExtensionGenerator<F, D>,
        BaseSplitGenerator<2>,
        BaseSumGenerator<2>,
        ConstantGenerator<F>,
        CopyGenerator,
        DummyProofGenerator<F, C, D>,
        EqualityGenerator,
        ExponentiationGenerator<F, D>,
        InterpolationGenerator<F, D>,
        LookupGenerator,
        LookupTableGenerator,
        LowHighGenerator,
        MulExtensionGenerator<F, D>,
        NonzeroTestGenerator,
        PoseidonGenerator<F, D>,
        PoseidonMdsGenerator<D>,
        QuotientGeneratorExtension<D>,
        RandomAccessGenerator<F, D>,
        RandomValueGenerator,
        ReducingGenerator<D>,
        ReducingExtensionGenerator<D>,
        SplitGenerator,
        WireSplitGenerator,
        ComparisonGenerator<F, D>,
        U32AddManyGenerator<F, D>,
        U32SubtractionGenerator<F, D>
    }
}

pub fn serialize_verifier_data<F, C, const D: usize>(
    circuit_data: &VerifierCircuitData<F, C, D>,
) -> Result<Vec<u8>>
where
    F: RichField + Extendable<D>,
    C: GenericConfig<D, F = F>,
{
    let gate_serializer = AllGateSerializer;
    let bytes = circuit_data
        .to_bytes(&gate_serializer)
        .map_err(|e| SerializeError::SerializationFailed(e.to_string()))?;
    Ok(bytes)
}

pub fn deserialize_verifier_data<F, C, const D: usize>(
    bytes: &[u8],
) -> Result<VerifierCircuitData<F, C, D>>
where
    F: RichField + Extendable<D>,
    C: GenericConfig<D, F = F>,
{
    let gate_serializer = AllGateSerializer;
    let circuit_data = VerifierCircuitData::from_bytes(bytes.to_vec(), &gate_serializer)
        .map_err(|e| SerializeError::DeserializationFailed(e.to_string()))?;
    Ok(circuit_data)
}

#[derive(Debug, thiserror::Error)]
pub enum CircuitSerializationError {
    #[error("failed to serialize {context}: {detail}")]
    Serialization {
        context: &'static str,
        detail: String,
    },

    #[error("failed to deserialize {context}: {detail}")]
    Deserialization {
        context: &'static str,
        detail: String,
    },
}

impl CircuitSerializationError {
    pub fn serialization(context: &'static str, error: impl ToString) -> Self {
        Self::Serialization {
            context,
            detail: error.to_string(),
        }
    }

    pub fn deserialization(context: &'static str, error: impl ToString) -> Self {
        Self::Deserialization {
            context,
            detail: error.to_string(),
        }
    }
}

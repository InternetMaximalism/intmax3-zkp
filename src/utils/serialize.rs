use crate::utils::error::{Result, SerializeError};
use plonky2::{
    field::extension::Extendable,
    gates::{
        arithmetic_base::ArithmeticGate, arithmetic_extension::ArithmeticExtensionGate,
        base_sum::BaseSumGate, constant::ConstantGate, coset_interpolation::CosetInterpolationGate,
        exponentiation::ExponentiationGate, lookup::LookupGate, lookup_table::LookupTableGate,
        multiplication_extension::MulExtensionGate, noop::NoopGate, poseidon::PoseidonGate,
        poseidon_mds::PoseidonMdsGate, public_input::PublicInputGate,
        random_access::RandomAccessGate, reducing::ReducingGate,
        reducing_extension::ReducingExtensionGate,
    },
    get_gate_tag_impl,
    hash::hash_types::RichField,
    impl_gate_serializer,
    plonk::{circuit_data::VerifierCircuitData, config::GenericConfig},
    read_gate_impl,
    util::serialization::GateSerializer,
};
use plonky2_u32::gates::{
    add_many_u32::U32AddManyGate, comparison::ComparisonGate, subtraction_u32::U32SubtractionGate,
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
    #[error("circuit serialization error: {0}")]
    SerializationError(String),

    #[error("circuit deserialization error: {0}")]
    DeserializationError(String),
}

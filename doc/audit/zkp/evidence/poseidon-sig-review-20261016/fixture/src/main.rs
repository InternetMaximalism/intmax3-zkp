pub use intmax3_zkp::{ethereum_types, utils};
#[path="/Users/andropov/repos/intmax3-zkp/src/poseidon_sig/mod.rs"]
mod poseidon_sig;

use ethereum_types::{bytes32::{Bytes32,Bytes32Target},u32limb_trait::{U32LimbTrait,U32LimbTargetTrait}};
use utils::poseidon_hash_out::{PoseidonHashOut,PoseidonHashOutTarget,GOLDILOCKS_ORDER};
use plonky2::{field::{goldilocks_field::GoldilocksField,types::{Field,PrimeField64}},iop::witness::PartialWitness,plonk::{circuit_builder::CircuitBuilder,circuit_data::CircuitConfig,config::PoseidonGoldilocksConfig}};
use poseidon_sig::list::{list_leaf,list_chain_step,list_commitment,leaf_target,chain_step_target};
type F=GoldilocksField;
type C=PoseidonGoldilocksConfig;
const D:usize=2;

fn main() {
    let zero=Bytes32::zero();
    let max=Bytes32::from_u32_slice(&[u32::MAX;8]).unwrap();
    let distinct=Bytes32::from_u32_slice(&[0,1,u32::MAX,0x80000000,5,7,11,13]).unwrap();
    let pairs=[(zero,max),(max,distinct),(distinct,zero)];
    let mut builder=CircuitBuilder::<F,D>::new(CircuitConfig::standard_recursion_config());
    let mut witness=PartialWitness::<F>::new();
    let mut expected=Vec::new();
    let mut native=PoseidonHashOut::default();
    let mut chain=PoseidonHashOutTarget::constant(&mut builder,native);
    for (message,key) in pairs {
        let m=Bytes32Target::new(&mut builder,true);
        let k=Bytes32Target::new(&mut builder,true);
        m.set_witness(&mut witness,message); k.set_witness(&mut witness,key);
        let leaf=leaf_target(&mut builder,&m,&k);
        let leaf_bytes=Bytes32Target::from_hash_out(&mut builder,leaf);
        builder.register_public_inputs(&leaf_bytes.to_vec());
        let native_leaf=list_leaf(message,key);
        let native_leaf_bytes:Bytes32=native_leaf.into();
        expected.extend(native_leaf_bytes.to_u32_vec());
        chain=chain_step_target(&mut builder,chain,leaf);
        let chain_bytes=Bytes32Target::from_hash_out(&mut builder,chain);
        builder.register_public_inputs(&chain_bytes.to_vec());
        native=list_chain_step(native,native_leaf);
        let native_bytes:Bytes32=native.into();
        expected.extend(native_bytes.to_u32_vec());
    }
    let data=builder.build::<C>();
    let proof=data.prove(witness).unwrap();
    let actual:Vec<u32>=proof.public_inputs.iter().map(|f|f.to_canonical_u64().try_into().unwrap()).collect();
    assert_eq!(actual,expected);
    data.verify(proof).unwrap();
    assert_eq!(list_commitment(&[]),zero);
    let final_native:Bytes32=native.into();
    assert_eq!(list_commitment(&pairs),final_native);
    println!("PASS native and original target helpers agree for three ordered pairs including all-zero/all-u32-max inputs; proof verified");

    let boundary=PoseidonHashOut{elements:[0,1,GOLDILOCKS_ORDER-2,GOLDILOCKS_ORDER-1]};
    let bytes:Bytes32=boundary.into();
    assert_eq!(PoseidonHashOut::try_from(bytes).unwrap(),boundary);
    let mut builder=CircuitBuilder::<F,D>::new(CircuitConfig::standard_recursion_config());
    let mut witness=PartialWitness::<F>::new();
    let byte_target=Bytes32Target::new(&mut builder,true);
    let h=byte_target.to_hash_out(&mut builder);
    let out=Bytes32Target::from_hash_out(&mut builder,h);
    builder.register_public_inputs(&out.to_vec());
    byte_target.set_witness(&mut witness,bytes);
    let data=builder.build::<C>();
    let proof=data.prove(witness).unwrap();
    let actual:Vec<u32>=proof.public_inputs.iter().map(|f|f.to_canonical_u64().try_into().unwrap()).collect();
    assert_eq!(actual,bytes.to_u32_vec());
    data.verify(proof).unwrap();
    println!("PASS canonical field/Bytes32 round-trip boundaries 0,1,p-2,p-1; proof verified");
}

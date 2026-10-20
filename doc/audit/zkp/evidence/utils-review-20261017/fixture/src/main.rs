use intmax3_zkp::{utils::{poseidon_hash_out::{PoseidonHashOut,PoseidonHashOutTarget,GOLDILOCKS_ORDER},trees::{incremental_merkle_tree::IncrementalMerkleTree,sparse_merkle_tree::SparseMerkleTree,indexed_merkle_tree::IndexedMerkleTree},hash_chain::chain_end_circuit::ChainEndProofPublicInputs},wallet_core::ChannelSnapshot};
use plonky2::{field::types::PrimeField64,iop::witness::PartialWitness,plonk::{circuit_builder::CircuitBuilder,circuit_data::CircuitConfig,config::{GenericConfig,PoseidonGoldilocksConfig}}};
type C=PoseidonGoldilocksConfig; type F=<C as GenericConfig<2>>::F;
fn main() {
 match std::env::args().nth(1).as_deref() {
  Some("incremental_decode") => { let _:Result<IncrementalMerkleTree<u32>,_>=serde_json::from_str(r#"{"height":0,"leaves":[1,2]}"#); panic!("unexpected return"); }
  Some("snapshot_decode") => {
    let zero=format!("0x{}","00".repeat(32));
    let v=serde_json::json!({"settledTxAccumulator":{"height":0,"leaves":[zero.clone(),zero]}});
    let _:Result<ChannelSnapshot,_>=serde_json::from_value(v); panic!("unexpected return");
  }
  Some("chain_end_decode") => { let mut values=vec![0u64;13]; values[0]=1u64<<32; let _=ChainEndProofPublicInputs::from_u64_slice(&values); panic!("unexpected return"); }
  _=>{}
 }
 let mut tree=IncrementalMerkleTree::<u32>::new(2); tree.push(7);
 let proof=tree.prove(0); proof.verify(&7,0,tree.get_root()).unwrap(); proof.verify(&7,4,tree.get_root()).unwrap();
 println!("MerkleProof: same height-2 proof accepts indices 0 and 4 for leaf 7");
 let mut sparse=SparseMerkleTree::<u32>::new(2); let before=sparse.get_root(); sparse.update(4,7);
 assert_eq!(before,sparse.get_root());assert_eq!(sparse.get_leaf(4),7); assert_eq!(sparse.len(),1);
 let restored:SparseMerkleTree<u32>=serde_json::from_str(r#"{"height":2,"leaves":[[4,7]]}"#).unwrap();
 assert_eq!(restored.get_leaf(4),7); assert_eq!(restored.get_root(),before);
 println!("SparseMerkleTree: out-of-range leaf survives update and serde without changing root");
 let indexed:IndexedMerkleTree=serde_json::from_str(r#"{"height":2,"leaves":[]}"#).unwrap();
 assert_eq!(indexed.len(),0);assert_ne!(indexed.get_root(),IndexedMerkleTree::new(2).get_root());
 println!("IndexedMerkleTree: serde accepts missing sentinel; new(2) has a different root");
 let raw=PoseidonHashOut::from_u64_slice(&[GOLDILOCKS_ORDER,0,0,0]).unwrap();
 assert_ne!(raw,PoseidonHashOut::default());
 assert_eq!(PoseidonHashOut::hash_inputs_u64(&raw.to_u64_vec()),PoseidonHashOut::hash_inputs_u64(&[0;4]));
 let encoded=serde_json::to_string(&raw).unwrap(); assert!(serde_json::from_str::<PoseidonHashOut>(&encoded).is_err());
 let mut builder=CircuitBuilder::<F,2>::new(CircuitConfig::standard_recursion_config());
 let target=PoseidonHashOutTarget::constant(&mut builder,raw); builder.register_public_inputs(&target.elements);
 let data=builder.build::<C>(); let proof=data.prove(PartialWitness::new()).unwrap();data.verify(proof.clone()).unwrap();
 assert!(proof.public_inputs.iter().all(|x|x.to_canonical_u64()==0));
 println!("PoseidonHashOut: p accepted as raw limb; hashes and circuit values alias 0; own JSON rejected");
}

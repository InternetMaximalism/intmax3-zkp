use intmax3_zkp::{common::{u63::U63, tx::{Tx,TxV2,ChannelAction,ChannelActionKind}, channel_id::ChannelId, public_state::{PublicState,PublicStateTarget,FullPublicState}, withdrawal::Withdrawal}, ethereum_types::bytes32::Bytes32, utils::{leafable::Leafable, trees::get_root::{get_merkle_root_from_leaves,get_merkle_root_from_leaves_circuit}}};
use plonky2::{field::types::PrimeField64, iop::witness::PartialWitness, plonk::{circuit_builder::CircuitBuilder,circuit_data::CircuitConfig,config::{GenericConfig,PoseidonGoldilocksConfig}}};
type C=PoseidonGoldilocksConfig;
type F=<C as GenericConfig<2>>::F;
fn main() {
 if std::env::args().nth(1).as_deref()==Some("withdrawal") {
   let _ = Withdrawal::from_u64_slice(&[1u64<<32]);
   panic!("unexpected return");
 }
 let invalid=1u64<<63;
 assert!(U63::new(invalid).is_err());
 let parsed:U63=serde_json::from_str(&invalid.to_string()).unwrap();
 assert_eq!(parsed.as_u64(),invalid);
 assert_eq!(parsed.to_u32_vec(),vec![0,0]);
 println!("U63: constructor rejects 2^63; serde accepts it; u32 encoding aliases zero");
 let mut tx=Tx::default().to_u64_vec(); tx[4]=1u64<<32;
 assert_eq!(Tx::from_u64_slice(&tx).unwrap().nonce,0);
 let mut txv2=TxV2::default().to_u64_vec(); txv2[0]=1u64<<32; txv2[5]=1u64<<32;
 let decoded=TxV2::from_u64_slice(&txv2).unwrap();
 assert_eq!(decoded,TxV2::default());
 let mut action=ChannelAction::default();
 action.source_channel_id=ChannelId::new(1).unwrap();
 action.destination_channel_id=ChannelId::new(2).unwrap();
 let mut action_words=action.to_u64_vec(); action_words[0]=1u64<<32;
 assert_eq!(ChannelAction::from_u64_slice(&action_words).unwrap(),action);
 println!("Tx / TxV2 / ChannelAction: high bits of nonce/class/kind silently discarded");
 action.kind=ChannelActionKind::ChannelClose;
 action.destination_channel_id=ChannelId::dummy();
 assert!(ChannelAction::from_u64_slice(&action.to_u64_vec()).is_err());
 println!("ChannelClose: encoded zero destination cannot be decoded");
 let leaves=vec![PublicState::empty_leaf();3];
 let native=get_merkle_root_from_leaves(2,&leaves).unwrap();
 let mut builder=CircuitBuilder::<F,2>::new(CircuitConfig::standard_recursion_config());
 let targets=leaves.iter().map(|x|PublicStateTarget::constant(&mut builder,x)).collect::<Vec<_>>();
 let root=get_merkle_root_from_leaves_circuit::<F,C,2,_>(&mut builder,2,&targets);
 builder.register_public_inputs(&root.elements);
 let data=builder.build::<C>();
 let proof=data.prove(PartialWitness::new()).unwrap();
 data.verify(proof.clone()).unwrap();
 let circuit=proof.public_inputs.iter().map(|x|x.to_canonical_u64()).collect::<Vec<_>>();
 assert_ne!(native.to_u64_vec(),circuit);
 println!("PublicState padded root: native={:?}, circuit={:?}; proof verifies",native.to_u64_vec(),circuit);
 let mut state=FullPublicState::new(&[1]);
 let before=state.to_public_state(); let blocks_before=state.blocks.len();
 assert!(state.add_block_with_channel(0,&[1],1,Bytes32::default()).is_err());
 assert_ne!(state.to_public_state(),before);
 assert_eq!(state.blocks.len(),blocks_before+1);
 println!("FullPublicState: rejected channel 0 block changes state and appends block");
}

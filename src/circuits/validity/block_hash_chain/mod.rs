pub mod block_chain_pis;
pub mod block_hash_chain_circuit;
pub mod block_hash_chain_processor;
pub mod block_step;
pub mod channel_state_message;
pub mod ext_public_state;
/// PHASE 5 (small-block N-of-N design §9): the dedicated adversarial module proving the §2.1
/// hole is closed. Test-only — it exists to be run, never to be linked into anything.
#[cfg(test)]
mod nofn_attack;
pub mod small_block_message;
pub mod update_channel_tree;
pub mod validity_circuit;

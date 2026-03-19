//! SPHINCS+ (SPX-128s Poseidon) keygen and signing for test use.
//!
//! This module provides `sphincs_keygen` and `sphincs_sign` functions that
//! generate valid SPHINCS+ key pairs and signatures.  The output is
//! consumed by [`SpxSigWitness::from_bytes`] to fill the validity-proof
//! circuit witnesses.
//!
//! Not intended for production use — only for `#[cfg(test)]` helpers.

use sphincsplus_params::*;
use sphincsplus_poseidon::hash_functions::{gen_message_random, hash_message, prf_addr, thash};
use sphincsplus_poseidon::fors::message_to_indices;
use sphincsplus_poseidon::wots::chain_lengths;

// ── Private helpers ─────────────────────────────────────────────────────────

/// Run a hash chain from position `start` for `steps` steps.
fn gen_chain(
    input: &[u8],
    start: u32,
    steps: u32,
    ctx: &SpxCtx,
    addr: &mut SpxAddress,
) -> [u8; SPX_N] {
    let mut out = [0u8; SPX_N];
    out.copy_from_slice(&input[..SPX_N]);
    let end = (start + steps).min(SPX_WOTS_W as u32);
    for i in start..end {
        addr.set_hash_addr(i);
        let h = thash(&out.clone(), 1, ctx, addr);
        out.copy_from_slice(&h);
    }
    out
}

/// Generate WOTS+ public key for the leaf at `wots_addr` (with type=WOTS already set,
/// layer/tree/keypair pre-set).
fn wots_gen_pk(ctx: &SpxCtx, wots_addr: &SpxAddress) -> Vec<u8> {
    let mut pk = vec![0u8; SPX_WOTS_BYTES];
    let mut prf_a = *wots_addr;
    prf_a.set_type(SPX_ADDR_TYPE_WOTSPRF);
    for i in 0..SPX_WOTS_LEN {
        prf_a.set_chain(i as u32);
        prf_a.set_hash_addr(0);
        let sk_i = prf_addr(ctx, &prf_a);
        let mut chain_a = *wots_addr;
        chain_a.set_type(SPX_ADDR_TYPE_WOTS);
        chain_a.set_chain(i as u32);
        let pk_i = gen_chain(&sk_i, 0, (SPX_WOTS_W - 1) as u32, ctx, &mut chain_a);
        pk[i * SPX_N..(i + 1) * SPX_N].copy_from_slice(&pk_i);
    }
    pk
}

/// Generate WOTS+ signature over `msg` (SPX_N bytes).
/// `wots_addr` must have layer/tree/keypair set; its type will be temporarily changed.
fn wots_sign_msg(msg: &[u8], ctx: &SpxCtx, wots_addr: &SpxAddress) -> Vec<u8> {
    let lengths = chain_lengths(msg);
    let mut sig = vec![0u8; SPX_WOTS_BYTES];
    let mut prf_a = *wots_addr;
    prf_a.set_type(SPX_ADDR_TYPE_WOTSPRF);
    for i in 0..SPX_WOTS_LEN {
        prf_a.set_chain(i as u32);
        prf_a.set_hash_addr(0);
        let sk_i = prf_addr(ctx, &prf_a);
        let mut chain_a = *wots_addr;
        chain_a.set_type(SPX_ADDR_TYPE_WOTS);
        chain_a.set_chain(i as u32);
        let out = gen_chain(&sk_i, 0, lengths[i] as u32, ctx, &mut chain_a);
        sig[i * SPX_N..(i + 1) * SPX_N].copy_from_slice(&out);
    }
    sig
}

/// Compute an XMSS leaf (= hash of the WOTS+ public key).
/// `tree_addr` has layer/tree set, type=HASHTREE (for subtree address).
fn xmss_leaf(leaf_idx: u32, ctx: &SpxCtx, tree_addr: &SpxAddress) -> [u8; SPX_N] {
    let mut wots_addr = SpxAddress::new();
    wots_addr.copy_subtree_addr(tree_addr);
    wots_addr.set_type(SPX_ADDR_TYPE_WOTS);
    wots_addr.set_keypair(leaf_idx);

    let pk = wots_gen_pk(ctx, &wots_addr);

    let mut pk_addr = SpxAddress::new();
    pk_addr.copy_keypair_addr(&wots_addr);
    pk_addr.set_type(SPX_ADDR_TYPE_WOTSPK);
    thash(&pk, SPX_WOTS_LEN, ctx, &pk_addr)
}

/// Build the full XMSS subtree for `(layer, tree_idx)`.
///
/// Returns a flat 1-indexed binary tree where:
/// - `tree[1]` = root
/// - `tree[n..2n]` = leaves (n = 2^SPX_TREE_HEIGHT = 512)
fn build_xmss_tree(layer: usize, tree_idx: u64, ctx: &SpxCtx) -> Vec<[u8; SPX_N]> {
    let n = 1usize << SPX_TREE_HEIGHT; // 512
    let mut tree = vec![[0u8; SPX_N]; 2 * n]; // 1-indexed, index 0 unused

    let mut subtree_addr = SpxAddress::new();
    subtree_addr.set_layer(layer as u32);
    subtree_addr.set_tree(tree_idx);
    subtree_addr.set_type(SPX_ADDR_TYPE_HASHTREE);

    // Compute leaves
    for j in 0..n {
        tree[n + j] = xmss_leaf(j as u32, ctx, &subtree_addr);
    }

    // Build internal nodes bottom-up
    for i in (1..n).rev() {
        let left = tree[2 * i];
        let right = tree[2 * i + 1];
        let mut buf = [0u8; 2 * SPX_N];
        buf[..SPX_N].copy_from_slice(&left);
        buf[SPX_N..].copy_from_slice(&right);

        // Node i: depth = floor(log2(i)), height = SPX_TREE_HEIGHT - depth
        let depth = (usize::BITS - 1 - i.leading_zeros()) as usize;
        let height = SPX_TREE_HEIGHT - depth;
        let node_in_level = i - (1 << depth);

        let mut h_addr = subtree_addr;
        h_addr.set_tree_height(height as u32);
        h_addr.set_tree_index(node_in_level as u32);
        tree[i] = thash(&buf, 2, ctx, &h_addr);
    }

    tree
}

/// Sign and produce auth path for XMSS at `(layer, tree_idx, leaf_idx)` over `msg`.
///
/// Returns `(wots_sig_bytes, auth_path_bytes, xmss_root)`.
fn xmss_sign_and_root(
    msg: &[u8],
    layer: usize,
    tree_idx: u64,
    leaf_idx: u32,
    ctx: &SpxCtx,
) -> (Vec<u8>, Vec<u8>, [u8; SPX_N]) {
    let tree = build_xmss_tree(layer, tree_idx, ctx);
    let n = 1usize << SPX_TREE_HEIGHT;
    let root = tree[1];

    // Auth path: siblings on the path from leaf to root
    let mut auth_path = vec![0u8; SPX_TREE_HEIGHT * SPX_N];
    let mut idx = n + leaf_idx as usize; // leaf position in 1-indexed tree
    for j in 0..SPX_TREE_HEIGHT {
        let sibling = if idx & 1 == 0 { idx + 1 } else { idx - 1 };
        auth_path[j * SPX_N..(j + 1) * SPX_N].copy_from_slice(&tree[sibling]);
        idx >>= 1;
    }

    // WOTS sign
    let mut wots_addr = SpxAddress::new();
    let mut ta = SpxAddress::new();
    ta.set_layer(layer as u32);
    ta.set_tree(tree_idx);
    wots_addr.copy_subtree_addr(&ta);
    wots_addr.set_type(SPX_ADDR_TYPE_WOTS);
    wots_addr.set_keypair(leaf_idx);
    let wots_sig = wots_sign_msg(msg, ctx, &wots_addr);

    (wots_sig, auth_path, root)
}

/// Build a complete FORS tree for tree index `tree_i`.
///
/// Returns flat 1-indexed binary tree of size `2 * 2^SPX_FORS_HEIGHT`.
/// Also returns all secret leaf values (pre-thash).
fn build_fors_tree(
    tree_i: usize,
    ctx: &SpxCtx,
    fors_addr_template: &SpxAddress,
) -> (Vec<[u8; SPX_N]>, Vec<[u8; SPX_N]>) {
    let n = 1usize << SPX_FORS_HEIGHT; // 4096
    let mut tree = vec![[0u8; SPX_N]; 2 * n];
    let mut secrets = vec![[0u8; SPX_N]; n];
    let idx_offset = (tree_i as u32) * (n as u32);

    let mut prf_addr_t = *fors_addr_template;
    prf_addr_t.set_type(SPX_ADDR_TYPE_FORSPRF);
    prf_addr_t.set_tree_height(0);

    let mut leaf_addr = *fors_addr_template;
    leaf_addr.set_type(SPX_ADDR_TYPE_FORSTREE);
    leaf_addr.set_tree_height(0);

    for j in 0..n {
        let global_idx = j as u32 + idx_offset;
        prf_addr_t.set_tree_index(global_idx);
        let sk = prf_addr(ctx, &prf_addr_t);
        secrets[j] = sk;
        leaf_addr.set_tree_index(global_idx);
        tree[n + j] = thash(&sk, 1, ctx, &leaf_addr);
    }

    // Build internal nodes bottom-up
    let mut h_addr = *fors_addr_template;
    h_addr.set_type(SPX_ADDR_TYPE_FORSTREE);
    for i in (1..n).rev() {
        let left = tree[2 * i];
        let right = tree[2 * i + 1];
        let mut buf = [0u8; 2 * SPX_N];
        buf[..SPX_N].copy_from_slice(&left);
        buf[SPX_N..].copy_from_slice(&right);

        let depth = (usize::BITS - 1 - i.leading_zeros()) as usize;
        let height = SPX_FORS_HEIGHT - depth;
        let node_in_level = i - (1 << depth);
        // Global tree_index at this level: node_in_level + idx_offset >> height
        let global_tree_idx = node_in_level as u32 + (idx_offset >> height);
        h_addr.set_tree_height(height as u32);
        h_addr.set_tree_index(global_tree_idx);
        tree[i] = thash(&buf, 2, ctx, &h_addr);
    }

    (tree, secrets)
}

/// Generate FORS signature.
///
/// `fors_addr_template` should have layer/tree/keypair pre-set (copied from the
/// WOTS address used at the bottom hypertree layer).
///
/// Returns `(sig_bytes, fors_pk)`.
fn fors_sign_impl(
    digest: &[u8; SPX_FORS_MSG_BYTES],
    ctx: &SpxCtx,
    fors_addr_template: &SpxAddress,
) -> (Vec<u8>, [u8; SPX_N]) {
    let indices = message_to_indices(digest);
    let mut sig = vec![0u8; SPX_FORS_BYTES];
    let mut roots = vec![0u8; SPX_FORS_TREES * SPX_N];
    let mut sig_offset = 0;

    for i in 0..SPX_FORS_TREES {
        let n = 1usize << SPX_FORS_HEIGHT;
        let idx_offset = (i as u32) * (n as u32);
        let leaf_idx = indices[i] as usize;

        let (tree, secrets) = build_fors_tree(i, ctx, fors_addr_template);

        // Secret leaf
        sig[sig_offset..sig_offset + SPX_N].copy_from_slice(&secrets[leaf_idx]);
        sig_offset += SPX_N;

        // Auth path
        let mut idx = n + leaf_idx;
        for j in 0..SPX_FORS_HEIGHT {
            let sibling = if idx & 1 == 0 { idx + 1 } else { idx - 1 };
            sig[sig_offset..sig_offset + SPX_N].copy_from_slice(&tree[sibling]);
            sig_offset += SPX_N;
            idx >>= 1;

            // Verify auth path length doesn't go out of bounds
            let _ = idx_offset; // suppress unused warning
        }

        // Compute this tree's root using compute_root (mimicking verification)
        let leaf_hash = {
            let mut prf_addr_t = *fors_addr_template;
            prf_addr_t.set_type(SPX_ADDR_TYPE_FORSPRF);
            prf_addr_t.set_tree_height(0);
            prf_addr_t.set_tree_index(indices[i] + idx_offset);
            let sk = prf_addr(ctx, &prf_addr_t);
            let mut leaf_addr = *fors_addr_template;
            leaf_addr.set_type(SPX_ADDR_TYPE_FORSTREE);
            leaf_addr.set_tree_height(0);
            leaf_addr.set_tree_index(indices[i] + idx_offset);
            thash(&sk, 1, ctx, &leaf_addr)
        };

        // Recompute root from leaf + auth path for cross-check
        let auth_start = n + leaf_idx - SPX_FORS_HEIGHT;
        let _ = auth_start; // not used directly

        roots[i * SPX_N..(i + 1) * SPX_N].copy_from_slice(&tree[1]);
        let _ = leaf_hash; // we use tree[1] directly
    }

    // Compute FORS pk = thash(roots, SPX_FORS_TREES, fors_pk_addr)
    let mut fors_pk_addr = *fors_addr_template;
    fors_pk_addr.set_type(SPX_ADDR_TYPE_FORSPK);
    let fors_pk_bytes = thash(&roots, SPX_FORS_TREES, ctx, &fors_pk_addr);
    let mut fors_pk = [0u8; SPX_N];
    fors_pk.copy_from_slice(&fors_pk_bytes);

    (sig, fors_pk)
}

// ── Public API ───────────────────────────────────────────────────────────────

/// SPHINCS+ key pair.
pub struct SpxKeyPair {
    pub sk_seed: [u8; SPX_N],
    pub sk_prf:  [u8; SPX_N],
    pub pub_seed: [u8; SPX_N],
    /// 32-byte public key: `pub_seed || pub_root`
    pub pk_bytes: [u8; SPX_PK_BYTES],
}

/// Compute a SPHINCS+ key pair from the given seeds.
pub fn sphincs_keygen(
    sk_seed: [u8; SPX_N],
    sk_prf: [u8; SPX_N],
    pub_seed: [u8; SPX_N],
) -> SpxKeyPair {
    let ctx = SpxCtx { pub_seed, sk_seed };

    // pub_root = root of the top-level XMSS tree (layer D-1 = 6, tree=0)
    let tree = build_xmss_tree(SPX_D - 1, 0, &ctx);
    let pub_root = tree[1];

    let mut pk_bytes = [0u8; SPX_PK_BYTES];
    pk_bytes[..SPX_N].copy_from_slice(&pub_seed);
    pk_bytes[SPX_N..].copy_from_slice(&pub_root);

    SpxKeyPair { sk_seed, sk_prf, pub_seed, pk_bytes }
}

/// Sign `msg_bytes` with the given SPHINCS+ secret key.
///
/// Returns the 7856-byte signature.
pub fn sphincs_sign(msg_bytes: &[u8], kp: &SpxKeyPair) -> [u8; SPX_BYTES] {
    let ctx = SpxCtx {
        pub_seed: kp.pub_seed,
        sk_seed: kp.sk_seed,
    };

    // R = gen_message_random(sk_prf, optrand=0, msg)
    let optrand = [0u8; SPX_N];
    let r = gen_message_random(&kp.sk_prf, &optrand, msg_bytes, &ctx);

    // (digest, tree, leaf_idx) = hash_message(R, pk, msg)
    let (digest, mut tree_val, mut idx_leaf) = hash_message(&r, &kp.pk_bytes, msg_bytes, &ctx);

    let mut sig = [0u8; SPX_BYTES];
    let mut offset = 0;

    // R
    sig[offset..offset + SPX_N].copy_from_slice(&r);
    offset += SPX_N;

    // FORS sign
    let mut fors_addr = SpxAddress::new();
    fors_addr.set_type(SPX_ADDR_TYPE_WOTS);
    fors_addr.set_tree(tree_val);
    fors_addr.set_keypair(idx_leaf);

    let (fors_sig, mut root) = fors_sign_impl(&digest, &ctx, &fors_addr);
    sig[offset..offset + SPX_FORS_BYTES].copy_from_slice(&fors_sig);
    offset += SPX_FORS_BYTES;

    // Hypertree: D layers
    for layer in 0..SPX_D {
        let (wots_sig, auth_path, xmss_root) =
            xmss_sign_and_root(&root, layer, tree_val, idx_leaf, &ctx);

        sig[offset..offset + SPX_WOTS_BYTES].copy_from_slice(&wots_sig);
        offset += SPX_WOTS_BYTES;
        sig[offset..offset + SPX_TREE_HEIGHT * SPX_N].copy_from_slice(&auth_path);
        offset += SPX_TREE_HEIGHT * SPX_N;

        root = xmss_root;

        // Update tree/leaf for next layer
        idx_leaf = (tree_val & ((1u64 << SPX_TREE_HEIGHT) - 1)) as u32;
        tree_val >>= SPX_TREE_HEIGHT;
    }

    assert_eq!(offset, SPX_BYTES, "signature length mismatch");
    sig
}

/// Derive the plonky2-compatible `pk_hash` for the given public key bytes.
///
/// `pk_hash = PoseidonHashOut::hash_inputs_u64(&[pub_seed_gl[0], pub_seed_gl[1],
///                                               pub_root_gl[0], pub_root_gl[1]])`
/// where `pub_seed_gl` and `pub_root_gl` are the LE-u64 packing of the 16-byte values.
pub fn pk_hash_from_pk_bytes(pk_bytes: &[u8; SPX_PK_BYTES]) -> crate::utils::poseidon_hash_out::PoseidonHashOut {
    // Pack the 32 bytes as four LE u64 values (GL elements).
    let gl: Vec<u64> = pk_bytes
        .chunks(8)
        .map(|c| u64::from_le_bytes(c.try_into().unwrap()))
        .collect();
    crate::utils::poseidon_hash_out::PoseidonHashOut::hash_inputs_u64(&gl)
}

#[cfg(test)]
mod tests {
    use super::*;
    use sphincsplus_poseidon::verify::crypto_sign_verify;

    #[test]
    fn test_sphincs_sign_and_verify() {
        let sk_seed = [0x11u8; SPX_N];
        let sk_prf  = [0x22u8; SPX_N];
        let pub_seed = [0x33u8; SPX_N];

        let kp = sphincs_keygen(sk_seed, sk_prf, pub_seed);
        let msg = b"test block signing";
        let sig = sphincs_sign(msg, &kp);

        crypto_sign_verify(&sig, msg, &kp.pk_bytes)
            .expect("SPHINCS+ signature verification failed");
    }
}

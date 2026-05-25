use anyhow::Result;
use p3_recursion::AggregationPrepCache;

use super::recursively_verifiable::{aggregate_recursion_outputs, KoalaRecursionProof};

pub fn fold_recursion_chain(
    mut proofs: Vec<KoalaRecursionProof>,
) -> Result<Option<KoalaRecursionProof>> {
    if proofs.is_empty() {
        return Ok(None);
    }

    let mut prep_cache: Option<AggregationPrepCache<_>> = None;
    let mut level = 1;
    while proofs.len() > 1 {
        let mut next = Vec::with_capacity(proofs.len().div_ceil(2));
        let mut iter = proofs.into_iter();
        while let Some(left) = iter.next() {
            if let Some(right) = iter.next() {
                next.push(aggregate_recursion_outputs(
                    &left,
                    &right,
                    level,
                    Some(&mut prep_cache),
                )?);
            } else {
                next.push(left);
            }
        }
        proofs = next;
        level += 1;
    }

    Ok(proofs.pop())
}

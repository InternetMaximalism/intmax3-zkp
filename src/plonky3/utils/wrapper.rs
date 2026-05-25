use anyhow::{anyhow, Result};
use p3_recursion::{build_and_prove_next_layer, BatchOnly};

use crate::plonky3::config::{
    koala_recursion_backend, koala_recursion_params, KoalaRecursionConfig,
};

use super::recursively_verifiable::{verify_recursion_output, KoalaRecursionProof};

pub fn wrap_recursion_output(base: &KoalaRecursionProof) -> Result<KoalaRecursionProof> {
    let config = KoalaRecursionConfig::new();
    let backend = koala_recursion_backend();
    let params = koala_recursion_params();
    let input = base.into_recursion_input::<BatchOnly>();
    let wrapped = build_and_prove_next_layer::<KoalaRecursionConfig, BatchOnly, _, 4>(
        &input, &config, &backend, &params,
    )
    .map_err(|e| anyhow!("failed to wrap KoalaBear recursive proof: {e:?}"))?;
    Ok(wrapped)
}

pub fn wrap_recursion_output_and_verify(base: &KoalaRecursionProof) -> Result<KoalaRecursionProof> {
    let wrapped = wrap_recursion_output(base)?;
    verify_recursion_output(&wrapped, koala_recursion_params().table_packing)?;
    Ok(wrapped)
}

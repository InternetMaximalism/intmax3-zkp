#[cfg(feature = "fast-benchmark")]
pub const Q: u64 = 65_537;
#[cfg(not(feature = "fast-benchmark"))]
pub const Q: u64 = 8_380_417;

#[cfg(feature = "fast-benchmark")]
pub const M: usize = 32;
#[cfg(not(feature = "fast-benchmark"))]
pub const M: usize = 128;

#[cfg(feature = "fast-benchmark")]
pub const N: usize = 64;
#[cfg(not(feature = "fast-benchmark"))]
pub const N: usize = 256;

pub const LIMBS: usize = 4;
pub const BITS_PER_LIMB: usize = 16;
pub const CHUNK_BITS: usize = 8;

#[cfg(feature = "fast-benchmark")]
pub const SECURITY_PROFILE: &str = "fast-benchmark-32x64";
#[cfg(not(feature = "fast-benchmark"))]
pub const SECURITY_PROFILE: &str = "research-candidate-128x256";

#[inline]
pub fn g_coeff(row: usize, limb: usize) -> u64 {
    debug_assert!(row < M);
    debug_assert!(limb < LIMBS);

    if row < LIMBS {
        return u64::from(row == limb);
    }

    let mix = ((row as u64 + 17) * (limb as u64 + 29) + 97) % Q;
    (mix + 1) % Q
}

#[inline]
pub fn b_coeff(row: usize, col: usize) -> u64 {
    debug_assert!(row < M);
    debug_assert!(col < N);

    let x = ((row as u64 + 1) << 32) ^ (col as u64 + 1);
    let mut z = x.wrapping_add(0x9e37_79b9_7f4a_7c15);
    z = (z ^ (z >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
    z = (z ^ (z >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
    let value = z ^ (z >> 31);
    value % Q
}

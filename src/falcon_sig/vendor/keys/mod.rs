// VENDOR EDITS (see vendor/README.md): unused `Felt`/`Signature` re-imports dropped; the inline
// `test_falcon_verification` test targeted the removed `PublicKey::verify` — the equivalent
// end-to-end coverage (round-trip, wrong-message, wrong-pk rejection) lives in
// `falcon_sig::tests` against the canonical `falcon_sig::verify`.
use super::{
    ByteReader, ByteWriter, Deserializable, DeserializationError, Serializable,
    math::{FalconFelt, Polynomial},
};

mod public_key;
pub use public_key::PublicKey;

mod secret_key;
pub use secret_key::SecretKey;
pub(crate) use secret_key::{WIDTH_BIG_POLY_COEFFICIENT, WIDTH_SMALL_POLY_COEFFICIENT};

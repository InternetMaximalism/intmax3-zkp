#[path = "/Users/andropov/repos/intmax3-zkp/src/wrapper_config/mod.rs"]
mod wrapper_config;
use plonky2::field::goldilocks_field::GoldilocksField;
use plonky2::plonk::config::GenericHashOut;
use wrapper_config::plonky2_config::PoseidonBN128HashOut;
type Digest = PoseidonBN128HashOut<GoldilocksField>;
fn main() {
    let case = std::env::args().nth(1).expect("case");
    if case == "binary_noncanonical" {
        let decoded = Digest::from_bytes(&[255u8; 32]);
        println!("OK {:?}", decoded);
        return;
    }
    let input = match case.as_str() {
        "valid_zero" => "\"0\"",
        "valid_max" => "\"21888242871839275222246405745257275088548364400416034343698204186575808495616\"",
        "json_wrong_type" => "0",
        "json_nondecimal" => "\"not-a-number\"",
        "json_modulus" => "\"21888242871839275222246405745257275088548364400416034343698204186575808495617\"",
        _ => panic!("unknown case"),
    };
    match serde_json::from_str::<Digest>(input) {
        Ok(value) => println!("OK {:?}", value),
        Err(error) => println!("ERR {error}"),
    }
}

use plonky2::{
    field::goldilocks_field::GoldilocksField,
    hash::poseidon::{ALL_ROUND_CONSTANTS, Poseidon},
};

fn main() {
    // ALL_ROUND_CONSTANTS (360 values = 30 rounds * 12 elements)
    println!("// ALL_ROUND_CONSTANTS[360]");
    for (i, c) in ALL_ROUND_CONSTANTS.iter().enumerate() {
        println!("0x{:016x},", c);
    }

    // MDS constants
    let circ = GoldilocksField::MDS_MATRIX_CIRC;
    let diag = GoldilocksField::MDS_MATRIX_DIAG;
    println!("\n// MDS_MATRIX_CIRC[12]");
    for c in circ.iter() {
        println!("{},", c);
    }
    println!("\n// MDS_MATRIX_DIAG[12]");
    for c in diag.iter() {
        println!("{},", c);
    }

    // FAST_PARTIAL_FIRST_ROUND_CONSTANT[12]
    let fpc = GoldilocksField::FAST_PARTIAL_FIRST_ROUND_CONSTANT;
    println!("\n// FAST_PARTIAL_FIRST_ROUND_CONSTANT[12]");
    for c in fpc.iter() {
        println!("0x{:016x},", c);
    }

    // FAST_PARTIAL_ROUND_CONSTANTS[22]
    let fprc = GoldilocksField::FAST_PARTIAL_ROUND_CONSTANTS;
    println!("\n// FAST_PARTIAL_ROUND_CONSTANTS[22]");
    for c in fprc.iter() {
        println!("0x{:016x},", c);
    }

    // FAST_PARTIAL_ROUND_W_HATS[22][11] - flattened
    let whats = GoldilocksField::FAST_PARTIAL_ROUND_W_HATS;
    println!("\n// FAST_PARTIAL_ROUND_W_HATS[22*11=242]");
    for row in whats.iter() {
        for val in row.iter() {
            println!("0x{:016x},", val);
        }
    }

    // FAST_PARTIAL_ROUND_VS[22][11] - flattened
    let vs = GoldilocksField::FAST_PARTIAL_ROUND_VS;
    println!("\n// FAST_PARTIAL_ROUND_VS[22*11=242]");
    for row in vs.iter() {
        for val in row.iter() {
            println!("0x{:016x},", val);
        }
    }

    // FAST_PARTIAL_ROUND_INITIAL_MATRIX[11][11] - flattened
    let im = GoldilocksField::FAST_PARTIAL_ROUND_INITIAL_MATRIX;
    println!("\n// FAST_PARTIAL_ROUND_INITIAL_MATRIX[11*11=121]");
    for row in im.iter() {
        for val in row.iter() {
            println!("0x{:016x},", val);
        }
    }
}

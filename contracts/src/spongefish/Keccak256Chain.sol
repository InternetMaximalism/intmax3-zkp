// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// @title Keccak256Chain
/// @notice EVM-friendly Fiat-Shamir transcript using keccak256 hash chain.
///         Matches the Rust Keccak256Chain in src/transcript/keccak256_chain.rs.
///
///   absorb(input): state = keccak256(state || input), counter = 0
///   squeeze(n):    output_i = keccak256(state || "squeeze" || counter_be), counter++
///   ratchet():     state = keccak256(state || "ratchet"), counter = 0
library Keccak256Chain {
    struct Sponge {
        bytes32 state;
        uint64 squeezeCounter;
    }

    /// @notice Initialize a fresh sponge (state = 0, counter = 0).
    function init() internal pure returns (Sponge memory s) {
        // default zero-initialized
    }

    /// @notice Absorb arbitrary bytes: state = keccak256(state || input), counter = 0.
    function absorb(Sponge memory s, bytes memory input) internal pure {
        bytes32 st = s.state;
        bytes32 result;
        assembly {
            let inputLen := mload(input)
            let totalLen := add(32, inputLen)
            // Use scratch space: write state at free memory, then input data
            let scratch := mload(0x40)
            mstore(scratch, st)
            // Copy input bytes after state
            let src := add(input, 0x20)
            let dst := add(scratch, 32)
            for { let i := 0 } lt(i, inputLen) { i := add(i, 32) } {
                mstore(add(dst, i), mload(add(src, i)))
            }
            result := keccak256(scratch, totalLen)
        }
        s.state = result;
        s.squeezeCounter = 0;
    }

    /// @notice Squeeze n bytes: each 32-byte block = keccak256(state || "squeeze" || counter_be).
    ///         Counter is big-endian uint64 (matches Rust's .to_be_bytes()).
    ///         Uses SHA3 opcode directly via assembly for gas efficiency.
    function squeeze(Sponge memory s, uint256 n) internal pure returns (bytes memory output) {
        output = new bytes(n);
        uint256 counter = uint256(s.squeezeCounter);
        bytes32 st = s.state;
        assembly {
            let scratch := mload(0x40)
            mstore(scratch, st)
            let dst := add(output, 0x20)
            let offset := 0
            for {} lt(offset, n) {} {
                let tagWord := or(
                    shl(200, 0x73717565657a65),
                    shl(136, counter)
                )
                mstore(add(scratch, 32), tagWord)
                let h := keccak256(scratch, 47)
                counter := add(counter, 1)

                // Always mstore the full 32 bytes — safe because bytes memory has
                // at least 32 bytes of padding after its length due to Solidity ABI.
                // For the last partial chunk, the excess bytes overwrite padding
                // which will not be read (output.length is already set correctly).
                mstore(add(dst, offset), h)
                offset := add(offset, 32)
            }
        }
        s.squeezeCounter = uint64(counter);
    }

    /// @notice Squeeze exactly 1 byte. Optimized hot path for challenge_indices.
    function squeezeByte(Sponge memory s) internal pure returns (uint8 b) {
        bytes32 st = s.state;
        uint256 counter = uint256(s.squeezeCounter);
        assembly {
            let scratch := mload(0x40)
            mstore(scratch, st)
            let tagWord := or(
                shl(200, 0x73717565657a65),
                shl(136, counter)
            )
            mstore(add(scratch, 32), tagWord)
            let h := keccak256(scratch, 47)
            b := shr(248, h) // first byte
        }
        s.squeezeCounter = uint64(counter + 1);
    }

    /// @notice Ratchet: state = keccak256(state || "ratchet"), counter = 0.
    function ratchet(Sponge memory s) internal pure {
        bytes32 st = s.state;
        bytes32 result;
        assembly {
            // state(32) || "ratchet"(7) = 39 bytes
            // "ratchet" = 0x72617463686574
            let scratch := mload(0x40)
            mstore(scratch, st)
            mstore(add(scratch, 32), 0x7261746368657400000000000000000000000000000000000000000000000000)
            result := keccak256(scratch, 39)
        }
        s.state = result;
        s.squeezeCounter = 0;
    }
}

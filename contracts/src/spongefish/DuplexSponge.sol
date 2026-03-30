// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {LibKeccak} from "./LibKeccak.sol";

/// @title DuplexSponge
/// @notice Keccak-f[1600] duplex sponge matching spongefish's DuplexSponge<KeccakF1600, 200, 136>.
///
///   Spongefish uses:
///     - Permutation: KeccakF1600 (24 rounds)
///     - State: 200 bytes (1600 bits)
///     - Rate: 136 bytes
///     - Capacity: 64 bytes
///     - Unit: u8 (bytes)
///
///   Absorb: overwrite state[absorb_pos..] with input bytes, permute when rate full
///   Squeeze: read state[squeeze_pos..], permute when rate exhausted
///
///   IMPORTANT: spongefish absorbs by OVERWRITING, not XOR-ing.
///   This matches DuplexSponge::absorb() in spongefish/src/duplex_sponge.rs lines 197-216.
library DuplexSponge {
    uint256 internal constant RATE = 136;

    /// @dev In-memory sponge state: 25 uint64 words + absorb_pos + squeeze_pos
    ///      Layout: [state[0..24], absorb_pos, squeeze_pos]
    struct Sponge {
        LibKeccak.StateMatrix state;
        uint256 absorbPos;
        uint256 squeezePos;
    }

    /// @notice Initialize a fresh sponge.
    function init() internal pure returns (Sponge memory s) {
        s.absorbPos = 0;
        s.squeezePos = RATE; // Force permute on first squeeze
    }

    /// @notice Absorb arbitrary bytes into the sponge.
    ///         Matches spongefish: overwrite (not XOR) state bytes.
    function absorb(Sponge memory s, bytes memory input) internal pure {
        s.squeezePos = RATE; // Reset squeeze position on absorb

        uint256 inputLen = input.length;
        uint256 inputPos = 0;

        while (inputPos < inputLen) {
            if (s.absorbPos == RATE) {
                LibKeccak.permutation(s.state);
                s.absorbPos = 0;
            }

            uint256 chunkLen = inputLen - inputPos;
            uint256 available = RATE - s.absorbPos;
            if (chunkLen > available) chunkLen = available;

            // Overwrite state bytes at [absorbPos .. absorbPos + chunkLen]
            _writeStateBytes(s.state, s.absorbPos, input, inputPos, chunkLen);
            s.absorbPos += chunkLen;
            inputPos += chunkLen;
        }
    }

    /// @notice Squeeze n bytes from the sponge.
    function squeeze(Sponge memory s, uint256 n) internal pure returns (bytes memory output) {
        output = new bytes(n);
        s.absorbPos = 0; // Reset absorb position on squeeze

        uint256 outputPos = 0;
        while (outputPos < n) {
            if (s.squeezePos == RATE) {
                s.squeezePos = 0;
                LibKeccak.permutation(s.state);
            }

            uint256 chunkLen = n - outputPos;
            uint256 available = RATE - s.squeezePos;
            if (chunkLen > available) chunkLen = available;

            // Read state bytes from [squeezePos .. squeezePos + chunkLen]
            _readStateBytes(s.state, s.squeezePos, output, outputPos, chunkLen);
            s.squeezePos += chunkLen;
            outputPos += chunkLen;
        }
    }

    /// @notice Ratchet: clear rate portion, permute. Used for domain separation.
    function ratchet(Sponge memory s) internal pure {
        s.absorbPos = RATE;
        s.squeezePos = RATE;
        // Zero out the rate portion
        for (uint256 i = 0; i < RATE / 8; i++) {
            s.state.state[i] = 0;
        }
        LibKeccak.permutation(s.state);
    }

    // -----------------------------------------------------------------------
    // State byte access — map byte offset to uint64[25] words
    // -----------------------------------------------------------------------

    /// @dev Write `len` bytes from `input[inputOffset..]` into state starting at byte `stateOffset`.
    function _writeStateBytes(
        LibKeccak.StateMatrix memory st,
        uint256 stateOffset,
        bytes memory input,
        uint256 inputOffset,
        uint256 len
    ) private pure {
        for (uint256 i = 0; i < len; i++) {
            uint256 byteIdx = stateOffset + i;
            uint256 wordIdx = byteIdx / 8;
            uint256 bitShift = (byteIdx % 8) * 8; // Little-endian byte order within word

            uint8 b = uint8(input[inputOffset + i]);
            // Clear the byte at position, then set it
            st.state[wordIdx] = (st.state[wordIdx] & ~uint64(uint64(0xFF) << bitShift))
                | uint64(uint64(b) << bitShift);
        }
    }

    /// @dev Read `len` bytes from state starting at byte `stateOffset` into `output[outputOffset..]`.
    function _readStateBytes(
        LibKeccak.StateMatrix memory st,
        uint256 stateOffset,
        bytes memory output,
        uint256 outputOffset,
        uint256 len
    ) private pure {
        for (uint256 i = 0; i < len; i++) {
            uint256 byteIdx = stateOffset + i;
            uint256 wordIdx = byteIdx / 8;
            uint256 bitShift = (byteIdx % 8) * 8;

            output[outputOffset + i] = bytes1(uint8(uint64(st.state[wordIdx] >> bitShift)));
        }
    }
}

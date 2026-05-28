// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Groth16Verifier} from "./Groth16Verifier.sol";
import {IChannelSettlementVerifier} from "./ChannelSettlementManager.sol";

contract ChannelSettlementVerifier is IChannelSettlementVerifier {
    uint32 internal constant CLOSE_INTENT_DOMAIN = 0x494d4349;
    uint32 internal constant CANCEL_CLOSE_DOMAIN = 0x494d434e;
    uint32 internal constant POST_CLOSE_CLAIM_DOMAIN = 0x494d4350;

    function verifyCloseIntent(
        uint64 channelId,
        uint64 closeNonce,
        uint64 finalEpoch,
        bytes32 finalChannelStateDigest,
        uint256 channelFundAmount,
        bytes32 channelFundIntmaxStateRoot,
        bytes32 settlementDigest,
        uint64 snapshotBlockNumber,
        bytes calldata proof
    ) external view returns (bool) {
        bytes32 closeIntentDigest = closePIHash(
            channelId,
            closeNonce,
            finalEpoch,
            finalChannelStateDigest,
            channelFundAmount,
            channelFundIntmaxStateRoot,
            settlementDigest,
            snapshotBlockNumber
        );
        return _verify(proof, closeIntentDigest);
    }

    function verifyCancelClose(
        uint64 channelId,
        bytes32 closeIntentDigest,
        bytes32 revivedInterChannelTxDigest,
        bytes32 revivedTxHash,
        bytes32 revivedSeal,
        bytes calldata proof
    ) external view returns (bool) {
        return _verify(
            proof,
            cancelPIHash(
                channelId,
                closeIntentDigest,
                revivedInterChannelTxDigest,
                revivedTxHash,
                revivedSeal
            )
        );
    }

    function verifyPostCloseClaim(
        uint64 channelId,
        bytes32 closeIntentDigest,
        bytes32 incomingTxHash,
        uint64 receiverId,
        address recipient,
        uint64 amount,
        bytes32 personalNullifier,
        bytes calldata proof
    ) external view returns (bool) {
        return _verify(
            proof,
            postCloseClaimPIHash(
                channelId,
                closeIntentDigest,
                incomingTxHash,
                receiverId,
                recipient,
                amount,
                personalNullifier
            )
        );
    }

    function closePIHash(
        uint64 channelId,
        uint64 closeNonce,
        uint64 finalEpoch,
        bytes32 finalChannelStateDigest,
        uint256 channelFundAmount,
        bytes32 channelFundIntmaxStateRoot,
        bytes32 settlementDigest,
        uint64 snapshotBlockNumber
    ) public pure returns (bytes32) {
        bytes32 closeIntentDigest = keccak256(
            abi.encodePacked(
                bytes4(CLOSE_INTENT_DOMAIN),
                channelId,
                closeNonce,
                finalEpoch,
                finalChannelStateDigest,
                channelId,
                channelFundAmount,
                channelFundIntmaxStateRoot,
                settlementDigest,
                snapshotBlockNumber
            )
        );
        return keccak256(
            abi.encodePacked(
                channelId,
                closeNonce,
                finalEpoch,
                finalChannelStateDigest,
                channelFundAmount,
                channelFundIntmaxStateRoot,
                settlementDigest,
                closeIntentDigest,
                snapshotBlockNumber
            )
        );
    }

    function cancelPIHash(
        uint64 channelId,
        bytes32 closeIntentDigest,
        bytes32 revivedInterChannelTxDigest,
        bytes32 revivedTxHash,
        bytes32 revivedSeal
    ) public pure returns (bytes32) {
        return keccak256(
            abi.encodePacked(
                channelId,
                closeIntentDigest,
                revivedInterChannelTxDigest,
                revivedTxHash,
                revivedSeal
            )
        );
    }

    function postCloseClaimPIHash(
        uint64 channelId,
        bytes32 closeIntentDigest,
        bytes32 incomingTxHash,
        uint64 receiverId,
        address recipient,
        uint64 amount,
        bytes32 personalNullifier
    ) public pure returns (bytes32) {
        return keccak256(
            abi.encodePacked(
                closeIntentDigest,
                channelId,
                incomingTxHash,
                receiverId,
                recipient,
                personalNullifier,
                amount
            )
        );
    }

    function _verify(
        bytes calldata proofBytes,
        bytes32 piHash
    ) internal view returns (bool) {
        (
            uint256[2] memory a,
            uint256[2][2] memory b,
            uint256[2] memory c,
            uint256[8] memory publicInputsFixed
        ) = abi.decode(proofBytes, (uint256[2], uint256[2][2], uint256[2], uint256[8]));
        if (!_publicInputsMatchPIHash(publicInputsFixed, piHash)) {
            return false;
        }

        uint256[] memory publicInputs = new uint256[](8);
        for (uint256 i = 0; i < 8; i++) {
            publicInputs[i] = publicInputsFixed[i];
        }
        Groth16Verifier.Proof memory proof = Groth16Verifier.Proof({a: a, b: b, c: c});
        return Groth16Verifier.verify(_vk(), proof, publicInputs);
    }

    function _publicInputsMatchPIHash(
        uint256[8] memory publicInputs,
        bytes32 piHash
    ) internal pure returns (bool) {
        uint256 h = uint256(piHash);
        for (uint256 i = 0; i < 8; i++) {
            uint256 limb = (h >> (224 - i * 32)) & 0xFFFFFFFF;
            if (publicInputs[i] != limb) return false;
        }
        return true;
    }

    function _vk() internal pure returns (Groth16Verifier.VerifyingKey memory vk) {
        vk.alpha = [uint256(1), uint256(2)];
        vk.beta = _g2Gen();
        vk.gamma = _g2Gen();
        vk.delta = _g2Gen();
        vk.ic = new uint256[2][](9);
        for (uint256 i = 0; i < 9; i++) {
            vk.ic[i] = [uint256(1), uint256(2)];
        }
    }

    function _g2Gen() internal pure returns (uint256[2][2] memory) {
        return [
            [uint256(0x1800deef121f1e76426a00665e5c4479674322d4f75edadd46debd5cd992f6ed),
             uint256(0x198e9393920d483a7260bfb731fb5d25f1aa493335a9e71297e485b7aef312c2)],
            [uint256(0x12c85ea5db8c6deb4aab71808dcb408fe3d1e7690c43d37b4ce6cc0166fa7daa),
             uint256(0x090689d0585ff075ec9e99ad690c3395bc4b313370b38ef355acdadcd122975b)]
        ];
    }
}

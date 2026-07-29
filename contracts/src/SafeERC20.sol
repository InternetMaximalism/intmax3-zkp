// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/// @notice Minimal ERC-20 surface used by the multi-token escrow (multitoken §N-7).
/// INTENTIONALLY SIMPLE: only the three functions the escrow needs — no allowance queries, no
/// metadata — to minimize attack surface and bytecode (IntmaxRollup rides close to EIP-170).
///
/// VENDORING NOTE: the repo vendors no OZ/solady ERC-20 library (contracts/lib holds only
/// forge-std and the polygon-plonky2 MLE verifier; the remappings.txt sol-whir entries are stale
/// leftovers with no lib behind them — foundry.toml's `remappings` key is authoritative), so this
/// minimal in-tree helper is the smallest consistent option — no new external dependency
/// (multitoken Phase 3, TM-4/TM-10).
interface IERC20 {
    function transfer(address to, uint256 amount) external returns (bool);
    function transferFrom(address from, address to, uint256 amount) external returns (bool);
    function balanceOf(address account) external view returns (uint256);
}

/// @notice Minimal safe-transfer helpers (missing-return-value tolerant, revert-on-false).
/// SECURITY (TM-4/TM-10a): a token call must be treated as UNTRUSTED code — the helpers revert
/// when the call fails OR when the token returns a decodable `false` (USDT-style tokens return no
/// data; that is accepted as success, per the de-facto SafeERC20 semantics). Callers remain
/// responsible for (a) reentrancy guards around any token call and (b) balanceOf-delta measurement
/// where the CREDITED amount must equal the RECEIVED amount (fee-on-transfer fail-closed).
/// Registration-time `code.length != 0` checks (see `IntmaxRollup.registerToken`) rule out the
/// no-code-address vacuous-success case.
library SafeERC20Lib {
    error TokenCallFailed();

    function safeTransfer(IERC20 token, address to, uint256 amount) internal {
        _callToken(token, abi.encodeCall(IERC20.transfer, (to, amount)));
    }

    function safeTransferFrom(IERC20 token, address from, address to, uint256 amount) internal {
        _callToken(token, abi.encodeCall(IERC20.transferFrom, (from, to, amount)));
    }

    function _callToken(IERC20 token, bytes memory data) private {
        (bool ok, bytes memory ret) = address(token).call(data);
        // OZ SafeERC20 semantics, exactly (review MINOR 1): success = the call succeeded AND
        // (empty return data OR a decodable >= 32-byte `true`). Empty return data is accepted
        // (non-standard USDT-style tokens); a registered token always has code (checked at
        // `registerToken`), so empty return data cannot be a no-code vacuous success on the
        // escrow paths. A nonzero-but-undecodable return (1-31 bytes) is MALFORMED and treated
        // as failure — never as success.
        if (!ok || !(ret.length == 0 || (ret.length >= 32 && abi.decode(ret, (bool))))) {
            revert TokenCallFailed();
        }
    }
}

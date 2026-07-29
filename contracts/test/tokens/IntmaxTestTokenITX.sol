// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/// @title IntmaxTestTokenITX — TESTNET-ONLY faucet token ($ITX)
///
/// @notice ███ TESTNET / LOCAL DEVNET ONLY. NOT A PRODUCTION CONTRACT. ███
///         This ERC-20 exists solely to back the in-channel $ITX faucet on anvil and public
///         testnets. It has no economic meaning, no upgrade path, no owner, and it deliberately
///         lives under `contracts/test/` — nothing in `contracts/src/` may import it, and it must
///         never appear in a mainnet deployment script.
///
/// @dev DESIGN NOTES (each is a deliberate difference from `TestTokens.sol:SimpleERC20`, which is a
///      test DOUBLE for the escrow suite rather than a deployable token):
///
///      * FIXED SUPPLY, MINTED ONCE TO THE DEPLOYER. There is no `mint`, no owner and no minter
///        role — the total supply is fixed at construction. `SimpleERC20.mint` is a free-for-all,
///        which is fine inside a test but wrong for anything that sits on a public testnet where
///        the faucet's own supply story ("the faucet can only run dry, never inflate") should hold
///        on L1 too.
///      * REAL `symbol` / `decimals`. `SimpleERC20` has neither, and the token manifest
///        (`node/tokens.json`) plus the wallet's display path both describe a token by symbol and
///        decimals. Note that neither carries any AUTHORITY: the authoritative identity is the
///        base `tokenIndex` bound set-once in `IntmaxRollup.tokenAddressOf`, and the relay serves
///        metadata only for entries whose manifest address reads back equal from that registry.
///      * FAITHFUL TRANSFERS. No fee-on-transfer, no hooks, no short returns — the rollup's ERC-20
///        deposit path measures a `balanceOf` delta and would (correctly) reject anything else.
///
///      INTENTIONALLY SIMPLE: a minimal, self-contained ERC-20 with no external dependencies, no
///      permit, no callbacks and no reentrancy surface. Less code is less attack surface, and this
///      contract will hold real (testnet) escrow on behalf of the faucet.
contract IntmaxTestTokenITX {
    string public constant name = "Intmax Test Token";
    string public constant symbol = "ITX";

    /// @notice 6, deliberately — NOT the reflexive 18.
    /// @dev In-channel balances are u64 BASE UNITS (`ChannelFund.amounts`, the CLI's `<amount>`
    ///      argument), so a channel position tops out at `u64::MAX / 10**decimals` whole tokens:
    ///      ~18.44 at 18 decimals (a faucet supply of 10 ITX already sits at 0.54 of u64::MAX —
    ///      1.8x headroom) versus ~18.4 trillion at 6. Nothing in this contract depends on the
    ///      value: it is a lone constant, escrow/deposit accounting is raw base units, and the
    ///      wallet's `fmtUnits(base, decimals)` is generic. It IS load-bearing for display, and it
    ///      is read back from this contract and compared against the manifest at relay/node
    ///      startup (`node/common/token-registry.js`) — a manifest that disagrees is a hard
    ///      startup failure, so this constant and `node/tokens.json` must change together.
    uint8 public constant decimals = 6;

    uint256 public immutable totalSupply;

    mapping(address => uint256) public balanceOf;
    mapping(address => mapping(address => uint256)) public allowance;

    event Transfer(address indexed from, address indexed to, uint256 value);
    event Approval(address indexed owner, address indexed spender, uint256 value);

    error TransferToZeroAddress();
    error InsufficientBalance(uint256 have, uint256 want);
    error InsufficientAllowance(uint256 have, uint256 want);

    /// @param initialSupply the entire supply, minted to `msg.sender`. Must be nonzero — a
    ///        zero-supply faucet token is an operator mistake, not a valid deployment.
    constructor(uint256 initialSupply) {
        require(initialSupply > 0, "ITX: zero supply");
        totalSupply = initialSupply;
        balanceOf[msg.sender] = initialSupply;
        emit Transfer(address(0), msg.sender, initialSupply);
    }

    function approve(address spender, uint256 amount) external returns (bool) {
        allowance[msg.sender][spender] = amount;
        emit Approval(msg.sender, spender, amount);
        return true;
    }

    function transfer(address to, uint256 amount) external returns (bool) {
        _move(msg.sender, to, amount);
        return true;
    }

    function transferFrom(address from, address to, uint256 amount) external returns (bool) {
        uint256 allowed = allowance[from][msg.sender];
        if (allowed != type(uint256).max) {
            if (allowed < amount) revert InsufficientAllowance(allowed, amount);
            unchecked {
                allowance[from][msg.sender] = allowed - amount;
            }
        }
        _move(from, to, amount);
        return true;
    }

    /// @dev The zero-address guard is not decorative: burning to address(0) here would silently
    ///      desynchronize `totalSupply` from the sum of balances, and the escrow's balanceOf-delta
    ///      accounting assumes a conservative transfer.
    function _move(address from, address to, uint256 amount) internal {
        if (to == address(0)) revert TransferToZeroAddress();
        uint256 bal = balanceOf[from];
        if (bal < amount) revert InsufficientBalance(bal, amount);
        unchecked {
            balanceOf[from] = bal - amount;
            balanceOf[to] += amount;
        }
        emit Transfer(from, to, amount);
    }
}

// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/// Local/testnet-only ERC-20 with permissionless, uncapped minting.
contract IntmaxTestTokenTEST {
    string public constant name = "Intmax Unlimited Test Token";
    string public constant symbol = "TEST";

    // Six decimals leave ample room in the channel's u64 base-unit balances.
    uint8 public constant decimals = 6;

    uint256 public totalSupply;

    mapping(address => uint256) public balanceOf;
    mapping(address => mapping(address => uint256)) public allowance;

    event Transfer(address indexed from, address indexed to, uint256 value);
    event Approval(address indexed owner, address indexed spender, uint256 value);

    error TransferToZeroAddress();
    error InsufficientBalance(uint256 have, uint256 want);
    error InsufficientAllowance(uint256 have, uint256 want);

    /// Anyone can mint 10 TEST per call. Test-only, no economic value.
    function mint() external { mint(msg.sender, 10 * 10 ** decimals); }

    /// Uncapped test mint, denominated in base units.
    function mint(address to, uint256 amount) public {
        if (to == address(0)) revert TransferToZeroAddress();
        totalSupply += amount;
        balanceOf[to] += amount;
        emit Transfer(address(0), to, amount);
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

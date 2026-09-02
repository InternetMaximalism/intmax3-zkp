// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/// @dev Test-double ERC-20s for the multi-token escrow suite (multitoken Phase 3, TM-4/TM-10).
/// INTENTIONALLY SIMPLE (CLAUDE.md: helper contracts that implement REAL interfaces with fixed
/// behavior — no crypto is faked): a plain ERC-20, a fee-on-transfer variant, an explicit
/// `false`-returning variant, and an ERC-777-style hook token that re-enters a target.

/// @notice Minimal standard ERC-20 (mint free-for-all — tests only).
contract SimpleERC20 {
    string public name;
    mapping(address => uint256) public balanceOf;
    mapping(address => mapping(address => uint256)) public allowance;

    constructor(string memory name_) {
        name = name_;
    }

    function mint(address to, uint256 amount) external {
        balanceOf[to] += amount;
    }

    function approve(address spender, uint256 amount) external returns (bool) {
        allowance[msg.sender][spender] = amount;
        return true;
    }

    function transfer(address to, uint256 amount) public virtual returns (bool) {
        _move(msg.sender, to, amount);
        return true;
    }

    function transferFrom(address from, address to, uint256 amount) public virtual returns (bool) {
        uint256 allowed = allowance[from][msg.sender];
        require(allowed >= amount, "allowance");
        if (allowed != type(uint256).max) {
            allowance[from][msg.sender] = allowed - amount;
        }
        _move(from, to, amount);
        return true;
    }

    function _move(address from, address to, uint256 amount) internal virtual {
        require(balanceOf[from] >= amount, "balance");
        balanceOf[from] -= amount;
        balanceOf[to] += amount;
    }
}

/// @notice Fee-on-transfer ERC-20: the recipient receives `amount - fee` (TM-4 negative — the
/// escrow's balanceOf-delta check must fail such deposits closed).
contract FeeOnTransferERC20 is SimpleERC20 {
    uint256 public immutable feeBps;
    constructor(uint256 feeBps_) SimpleERC20("FeeOnTransfer") {
        feeBps = feeBps_;
    }

    function _move(address from, address to, uint256 amount) internal override {
        require(balanceOf[from] >= amount, "balance");
        uint256 fee = (amount * feeBps) / 10_000;
        balanceOf[from] -= amount;
        balanceOf[to] += amount - fee; // fee is burned
    }
}

/// @notice Sender-selective fee token. It behaves exactly on deposit and Rollup-to-Manager pulls,
/// then under-delivers only when the configured Manager pays its final recipient. This models
/// upgradeable/role-based tokens whose transfer semantics can change after registration.
contract SenderFeeERC20 is SimpleERC20 {
    address public taxedSender;
    uint256 public immutable feeBps;

    constructor(uint256 feeBps_) SimpleERC20("SenderFee") {
        feeBps = feeBps_;
    }

    function setTaxedSender(address sender) external {
        taxedSender = sender;
    }

    function _move(address from, address to, uint256 amount) internal override {
        require(balanceOf[from] >= amount, "balance");
        uint256 fee = from == taxedSender ? (amount * feeBps) / 10_000 : 0;
        balanceOf[from] -= amount;
        balanceOf[to] += amount - fee;
    }
}

/// @notice ERC-20 that returns `false` instead of reverting (SafeERC20Lib must treat it as
/// failure).
contract FalseReturnERC20 is SimpleERC20 {
    constructor() SimpleERC20("FalseReturn") {}

    function transfer(address, uint256) public pure override returns (bool) {
        return false;
    }

    function transferFrom(address, address, uint256) public pure override returns (bool) {
        return false;
    }
}

/// @notice ERC-20 whose transfer functions MOVE real balances but return a MALFORMED 1-byte
/// `0x01` instead of a 32-byte bool (review MINOR 1 negative: SafeERC20Lib must treat any
/// nonzero-but-undecodable 1-31-byte return as FAILURE, exactly like OZ SafeERC20 — never as
/// success).
contract ShortReturnERC20 is SimpleERC20 {
    constructor() SimpleERC20("ShortReturn") {}

    function transfer(address to, uint256 amount) public override returns (bool) {
        _move(msg.sender, to, amount);
        assembly {
            mstore(0, 0x0100000000000000000000000000000000000000000000000000000000000000)
            return(0, 1) // single 0x01 byte — undecodable as bool
        }
    }

    function transferFrom(address from, address to, uint256 amount) public override returns (bool) {
        uint256 allowed = allowance[from][msg.sender];
        require(allowed >= amount, "allowance");
        if (allowed != type(uint256).max) {
            allowance[from][msg.sender] = allowed - amount;
        }
        _move(from, to, amount);
        assembly {
            mstore(0, 0x0100000000000000000000000000000000000000000000000000000000000000)
            return(0, 1) // single 0x01 byte — undecodable as bool
        }
    }
}

/// @notice ERC-777-style hook token: on `transfer`/`transferFrom` it calls back into a configured
/// target with configured calldata ONCE (the reentrancy attack vehicle for TM-10a). The token
/// moves REAL balances, so the escrow's delta check still sees a faithful transfer — only the
/// reentrancy attempt is adversarial.
contract ReentrantHookERC20 is SimpleERC20 {
    address public hookTarget;
    bytes public hookData;
    bool public hookOnTransferFrom; // fire during deposits (transferFrom) vs payouts (transfer)
    bool internal fired;
    bool public hookReverted; // records whether the reentrant call reverted (expected: true)

    constructor() SimpleERC20("ReentrantHook") {}

    function setHook(address target, bytes calldata data, bool onTransferFrom) external {
        hookTarget = target;
        hookData = data;
        hookOnTransferFrom = onTransferFrom;
        fired = false;
        hookReverted = false;
    }

    function transfer(address to, uint256 amount) public override returns (bool) {
        _move(msg.sender, to, amount);
        if (!hookOnTransferFrom) _fire();
        return true;
    }

    function transferFrom(address from, address to, uint256 amount) public override returns (bool) {
        uint256 allowed = allowance[from][msg.sender];
        require(allowed >= amount, "allowance");
        if (allowed != type(uint256).max) {
            allowance[from][msg.sender] = allowed - amount;
        }
        _move(from, to, amount);
        if (hookOnTransferFrom) _fire();
        return true;
    }

    function _fire() internal {
        if (hookTarget != address(0) && !fired) {
            fired = true;
            (bool ok, ) = hookTarget.call(hookData);
            // Record the (expected) rejection instead of bubbling it, so the OUTER call's own
            // guards are what the test observes.
            hookReverted = !ok;
        }
    }
}

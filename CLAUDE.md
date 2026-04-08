# Development Guidelines for Claude

## No Mocks or Dummies

**Never create mock or dummy implementations for cryptographic verification.**

This includes:
- Functions named `_mock*`, `mock*`, `Mock*`
- Functions named `_dummy*`, `dummy*`, `Dummy*`
- `vm.mockCall()` to fake precompile responses (ecPairing, BLS12-381, etc.)
- Fake proof data (placeholder curve points, zero-filled proofs, etc.)
- Fake verifying keys that don't correspond to a real circuit setup

Tests that require cryptographic verification (Groth16, WHIR, KZG) must use
real pre-generated proof fixtures. If fixtures are not yet available, the test
should not exist yet — do not write it with mocked crypto and call it a test.

**Acceptable in tests:**
- `vm.blobhashes()` to set up EIP-4844 blob transaction context (environment setup, not crypto faking)
- Helper contracts that implement real interfaces with simple fixed behavior (e.g., `FixedReturnForcedTxLogic`)
- `vm.prank()`, `vm.deal()`, `vm.expectRevert()` and other standard Foundry cheatcodes
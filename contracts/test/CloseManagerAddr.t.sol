// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

// MOVED (multitoken Phase 5b): the canonical close-manager CREATE2 address printer now lives in
// `CloseLifecycleE2E.t.sol` (`CloseLifecycleE2ETest.test_printCloseManagerAddress`) — run:
//
//   forge test --match-test test_printCloseManagerAddress -vv
//
// WHY IT MOVED: `type(MleVerifier).creationCode` embeds the linked external-library addresses
// (Plonky2GateEvaluator / SpongefishWhirVerify), and Foundry links those PER TEST CONTRACT — a
// printer in a separate test contract can compute a DIFFERENT MleVerifier (hence rollup, hence
// manager) CREATE2 address than the one `CloseLifecycleE2ETest` actually deploys to (observed
// during the Phase 5b regeneration: identical fixture inputs, different addresses across the two
// contracts). Only a printer INSIDE the lifecycle test contract is guaranteed to share its
// linking context. This file is kept as a pointer so old runbook references fail loudly here
// rather than silently printing a wrong address.

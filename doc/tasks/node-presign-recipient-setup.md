# Configuring cosigner payout recipients before the initial deposit

Applies to: the native CLI, and new-channel initialization from the API / Node that uses the same CLI.

## New production channels

In production key mode, which uses `INTMAX_COSIGNER_KEYFILE`, specify `CLI_RECIPIENT_SLOT_<slot>` explicitly for every controlled cosigner before `setup-backing`. The default cosigner count is 3, so in that case slots 0, 1, and 2 are the ones concerned. If `INTMAX_CLI_COSIGNERS` is increased, the additional slots are required too, and they cannot be omitted even when the initial balance is zero.

For each value, specify a 20-byte L1 address on which that participant can actually perform the payout operation. When launching the CLI from the API / Node, pass the same settings to the child process. Because configuration alone does not prove key ownership, operators must confirm the payout method on the target chain.

- For an EOA, the participant must hold the corresponding signing key themselves and have it backed up safely.
- For a smart wallet, it must be able to call the Manager's `claimWithdrawalCredit` from the wallet itself and receive the required native/token.
- Do not auto-assign everyone to the operator's address. Do not auto-generate new keys.
- Keep the settings available to both `setup-backing` and `init`. Before signing genesis, check that the resulting recipient for each slot is the intended payout destination.

In production key mode, unset values, empty values, malformed values, the zero address, and this channel's known synthetic cosigner defaults are all rejected. `setup-backing` inspects all slots before proof generation and before using the L1 signer. Genesis creation in `init` uses the same resolver.

## Test mode

Only the existing test mode, enabled by explicitly setting `INTMAX_INSECURE_DETERMINISTIC_KEYS=1`, may fall back to the previous `test_recipient_for` when nothing is set. That address is not a payout destination for real funds. In tests that check real payouts, specify a recoverable address explicitly.

Even in test mode, an explicitly specified value is rejected if it is malformed or zero. Combining a production keyfile with the insecure flag is still rejected, as before.

## Warning about existing signed H

This change does not rewrite the recipient in an existing H. Setting the environment variables after the fact does not fix an already-signed recipient. Nor does it stop normal operation, close, or claim on a healthy existing channel merely because the settings for a new genesis are missing.

If an existing H has a synthetic recipient and a positive balance, closing it as-is leaves no known key able to withdraw that slot's payout. First cross-check the latest fully signed H, the recipient of each slot, and the keys/wallets the participant can actually recover from. Do not try to resolve this by directly rewriting state files or recipients.

If everyone can cooperate and normal legitimate transitions are still possible, consider an agreed move to an existing recoverable slot, or migration to a new, correctly configured channel. Do not perform transitions that change the destination, and do not re-enable a halted MSU on your own authority. If the channel is already frozen or closed, or a required signer is absent, there is no guarantee that such a rescue is possible. Do not assume that a normal exit requiring no additional signatures has become possible.

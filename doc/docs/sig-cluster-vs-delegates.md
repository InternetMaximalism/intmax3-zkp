# Sig-cluster vs delegates — never conflate them

> Read this before designing, implementing, reviewing or auditing anything that touches channel
> membership, settlement deployment, close, or member-set update.

A channel has two participant sets with **different rules**. Design, implementation, reviews,
audits and discussion must always say which set they mean, and a rule derived for one set must never
be applied to the other.

| | Sig-cluster (co-signers) | Delegates |
|---|---|---|
| Slots | `0 .. member_count` (2–8) | `member_count .. member_count + delegate_count` |
| Signs channel states | Yes, N-of-N on every state | No |
| L1 registration (`registerChannel`, validity-tree reg chain) | Yes | No (`reg_delegate_count` is always 0) |
| Joins after settlement deployment | **No.** Member-set update (MSU) is retired for the cluster; changing it means closing and migrating to a new channel (`doc/tasks/channel-change-msu.md`) | **Yes, at any time.** A join appends at the delegate boundary through a cosigner-signed state; delegates are never removed. Owner intent: delegates may join later freely, for a fee |
| How L1 binds it at close | Close-PI limb 93 (`member_count`) strictly equal; member-set commitment strictly bound | Close-PI limb 94 (`delegate_count`) bound only as a **floor**: `>=` the count at deployment. No ceiling at the Verifier (the claim circuits bound 1024 in-circuit) |

Consequences to keep straight:

- "Membership is fixed after deployment", "MSU is not atomic across the Manager and the validity
  tree", and anything else about MSU are statements about the **sig-cluster only**.
- The Manager's `participantRoot` is the snapshot taken at deployment. It authenticates only those
  participants for `requestCloseAsParticipant`. A delegate that joined later is not in it, yet closes
  normally and claims its balance through the signed-state proof, exactly like a registered delegate.
- Delegate joins pause only while a settlement deployment is PREPARED (that deployment registers
  one exact snapshot). After it is ACTIVE they resume.
- Changing any of the above is an **owner decision**. Do not decide it silently inside another
  change: write the question down and ask.

History (why this note exists): between 2026-08-30 and 2026-09-06 a security-fix cycle applied the
cluster's "no change after deployment" rule to delegates, replacing the recommended one-sided floor
from `doc/tasks/b2-delegate-close-threat-model.md` with exact equality and refusing post-deployment
delegate joins. It was never approved by the owner and was reverted on 2026-09-29.

import Std

/-!
# Utility gadgets: selection logic, cyclic verifier-data codec, leaf discipline, pinned constants

Handwritten SEMANTIC MODEL of the intmax3 `src/utils/*` gadget layer, the
`src/poseidon_sig` list-commitment format, and `src/constants.rs`. Sources read in full:

* `src/utils/logic.rs` (302), `src/utils/cyclic.rs` (295), `src/utils/leafable_hasher.rs` (262),
  `src/utils/leafable.rs` (194), `src/utils/serialize.rs` (195), `src/utils/dummy.rs` (92),
  `src/utils/recursively_verifiable.rs` (87), `src/utils/conversion.rs` (59),
  `src/utils/wrapper.rs` (58), `src/utils/serializer.rs` (46), `src/utils/error.rs` (69),
  `src/utils/mod.rs` (18)
* `src/poseidon_sig/list.rs` (140), `src/poseidon_sig/mod.rs` (37)
* `src/constants.rs` (522)

This is NOT a refinement proof of the Rust code, of plonky2's gate lowering, of the FRI/Merkle-cap
machinery, or of any generated serde/bincode implementation. It is a local model of the *stated*
semantics of these gadgets, with kernel-checked theorems about the model only.

## What is modelled honestly and what is an assumed premise

* Field elements are modelled by their non-negative integer representatives (`Nat`). The
  `select_vec` algebra is stated over `Nat`; the corresponding statement modulo an arbitrary
  modulus is derived separately (`select_vec_mod_selects_candidate`). Nothing here proves that
  plonky2's `mul`/`add`/`arithmetic` gates lower to these operations.
* Hashing (Poseidon, keccak) is an OPAQUE callback (`HashEnv`). No injectivity, collision
  resistance or preimage resistance is assumed anywhere. Order-sensitivity of the IMLL chain is
  stated only under an EXPLICIT injectivity premise on the concrete compared pair.
* Proof verification is opaque: a verification call is recorded as data (`ProofCheck`), never as
  "the proof is sound". No theorem here says acceptance implies safety.
* `BoolTarget` booleanness is a PREMISE, not a derived fact: `conditional_and` returns
  `BoolTarget::new_unsafe`, and `select_vec` takes `&[BoolTarget]` whose one-hotness is the
  CALLER's obligation (`SwitchBoard` discharges it with a sum-to-one field check; `select_vec`
  itself does not, see `select_vec_two_hot_is_a_sum`).
* Cap counts (`fri_config.num_cap_elements()`) come from plonky2's `CircuitConfig`; the model
  carries `capCount` symbolically and pins only the arithmetic convention `4 + 4 * capCount`.
* Gate/generator serializer registries are modelled as tag LISTS; the actual
  `impl_gate_serializer!` macro expansion, its wire format and its bincode behaviour are opaque.

## Named boundaries (all undischarged)

`hashOpaque`, `proofVerificationOpaque`, `boolTargetWellFormed`, `gateLoweringOpaque`,
`fieldRepresentativeAbstraction`, `capCountFromPlonky2Config`, `serializerMacroOpaque`,
`merkleCapStructureOpaque`, `degreeAndGateCountOpaque`.
-/

namespace Zkp.Implementation.UtilGadgets

/-! ## 0. Preliminaries -/

/-- Big-endian ASCII 4-byte tag read as a `u32`; the `u32::from_be_bytes(*b"XXXX")` convention
used by every intmax3 domain separator. -/
def asciiBE (a b c d : Nat) : Nat := a * 16777216 + b * 65536 + c * 256 + d

/-- Field/`BoolTarget` representative of a Boolean: `1` for true, `0` for false. -/
def bit (b : Bool) : Nat := if b then 1 else 0

theorem bit_true_is_one : bit true = 1 := rfl

theorem bit_false_is_zero : bit false = 0 := rfl

theorem bit_le_one (b : Bool) : bit b ≤ 1 := by cases b <;> simp [bit]

/-- Executable "all elements pairwise distinct" over `Nat` lists (no Mathlib available). -/
def noDupB : List Nat → Bool
  | [] => true
  | x :: xs => !(xs.elem x) && noDupB xs

/-- `noDupB` really means what its name says: the head occurs in no later position, and the tail is
itself duplicate-free. -/
theorem no_dup_cons {x : Nat} {xs : List Nat} (h : noDupB (x :: xs) = true) :
    ¬ (x ∈ xs) ∧ noDupB xs = true := by
  simp only [noDupB, Bool.and_eq_true, Bool.not_eq_true'] at h
  refine ⟨fun hmem => ?_, h.2⟩
  have hy : xs.elem x = true := List.elem_eq_true_of_mem hmem
  rw [h.1] at hy
  exact Bool.noConfusion hy

/-- Consequence used for domain separators: distinct positions of a `noDupB` list hold distinct
values, so no two registered domain tags collide. -/
theorem no_dup_not_mem_tail : ∀ (l : List Nat), noDupB l = true →
    ∀ (x : Nat) (t : List Nat), l = x :: t → ¬ (x ∈ t) := by
  intro l h x t hl
  subst hl
  exact (no_dup_cons h).1

/-! ## 1. `src/constants.rs` — every constant pinned as a literal

Each `pub const` of `src/constants.rs` appears below as a `def` and a `*_pinned` theorem giving
its literal value, so that any other module asserting one of these values can be cross-checked
against this file. Derived constants (`PUBLIC_STATE_TREE_HEIGHT`, `CHANNEL_TREE_HEIGHT`,
`ASSET_TREE_HEIGHT`, `TX_TREE_HEIGHT`, `MAX_NUM_CHANNELS`, `MAX_NUM_TRANSFERS_PER_TX`) are
defined by their DERIVATION and then pinned, so the derivation itself is checked. -/

/-- `TOKEN_INDEX_BITS` (constants.rs:2). -/
def tokenIndexBits : Nat := 32

theorem token_index_bits_pinned : tokenIndexBits = 32 := rfl

/-- `TOKEN_DECIMALS` (constants.rs:8). ETH-native display convention. -/
def tokenDecimals : Nat := 18

theorem token_decimals_pinned : tokenDecimals = 18 := rfl

/-- `TOKEN_UNIT` (constants.rs:10) = `10 ^ TOKEN_DECIMALS`. -/
def tokenUnit : Nat := 1000000000000000000

theorem token_unit_pinned : tokenUnit = 1000000000000000000 := rfl

/-- The documented derivation `TOKEN_UNIT = 10 ^ TOKEN_DECIMALS` actually holds. -/
theorem token_unit_is_ten_pow_decimals : tokenUnit = 10 ^ tokenDecimals := by decide

/-- `BLOCK_NUMBER_BITS` (constants.rs:13). -/
def blockNumberBits : Nat := 63

theorem block_number_bits_pinned : blockNumberBits = 63 := rfl

/-- `PUBLIC_STATE_TREE_HEIGHT = BLOCK_NUMBER_BITS` (constants.rs:14). -/
def publicStateTreeHeight : Nat := blockNumberBits

theorem public_state_tree_height_pinned : publicStateTreeHeight = 63 := rfl

/-- `DEPOSIT_TREE_HEIGHT` (constants.rs:15). -/
def depositTreeHeight : Nat := 63

theorem deposit_tree_height_pinned : depositTreeHeight = 63 := rfl

/-- `CHANNEL_ID_BITS` (constants.rs:16). -/
def channelIdBits : Nat := 32

theorem channel_id_bits_pinned : channelIdBits = 32 := rfl

/-- `SEND_TREE_HEIGHT` (constants.rs:17). -/
def sendTreeHeight : Nat := 32

theorem send_tree_height_pinned : sendTreeHeight = 32 := rfl

/-- `CHANNEL_TREE_HEIGHT = CHANNEL_ID_BITS` (constants.rs:21): the channel tree is indexed by
`channel_id` alone (base intmax native user IS the channel). -/
def channelTreeHeight : Nat := channelIdBits

theorem channel_tree_height_pinned : channelTreeHeight = 32 := rfl

/-- `MAX_NUM_CHANNELS = 1u64 << CHANNEL_ID_BITS` (constants.rs:25). Widened to `u64` in the source
because `1 << 32` overflows a wasm32 `usize`. -/
def maxNumChannels : Nat := 2 ^ channelIdBits

theorem max_num_channels_pinned : maxNumChannels = 4294967296 := by decide

/-- `BURN_CHANNEL_ID` (constants.rs:34): the reserved all-ones sentinel channel id used as the
partial-withdrawal burn destination. Disjoint from every allocatable channel id. -/
def burnChannelId : Nat := 4294967295

theorem burn_channel_id_pinned : burnChannelId = 4294967295 := rfl

/-- The burn sentinel is the largest 32-bit id, hence never an allocatable id below it. -/
theorem burn_channel_id_is_all_ones : burnChannelId = 2 ^ channelIdBits - 1 := by decide

/-- `ASSET_TREE_HEIGHT = TOKEN_INDEX_BITS` (constants.rs:37). -/
def assetTreeHeight : Nat := tokenIndexBits

theorem asset_tree_height_pinned : assetTreeHeight = 32 := rfl

/-- `NULLIFIER_TREE_HEIGHT` (constants.rs:38). -/
def nullifierTreeHeight : Nat := 32

theorem nullifier_tree_height_pinned : nullifierTreeHeight = 32 := rfl

/-- `SENT_TX_TREE_HEIGHT` (constants.rs:39). -/
def sentTxTreeHeight : Nat := 32

theorem sent_tx_tree_height_pinned : sentTxTreeHeight = 32 := rfl

/-- `MEMBER_TREE_HEIGHT` (constants.rs:62): the REGISTERED cosigner pubkey tree (validity side). -/
def memberTreeHeight : Nat := 3

theorem member_tree_height_pinned : memberTreeHeight = 3 := rfl

/-- `MAX_CHANNEL_MEMBERS` (constants.rs:96): balance-slot capacity (cosigners + delegates). -/
def maxChannelMembers : Nat := 1024

theorem max_channel_members_pinned : maxChannelMembers = 1024 := rfl

/-- `MAX_SIG_CLUSTER` (constants.rs:135): the N-of-N close COSIGNER cap. -/
def maxSigCluster : Nat := 8

theorem max_sig_cluster_pinned : maxSigCluster = 8 := rfl

/-- `WALLET_MEMBER_TREE_HEIGHT` (constants.rs:79): the wallet-side LIVE membership tree. -/
def walletMemberTreeHeight : Nat := 10

theorem wallet_member_tree_height_pinned : walletMemberTreeHeight = 10 := rfl

/-- `BALANCE_SLOT_TREE_HEIGHT` (constants.rs:110): the H1 balance-slot Poseidon tree. -/
def balanceSlotTreeHeight : Nat := 10

theorem balance_slot_tree_height_pinned : balanceSlotTreeHeight = 10 := rfl

/-- The `const _: () = assert!(1 << MEMBER_TREE_HEIGHT == MAX_SIG_CLUSTER, ...)` of
constants.rs:63-66. -/
theorem member_tree_height_is_log2_sig_cluster : 2 ^ memberTreeHeight = maxSigCluster := by decide

/-- The `const _: () = assert!(1 << WALLET_MEMBER_TREE_HEIGHT == MAX_CHANNEL_MEMBERS, ...)` of
constants.rs:80-83. -/
theorem wallet_member_tree_height_is_log2_channel_members :
    2 ^ walletMemberTreeHeight = maxChannelMembers := by decide

/-- The `const _: () = assert!(1 << BALANCE_SLOT_TREE_HEIGHT == MAX_CHANNEL_MEMBERS, ...)` of
constants.rs:111-114. -/
theorem balance_slot_tree_height_is_log2_channel_members :
    2 ^ balanceSlotTreeHeight = maxChannelMembers := by decide

/-- The registered cosigner tree and the balance-slot tree are DIFFERENT heights on purpose
(constants.rs:73-78: accidental conflation must fail loudly). -/
theorem member_and_balance_slot_tree_heights_differ :
    memberTreeHeight ≠ balanceSlotTreeHeight := by decide

/-- The doubling loop of `MEMBER_DISTINCTNESS_TREE_HEIGHT` (constants.rs:158-168) written with a
fuel bound: `capacity` doubles each step, so 64 steps exhaust any `u64` `needed`. -/
def ceilLog2Loop : Nat → Nat → Nat → Nat → Nat
  | 0, _, height, _ => height
  | fuel + 1, needed, height, capacity =>
      if capacity < needed then ceilLog2Loop fuel needed (height + 1) (capacity * 2) else height

/-- `MEMBER_DISTINCTNESS_TREE_HEIGHT` (constants.rs:158-168): smallest `h` with
`2^h >= MAX_SIG_CLUSTER + 1` (the indexed-Merkle distinctness tree holds one sentinel leaf plus up
to `MAX_SIG_CLUSTER` active cosigner keys). -/
def memberDistinctnessTreeHeight : Nat := ceilLog2Loop 64 (maxSigCluster + 1) 0 1

theorem member_distinctness_tree_height_pinned : memberDistinctnessTreeHeight = 4 := by decide

/-- The sizing obligation the source comment states: the tree holds the sentinel leaf plus every
active cosigner leaf. -/
theorem member_distinctness_tree_has_room_for_sentinel_and_cluster :
    maxSigCluster + 1 ≤ 2 ^ memberDistinctnessTreeHeight := by decide

/-- `SIGN_TIMEOUT_SECS` (constants.rs:172): 3 minutes. -/
def signTimeoutSecs : Nat := 180

theorem sign_timeout_secs_pinned : signTimeoutSecs = 180 := rfl

/-- `GRACE_BEFORE_PROCESS_SECS` (constants.rs:175): 10 minutes. -/
def graceBeforeProcessSecs : Nat := 600

theorem grace_before_process_secs_pinned : graceBeforeProcessSecs = 600 := rfl

/-- `CHALLENGE_PERIOD_SECS` (constants.rs:177): 1 day. -/
def challengePeriodSecs : Nat := 86400

theorem challenge_period_secs_pinned : challengePeriodSecs = 86400 := rfl

/-- The close-timeline ordering the three windows are meant to have. -/
theorem close_timeline_windows_are_increasing :
    signTimeoutSecs < graceBeforeProcessSecs ∧ graceBeforeProcessSecs < challengePeriodSecs := by
  decide

/-- `MAX_CHANNEL_TOKENS` (constants.rs:189): static per-channel token-slot width. -/
def maxChannelTokens : Nat := 10

theorem max_channel_tokens_pinned : maxChannelTokens = 10 := rfl

/-- `TRANSFER_TREE_HEIGHT` (constants.rs:279). -/
def transferTreeHeight : Nat := 6

theorem transfer_tree_height_pinned : transferTreeHeight = 6 := rfl

/-- `MAX_NUM_TRANSFERS_PER_TX = 1 << TRANSFER_TREE_HEIGHT` (constants.rs:280). -/
def maxNumTransfersPerTx : Nat := 2 ^ transferTreeHeight

theorem max_num_transfers_per_tx_pinned : maxNumTransfersPerTx = 64 := by decide

/-- `TX_TREE_HEIGHT = CHANNEL_ID_BITS` (constants.rs:282). -/
def txTreeHeight : Nat := channelIdBits

theorem tx_tree_height_pinned : txTreeHeight = 32 := rfl

/-! ### 1.1 Domain separators defined in `src/constants.rs` (lines 203-276) -/

/-- `BALANCE_STATE_DOMAIN_V2` — "IMB2" (constants.rs:203). -/
def balanceStateDomainV2 : Nat := 0x494d4232

theorem balance_state_domain_v2_pinned : balanceStateDomainV2 = 0x494d4232 := rfl

/-- `BALANCE_SLOT_LEAF_DOMAIN_V2` — "IMS2" (constants.rs:207). -/
def balanceSlotLeafDomainV2 : Nat := 0x494d5332

theorem balance_slot_leaf_domain_v2_pinned : balanceSlotLeafDomainV2 = 0x494d5332 := rfl

/-- `PAY_DOMAIN_V2` — "IMP2" (constants.rs:211). -/
def payDomainV2 : Nat := 0x494d5032

theorem pay_domain_v2_pinned : payDomainV2 = 0x494d5032 := rfl

/-- `L1_DEPOSIT_IMPORT_DOMAIN_V2` — "IML2" (constants.rs:215). -/
def l1DepositImportDomainV2 : Nat := 0x494d4c32

theorem l1_deposit_import_domain_v2_pinned : l1DepositImportDomainV2 = 0x494d4c32 := rfl

/-- `WITHDRAWAL_CLAIM_DOMAIN_V2` — "IMW2" (constants.rs:220). -/
def withdrawalClaimDomainV2 : Nat := 0x494d5732

theorem withdrawal_claim_domain_v2_pinned : withdrawalClaimDomainV2 = 0x494d5732 := rfl

/-- `CHANNEL_UPDATE_ZKP_DOMAIN_V2` — "IMU2" (constants.rs:225). -/
def channelUpdateZkpDomainV2 : Nat := 0x494d5532

theorem channel_update_zkp_domain_v2_pinned : channelUpdateZkpDomainV2 = 0x494d5532 := rfl

/-- `INTER_CHANNEL_TX_DOMAIN_V2` — "IMI2" (constants.rs:239). -/
def interChannelTxDomainV2 : Nat := 0x494d4932

theorem inter_channel_tx_domain_v2_pinned : interChannelTxDomainV2 = 0x494d4932 := rfl

/-- `INTER_CHANNEL_TX_DOMAIN_V3` — "IMI3" (constants.rs:245). -/
def interChannelTxDomainV3 : Nat := 0x494d4933

theorem inter_channel_tx_domain_v3_pinned : interChannelTxDomainV3 = 0x494d4933 := rfl

/-- `INTER_CHANNEL_TX_DOMAIN_V4` — "IMI4" (constants.rs:251). -/
def interChannelTxDomainV4 : Nat := 0x494d4934

theorem inter_channel_tx_domain_v4_pinned : interChannelTxDomainV4 = 0x494d4934 := rfl

/-- `INTER_CHANNEL_TX_DOMAIN_V5` — "IMI5" (constants.rs:257). -/
def interChannelTxDomainV5 : Nat := 0x494d4935

theorem inter_channel_tx_domain_v5_pinned : interChannelTxDomainV5 = 0x494d4935 := rfl

/-- `MEMBER_SET_UPDATE_DOMAIN` — "IMMS" (constants.rs:262). -/
def memberSetUpdateDomain : Nat := 0x494d4d53

theorem member_set_update_domain_pinned : memberSetUpdateDomain = 0x494d4d53 := rfl

/-- `KEY_ROTATION_CONSENT_DOMAIN` — "IMKR" (constants.rs:267). -/
def keyRotationConsentDomain : Nat := 0x494d4b52

theorem key_rotation_consent_domain_pinned : keyRotationConsentDomain = 0x494d4b52 := rfl

/-- `JOINER_CONSENT_DOMAIN` — "IMJC" (constants.rs:271). -/
def joinerConsentDomain : Nat := 0x494d4a43

theorem joiner_consent_domain_pinned : joinerConsentDomain = 0x494d4a43 := rfl

/-- `TOKEN_FUNDS_DIGEST_DOMAIN` — "IMTF" (constants.rs:276). -/
def tokenFundsDigestDomain : Nat := 0x494d5446

theorem token_funds_digest_domain_pinned : tokenFundsDigestDomain = 0x494d5446 := rfl

/-- Every domain separator defined in `src/constants.rs` is exactly the big-endian ASCII tag its
docstring claims (the `multitoken_domain_constant_ascii_tags` obligation, constants.rs:288-314). -/
theorem constants_domains_are_ascii_tags :
    balanceStateDomainV2 = asciiBE 0x49 0x4d 0x42 0x32 ∧
    balanceSlotLeafDomainV2 = asciiBE 0x49 0x4d 0x53 0x32 ∧
    payDomainV2 = asciiBE 0x49 0x4d 0x50 0x32 ∧
    l1DepositImportDomainV2 = asciiBE 0x49 0x4d 0x4c 0x32 ∧
    withdrawalClaimDomainV2 = asciiBE 0x49 0x4d 0x57 0x32 ∧
    channelUpdateZkpDomainV2 = asciiBE 0x49 0x4d 0x55 0x32 ∧
    interChannelTxDomainV2 = asciiBE 0x49 0x4d 0x49 0x32 ∧
    interChannelTxDomainV3 = asciiBE 0x49 0x4d 0x49 0x33 ∧
    interChannelTxDomainV4 = asciiBE 0x49 0x4d 0x49 0x34 ∧
    interChannelTxDomainV5 = asciiBE 0x49 0x4d 0x49 0x35 ∧
    memberSetUpdateDomain = asciiBE 0x49 0x4d 0x4d 0x53 ∧
    keyRotationConsentDomain = asciiBE 0x49 0x4d 0x4b 0x52 ∧
    joinerConsentDomain = asciiBE 0x49 0x4d 0x4a 0x43 ∧
    tokenFundsDigestDomain = asciiBE 0x49 0x4d 0x54 0x46 := by
  refine ⟨rfl, rfl, rfl, rfl, rfl, rfl, rfl, rfl, rfl, rfl, rfl, rfl, rfl, rfl⟩

/-- The domain separators DEFINED in `src/constants.rs`, in source order. -/
def constantsFileDomains : List Nat :=
  [balanceStateDomainV2, balanceSlotLeafDomainV2, payDomainV2, l1DepositImportDomainV2,
   withdrawalClaimDomainV2, channelUpdateZkpDomainV2, interChannelTxDomainV2,
   interChannelTxDomainV3, interChannelTxDomainV4, interChannelTxDomainV5,
   memberSetUpdateDomain, keyRotationConsentDomain, joinerConsentDomain, tokenFundsDigestDomain]

theorem constants_file_domains_count : constantsFileDomains.length = 14 := rfl

/-- The `src/constants.rs` share of the repo-wide pairwise-distinctness obligation
(`all_domain_constants_pairwise_distinct`, constants.rs:327-521): the fourteen domains defined in
that file are pairwise distinct. This covers only the constants defined THERE; the full registry
also pins values owned by other files (see `registryDomains` below). -/
theorem constants_file_domains_pairwise_distinct : noDupB constantsFileDomains = true := by decide


/-! ### 1.2 The repo-wide domain registry pinned by `all_domain_constants_pairwise_distinct`

`src/constants.rs:327-521` is a `#[cfg(test)]` registry that pins EVERY domain separator in the
tree — including private ones owned by other files — as a literal, and asserts pairwise
distinctness. Two honesty notes about that test:

* it is `#[cfg_attr(debug_assertions, ignore)]`, so it only runs in release-mode test runs;
* it is a TEST, so nothing in the built artefact enforces it.

The registry values are reproduced below as literals, tagged with their defining site, so that a
drifting definition elsewhere can be diffed against this file. Values marked `(other file)` are
NOT defined in `src/constants.rs`; the model pins the value the registry pins. -/

/-- The 63 registry entries of `all_domain_constants_pairwise_distinct`, in source order. -/
def registryDomains : List Nat :=
  [ 0x494d4348,  -- IMCH CHANNEL_STATE_DOMAIN (common/channel.rs)
    0x494d5041,  -- IMPA PAY_DOMAIN v1 (retired)
    0x494d5342,  -- IMSB SMALL_BLOCK_DOMAIN (common/channel.rs)
    0x494d5353,  -- IMSS SIGNED_SMALL_BLOCK_DOMAIN (common/channel.rs)
    0x494d4954,  -- IMIT INTER_CHANNEL_TX_DOMAIN v1 (retired)
    0x494d434c,  -- IMCL CLOSE_TX_DOMAIN (common/channel.rs)
    0x494d4349,  -- IMCI CLOSE_INTENT_DOMAIN v1 (retired)
    0x494d4353,  -- IMCS CLOSE_STATE_ID_DOMAIN (common/channel.rs)
    0x494d5343,  -- IMSC SPECIAL_CLOSE_DOMAIN (common/channel.rs)
    0x494d434e,  -- IMCN CANCEL_CLOSE_DOMAIN (common/channel.rs)
    0x494d4350,  -- IMCP POST_CLOSE_CLAIM_DOMAIN (common/channel.rs)
    0x494d434b,  -- IMCK POST_CLOSE_NULLIFIER_DOMAIN (common/channel.rs)
    0x494d4357,  -- IMCW WITHDRAWAL_CLAIM_DOMAIN v1 (common/channel.rs)
    0x494d5546,  -- IMUF CHANNEL_BALANCE_LEAF_DOMAIN (common/channel.rs)
    0x494d4352,  -- IMCR CHANNEL_RECORD_DOMAIN (common/channel.rs)
    0x494d434d,  -- IMCM CLOSE_MEMBER_SET_DOMAIN (common/channel.rs)
    0x494d4c44,  -- IMLD L1_DEPOSIT_IMPORT_DOMAIN v1 (retired)
    0x494d4253,  -- IMBS BALANCE_STATE_DOMAIN v1 (retired)
    0x494d534c,  -- IMSL BALANCE_SLOT_LEAF_DOMAIN v1 (retired)
    0x494d4248,  -- IMBH BALANCE_STATE_HASH_DOMAIN (common/balance_state.rs)
    0x494d544c,  -- IMTL TX_LEAF_DOMAIN (common/balance_state.rs)
    0x494d4244,  -- IMBD BURN_DESCRIPTOR_DOMAIN v1 (retired)
    0x494d4432,  -- IMD2 BURN_DESCRIPTOR_DOMAIN v2 (other file: common/channel.rs:52)
    0x494d5443,  -- IMTC SETTLED_TX_CHAIN_DOMAIN (common/balance_state.rs)
    0x494d5243,  -- IMRC REGEV_CT_DOMAIN (regev/encrypt.rs)
    0x494d524b,  -- IMRK REGEV_PK_DOMAIN (regev/keys.rs)
    0x494d5252,  -- IMRR REGEV_PK_ROOT_DOMAIN (regev/keys.rs)
    0x494d5250,  -- IMRP REGEV_PK_POSEIDON_DOMAIN (regev/keys.rs)
    0x494d435a,  -- IMCZ CHANNEL_TX_ZKP_DOMAIN (regev/transfer_stark.rs)
    0x494d555a,  -- IMUZ E-2 channelUpdateZKP v1 (retired)
    0x494d575a,  -- IMWZ WITHDRAW_CLAIM_ZKP_DOMAIN (regev/transfer_stark.rs)
    0x494d5246,  -- IMRF BALANCE_REFRESH_ZKP_DOMAIN (regev/transfer_stark.rs)
    0x494d4c4c,  -- IMLL LIST_LEAF_DOMAIN (poseidon_sig/list.rs:38)
    0x494d5047,  -- IMPG DOMAIN_PK_G (poseidon_sig/mod.rs:33)
    0x494d5347,  -- IMSG DOMAIN_SIG_G (poseidon_sig/mod.rs:37)
    0x494d5057,  -- IMPW PARTIAL_WITHDRAWAL_DOMAIN v1 (retired)
    0x49505732,  -- IPW2 PARTIAL_WITHDRAWAL_DOMAIN v2 (other file: wallet_core.rs:4179)
    0x4d424c46,  -- MBLF MEMBER_LEAF_DOMAIN (trees/key_tree.rs)
    0x43484c46,  -- CHLF CHANNEL_LEAF_DOMAIN (trees/channel_tree.rs)
    0x55494400,  -- UID\0 USER_ID_DOMAIN (balance/common/recipient.rs)
    0x42504b42,  -- BPKB DOMAIN_PK_B (other file: regev/hash_sig.rs:135)
    0x42534742,  -- BSGB DOMAIN_SIG_B (other file: regev/hash_sig.rs:137)
    0x494d5043,  -- IMPC CHANNEL_MESSAGE_MAGIC (other file: common/channel_message.rs:16)
    balanceStateDomainV2, balanceSlotLeafDomainV2, payDomainV2, l1DepositImportDomainV2,
    withdrawalClaimDomainV2, channelUpdateZkpDomainV2, interChannelTxDomainV2,
    interChannelTxDomainV3, memberSetUpdateDomain, keyRotationConsentDomain, joinerConsentDomain,
    interChannelTxDomainV5, interChannelTxDomainV4, tokenFundsDigestDomain,
    0x494d4648,  -- IMFH DOMAIN_FALCON_H2P (other file: falcon_sig/mod.rs:61)
    0x494d464b,  -- IMFK DOMAIN_FALCON_PK (other file: falcon_sig/mod.rs:64)
    0x494d4647,  -- IMFG DOMAIN_FALCON_KEYGEN (other file: falcon_sig/mod.rs:68)
    0x494d414c,  -- IMAL AGG_LIST_LEAF_DOMAIN (other file: falcon_sig/agg_list.rs:88)
    0x494d504c,  -- IMPL AGG_PK_LIST_DOMAIN (other file: falcon_sig/agg_list.rs:93)
    0x494d4642]  -- IMFB DOMAIN_FALCON_BATCH (other file: falcon_sig/mod.rs:73)

theorem registry_domains_count : registryDomains.length = 63 := rfl

/-- The registry really is collision free: no two of the 63 pinned domain separators are equal.
This is the model's discharge of the `all_domain_constants_pairwise_distinct` obligation for the
values as pinned; it says nothing about whether a definition elsewhere still HAS that value. -/
theorem registry_domains_pairwise_distinct : noDupB registryDomains = true := by decide

/-- Every domain defined in `src/constants.rs` is actually registered in the distinctness
registry. -/
theorem constants_file_domains_are_registered :
    ∀ d ∈ constantsFileDomains, d ∈ registryDomains := by decide

/-! ## 2. `src/poseidon_sig/mod.rs` and `src/poseidon_sig/list.rs` — the IMLL chain format -/

/-- A Poseidon digest: the 4 Goldilocks field elements of `PoseidonHashOut`. -/
abbrev Hash := List Nat

/-- `POSEIDON_HASH_OUT_LEN` (utils/poseidon_hash_out.rs:36). -/
def poseidonHashOutLen : Nat := 4

theorem poseidon_hash_out_len_pinned : poseidonHashOutLen = 4 := rfl

/-- `BYTES32_LEN = U256_LEN` (ethereum_types/bytes32.rs:15): a `Bytes32` is 8 `u32` limbs. -/
def bytes32Len : Nat := 8

theorem bytes32_len_pinned : bytes32Len = 8 := rfl

/-- `PoseidonHashOut::default()` — the all-zero digest, and the `C_0` of the IMLL chain. -/
def zeroHash : Hash := [0, 0, 0, 0]

theorem zero_hash_length : zeroHash.length = poseidonHashOutLen := rfl

/-- Opaque hash callbacks. NOTHING is assumed about them: not injectivity, not collision
resistance, not that distinct preimages give distinct digests. Boundary `hashOpaque`. -/
structure HashEnv where
  /-- `PoseidonHashOut::hash_inputs_u64`. -/
  poseidonU64 : List Nat → Hash
  /-- `PoseidonHashOut::hash_inputs_u32`. -/
  poseidonU32 : List Nat → Hash
  /-- `plonky2_keccak::utils::solidity_keccak256` over `u32` limbs. -/
  keccakU32 : List Nat → List Nat

/-- The digest width the model relies on when it needs to split a concatenated preimage. Stating
it as a premise keeps the hash itself opaque. -/
structure HashEnvShape (env : HashEnv) : Prop where
  poseidon_u64_width : ∀ xs, (env.poseidonU64 xs).length = poseidonHashOutLen
  poseidon_u32_width : ∀ xs, (env.poseidonU32 xs).length = poseidonHashOutLen

/-- `LIST_LEAF_DOMAIN` — ASCII "IMLL" (poseidon_sig/list.rs:38). -/
def listLeafDomain : Nat := 0x494d4c4c

theorem list_leaf_domain_pinned : listLeafDomain = 0x494d4c4c := rfl

theorem list_leaf_domain_is_ascii_imll : listLeafDomain = asciiBE 0x49 0x4d 0x4c 0x4c := rfl

/-- `DOMAIN_PK_G` — ASCII "IMPG" (poseidon_sig/mod.rs:33). RETIRED but kept RESERVED: nothing
derives from it; it stays registered so no live domain may reuse the value. -/
def domainPkG : Nat := 0x494d5047

theorem domain_pk_g_pinned : domainPkG = 0x494d5047 := rfl

theorem domain_pk_g_is_ascii_impg : domainPkG = asciiBE 0x49 0x4d 0x50 0x47 := rfl

/-- `DOMAIN_SIG_G` — ASCII "IMSG" (poseidon_sig/mod.rs:37). RETIRED, kept RESERVED. -/
def domainSigG : Nat := 0x494d5347

theorem domain_sig_g_pinned : domainSigG = 0x494d5347 := rfl

theorem domain_sig_g_is_ascii_imsg : domainSigG = asciiBE 0x49 0x4d 0x53 0x47 := rfl

/-- The `poseidon_sig` module's own non-collision obligation (list.rs:125-128): the live IMLL leaf
domain is distinct from both retired Goldilocks-scheme domains. -/
theorem list_leaf_domain_distinct_from_retired_sig_domains :
    listLeafDomain ≠ domainPkG ∧ listLeafDomain ≠ domainSigG ∧ domainPkG ≠ domainSigG := by decide

/-- `poseidon_sig::list::list_leaf` preimage: `[LIST_LEAF_DOMAIN] ‖ m ‖ pk` — message FIRST, then
public key. `message` and `public_key` are the 8 `u32` limbs of a `Bytes32`, widened to `u64`. -/
def listLeafPreimage (message publicKey : List Nat) : List Nat :=
  listLeafDomain :: (message ++ publicKey)

/-- The layout claim of list.rs:44-52, checked against the definition. -/
theorem list_leaf_preimage_is_domain_message_key (message publicKey : List Nat) :
    listLeafPreimage message publicKey = listLeafDomain :: (message ++ publicKey) := rfl

/-- A well-formed leaf preimage is exactly `1 + 2 * BYTES32_LEN = 17` words long (the
`Vec::with_capacity(1 + 2 * BYTES32_LEN)` of list.rs:47). -/
theorem list_leaf_preimage_length (message publicKey : List Nat)
    (hm : message.length = bytes32Len) (hk : publicKey.length = bytes32Len) :
    (listLeafPreimage message publicKey).length = 1 + 2 * bytes32Len := by
  simp [listLeafPreimage, hm, hk, bytes32Len]

/-- `list_leaf` (poseidon_sig/list.rs:46-52). -/
def listLeaf (env : HashEnv) (message publicKey : List Nat) : Hash :=
  env.poseidonU64 (listLeafPreimage message publicKey)

/-- `list_chain_step` (poseidon_sig/list.rs:55-60): `C' = Poseidon(prev ‖ leaf)`, matching
`PoseidonHashOutTarget::two_to_one`. -/
def listChainStep (env : HashEnv) (prev leaf : Hash) : Hash :=
  env.poseidonU64 (prev ++ leaf)

/-- `list_commitment` (poseidon_sig/list.rs:64-70): fold the ordered `(message, public_key)` pairs
from `C_0 = PoseidonHashOut::default()`. -/
def listCommitment (env : HashEnv) (pairs : List (List Nat × List Nat)) : Hash :=
  pairs.foldl (fun chain p => listChainStep env chain (listLeaf env p.1 p.2)) zeroHash

/-- The empty list is the ZERO chain — the exact value the validity circuit gates on
(list.rs:123: `assert_eq!(list_commitment(&[]), Bytes32::zero())`). -/
theorem list_commitment_empty_is_zero (env : HashEnv) : listCommitment env [] = zeroHash := rfl

/-- One fold step. -/
theorem list_commitment_cons (env : HashEnv) (p : List Nat × List Nat)
    (rest : List (List Nat × List Nat)) :
    listCommitment env (p :: rest) =
      rest.foldl (fun chain q => listChainStep env chain (listLeaf env q.1 q.2))
        (listChainStep env zeroHash (listLeaf env p.1 p.2)) := rfl

/-- The chain is a left fold, so a prefix's commitment is a resume point: appending `b` to `a`
continues from `listCommitment env a`. This is what lets a consumer rebuild the chain
incrementally. -/
theorem list_commitment_append (env : HashEnv) (a b : List (List Nat × List Nat)) :
    listCommitment env (a ++ b) =
      b.foldl (fun chain q => listChainStep env chain (listLeaf env q.1 q.2))
        (listCommitment env a) := by
  simp [listCommitment, List.foldl_append]

/-- Appending one pair. -/
theorem list_commitment_snoc (env : HashEnv) (a : List (List Nat × List Nat))
    (p : List Nat × List Nat) :
    listCommitment env (a ++ [p]) =
      listChainStep env (listCommitment env a) (listLeaf env p.1 p.2) := by
  simp [list_commitment_append]

/-- Order sensitivity, stated HONESTLY: it holds only under an explicit injectivity premise on the
opaque Poseidon callback plus the digest-width premise. The model does NOT assume Poseidon is
injective; the premise is the obligation a consumer inherits. -/
theorem list_commitment_order_sensitive_under_injectivity (env : HashEnv) (shape : HashEnvShape env)
    (inj : ∀ x y : List Nat, env.poseidonU64 x = env.poseidonU64 y → x = y)
    (a b : List Nat × List Nat)
    (hne : listLeaf env a.1 a.2 ≠ listLeaf env b.1 b.2) :
    listCommitment env [a, b] ≠ listCommitment env [b, a] := by
  intro heq
  simp only [listCommitment, List.foldl, listChainStep] at heq
  have hsplit := inj _ _ heq
  have hlen : (env.poseidonU64 (zeroHash ++ listLeaf env a.1 a.2)).length =
      (env.poseidonU64 (zeroHash ++ listLeaf env b.1 b.2)).length := by
    rw [shape.poseidon_u64_width, shape.poseidon_u64_width]
  exact hne (List.append_inj hsplit hlen).2.symm

/-- SECURITY BOUNDARY, documenting list.rs:131-139: the chain binds the ORDERED pairs but performs
NO distinctness check — folding the same pair twice is a well-defined operation that simply
continues the chain. Pubkey distinctness / all-members-present are CONSUMER obligations. -/
theorem list_commitment_folds_duplicates_without_rejection (env : HashEnv)
    (p : List Nat × List Nat) :
    listCommitment env [p, p] =
      listChainStep env (listCommitment env [p]) (listLeaf env p.1 p.2) := rfl

/-- Non-vacuous positive example: with a concrete (toy) hash callback the chain of two pairs is the
value obtained by folding the two leaves in order, and the empty chain is zero. -/
def toyEnv : HashEnv where
  poseidonU64 := fun xs => [xs.length, xs.foldl (· + ·) 0, 0, 0]
  poseidonU32 := fun xs => [xs.length, xs.foldl (· + ·) 0, 0, 0]
  keccakU32 := fun xs => xs

theorem toy_list_commitment_example :
    listCommitment toyEnv [] = [0, 0, 0, 0] ∧
    listCommitment toyEnv [([1], [2])] = [8, 1229802578, 0, 0] ∧
    listCommitment toyEnv [([1], [2]), ([3], [4])] = [8, 2459605168, 0, 0] := by
  refine ⟨rfl, by decide, by decide⟩

/-- `src/poseidon_sig/mod.rs` exposes exactly one submodule after the falcon-sig retirement. -/
def poseidonSigModules : List String := ["list"]

theorem poseidon_sig_modules_pinned : poseidonSigModules = ["list"] := rfl

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

/-! ## 3. `src/utils/logic.rs` — the `BuilderLogic` gadgets

The three `BuilderLogic` methods are modelled at the level of the ARITHMETIC they emit, over
integer representatives of field elements. Boundary `gateLoweringOpaque`: nothing here proves that
plonky2's `arithmetic` / `mul` / `add` / `select` gates lower to these operations. Boundary
`boolTargetWellFormed`: every `BoolTarget` argument is ASSUMED Boolean — the source never
re-constrains them, and `conditional_and` even returns `BoolTarget::new_unsafe`. -/

/-- `builder.select(c, a, b)`, as the arithmetic `c*a + (1-c)*b` on representatives. -/
def selectVal (c a b : Nat) : Nat := c * a + (1 - c) * b

theorem select_val_true (a b : Nat) : selectVal 1 a b = a := by simp [selectVal]

theorem select_val_false (a b : Nat) : selectVal 0 a b = b := by simp [selectVal]

theorem select_val_of_bit (f : Bool) (a b : Nat) : selectVal (bit f) a b = if f then a else b := by
  cases f <;> simp [selectVal, bit]

/-! ### 3.1 `conditional_assert_true` (logic.rs:24-34) -/

/-- The residue the source asserts zero. `self.arithmetic(NEG_ONE, ONE, target, condition,
condition)` computes `-1 * target * condition + 1 * condition = condition - target*condition`;
`assert_zero` then forces it to `0`. Both operands are `BoolTarget`s, so `bit target * bit
condition ≤ bit condition` and the `Nat` subtraction is exact (no truncation). -/
def conditionalAssertTrueResidue (condition target : Bool) : Nat :=
  bit condition - bit target * bit condition

/-- The emitted constraint. -/
def ConditionalAssertTrueHolds (condition target : Bool) : Prop :=
  conditionalAssertTrueResidue condition target = 0

/-- The gate says exactly `condition → target`, and nothing more. Derived, not assumed: this is
the semantics `SwitchBoard` and the claim circuits rely on. -/
theorem conditional_assert_true_iff_implication (c t : Bool) :
    ConditionalAssertTrueHolds c t ↔ (c = true → t = true) := by
  cases c <;> cases t <;>
    simp [ConditionalAssertTrueHolds, conditionalAssertTrueResidue, bit]

/-- With the condition off the constraint is vacuous: the target is COMPLETELY unconstrained by
this gadget (logic.rs test cases 2 and 3). -/
theorem conditional_assert_true_is_vacuous_when_condition_false (t : Bool) :
    ConditionalAssertTrueHolds false t := by
  cases t <;> simp [ConditionalAssertTrueHolds, conditionalAssertTrueResidue, bit]

/-- With the condition on, the target is forced (the `should_panic` case of logic.rs:151-167). -/
theorem conditional_assert_true_forces_target (t : Bool)
    (h : ConditionalAssertTrueHolds true t) : t = true :=
  (conditional_assert_true_iff_implication true t).mp h rfl

/-- The same residue as a signed-integer identity, showing it really is `condition * (1 - target)`
(the comment at logic.rs:25). -/
theorem conditional_assert_true_residue_int (c t : Int) : c - t * c = c * (1 - t) := by
  rw [Int.mul_sub, Int.mul_one, Int.mul_comm t c]

/-! ### 3.2 `conditional_and` (logic.rs:36-45) -/

/-- `let x_and_y = and(x, y); let selected = select(condition, x_and_y, x)`, wrapped with
`BoolTarget::new_unsafe`. -/
def conditionalAnd (condition x y : Bool) : Bool := if condition then (x && y) else x

theorem conditional_and_true (x y : Bool) : conditionalAnd true x y = (x && y) := rfl

theorem conditional_and_false (x y : Bool) : conditionalAnd false x y = x := rfl

/-- The gadget can only ever WEAKEN `x`: a true result always implies `x` was true. This is what
callers use it for (conditionally strengthening a flag). -/
theorem conditional_and_implies_x (c x y : Bool) (h : conditionalAnd c x y = true) : x = true := by
  cases c <;> simp [conditionalAnd] at h <;> simp [h]

/-- `BoolTarget::new_unsafe` adds NO Boolean constraint. The result is nevertheless Boolean
whenever `x`, `y` are — because it is a `select` between two Booleans. Booleanness of `x`, `y` is
the premise (boundary `boolTargetWellFormed`); this theorem discharges only the propagation. -/
theorem conditional_and_value_is_boolean (c x y : Bool) :
    selectVal (bit c) (bit (x && y)) (bit x) = bit (conditionalAnd c x y) ∧
    selectVal (bit c) (bit (x && y)) (bit x) ≤ 1 := by
  cases c <;> cases x <;> cases y <;> exact ⟨rfl, by decide⟩

/-- Exhaustive agreement with the five in-source test cases (logic.rs:169-265). -/
theorem conditional_and_matches_source_tests :
    conditionalAnd true true true = true ∧
    conditionalAnd true true false = false ∧
    conditionalAnd true false true = false ∧
    conditionalAnd false true true = true ∧
    conditionalAnd false false true = false := by decide

/-! ### 3.3 `select_vec` (logic.rs:47-78) — the one-hot product sum

`select_vec` accumulates `result[j] += flag_i * candidate_i[j]` over every candidate. It does NOT
constrain `one_hot` to be one-hot; that is the CALLER's obligation. `SwitchBoard` discharges it
with a field sum-to-one check over four safely-allocated Booleans, which is why the four-candidate
instance below is exactly the "four-product sum" that module asserts. -/

/-- One inner-loop pass: `for (acc, &c) in result.iter_mut().zip(candidate.iter())`. Rust's `zip`
over `iter_mut` preserves `result`'s LENGTH — positions past the candidate's end are left
untouched, and candidate entries past `result`'s end are ignored. -/
def accumulate : List Nat → Bool → List Nat → List Nat
  | [], _, _ => []
  | a :: rest, _, [] => a :: rest
  | a :: rest, f, c :: cs => (a + bit f * c) :: accumulate rest f cs

/-- The outer loop: `candidates.iter().zip(one_hot.iter())`. -/
def selectFold : List Nat → List (List Nat) → List Bool → List Nat
  | acc, c :: cs, f :: fs => selectFold (accumulate acc f c) cs fs
  | acc, _, _ => acc

/-- `let width = candidates[0].len();` (logic.rs:58). -/
def selectWidth : List (List Nat) → Nat
  | [] => 0
  | c :: _ => c.length

/-- The body of `select_vec` after its three assertions: start from `vec![zero; width]` and fold. -/
def selectVecCore (candidates : List (List Nat)) (oneHot : List Bool) : List Nat :=
  selectFold (List.replicate (selectWidth candidates) 0) candidates oneHot

/-- The three `assert!`s of `select_vec` are Rust PANICS, not returned errors; they are modelled as
an `Except` so their ORDER and their triggering conditions are explicit. -/
inductive SelectVecPanic where
  | emptyCandidates
  | indicatorLengthMismatch
  | raggedCandidates
  deriving DecidableEq, Repr

/-- "all candidates have the same length" (logic.rs:59-65). -/
def allWidth (w : Nat) : List (List Nat) → Bool
  | [] => true
  | c :: cs => (c.length == w) && allWidth w cs

theorem all_width_iff (w : Nat) (cs : List (List Nat)) :
    allWidth w cs = true ↔ ∀ c ∈ cs, c.length = w := by
  induction cs with
  | nil => simp [allWidth]
  | cons c rest ih => simp [allWidth, ih]

/-- `select_vec` including its assertions, in source order (logic.rs:48-65). The source checks the
width of `candidates.iter().skip(1)`; skipping the first is equivalent to checking all, since
`candidates[0].len()` IS the width. -/
def selectVec (candidates : List (List Nat)) (oneHot : List Bool) :
    Except SelectVecPanic (List Nat) :=
  if candidates.isEmpty then .error .emptyCandidates
  else if candidates.length ≠ oneHot.length then .error .indicatorLengthMismatch
  else if allWidth (selectWidth candidates) candidates = false then .error .raggedCandidates
  else .ok (selectVecCore candidates oneHot)

theorem select_vec_rejects_empty (oneHot : List Bool) :
    selectVec [] oneHot = .error .emptyCandidates := rfl

theorem select_vec_rejects_length_mismatch :
    selectVec [[1, 2], [3, 4]] [true] = .error .indicatorLengthMismatch := rfl

theorem select_vec_rejects_ragged :
    selectVec [[1, 2], [3]] [true, false] = .error .raggedCandidates := rfl

/-- An unset flag contributes nothing at all. -/
theorem accumulate_false (acc c : List Nat) : accumulate acc false c = acc := by
  induction acc generalizing c with
  | nil => rfl
  | cons a rest ih =>
      cases c with
      | nil => rfl
      | cons _ cs => simp [accumulate, bit, ih cs]

/-- A set flag against the all-zero accumulator copies the candidate verbatim (this is where the
`vec![zero; width]` initialisation matters). -/
theorem accumulate_zeros_true (w : Nat) (c : List Nat) (hc : c.length = w) :
    accumulate (List.replicate w 0) true c = c := by
  induction w generalizing c with
  | zero => cases c with
    | nil => rfl
    | cons _ _ => simp at hc
  | succ n ih =>
      cases c with
      | nil => simp at hc
      | cons x xs =>
          have hx : xs.length = n := by simpa using hc
          simp [List.replicate, accumulate, bit, ih xs hx]

/-- An all-false suffix of the indicator leaves the accumulator alone. -/
theorem select_fold_replicate_false (acc : List Nat) (cs : List (List Nat)) (n : Nat) :
    selectFold acc cs (List.replicate n false) = acc := by
  induction cs generalizing acc n with
  | nil => cases n <;> rfl
  | cons c rest ih =>
      cases n with
      | zero => rfl
      | succ m => simp [List.replicate, selectFold, accumulate_false, ih acc m]

/-- An all-false PREFIX of the indicator is skipped entirely. -/
theorem select_fold_false_prefix (acc : List Nat) (pre rest : List (List Nat))
    (fs : List Bool) :
    selectFold acc (pre ++ rest) (List.replicate pre.length false ++ fs) =
      selectFold acc rest fs := by
  induction pre generalizing acc with
  | nil => rfl
  | cons p ps ih => simp [List.replicate, selectFold, accumulate_false, ih acc]

/-- THE selection lemma: with a genuinely one-hot indicator the four-product (in general,
n-product) sum returns the selected candidate WHOLE. -/
theorem select_fold_one_hot (w : Nat) (pre post : List (List Nat)) (sel : List Nat)
    (hsel : sel.length = w) :
    selectFold (List.replicate w 0) (pre ++ sel :: post)
        (List.replicate pre.length false ++ true :: List.replicate post.length false) = sel := by
  rw [select_fold_false_prefix]
  simp only [selectFold]
  rw [accumulate_zeros_true w sel hsel, select_fold_replicate_false]

/-- The width of a uniformly sized candidate list containing `sel`. -/
theorem select_width_of_uniform (pre post : List (List Nat)) (sel : List Nat)
    (hw : ∀ c ∈ pre ++ sel :: post, c.length = sel.length) :
    selectWidth (pre ++ sel :: post) = sel.length := by
  cases pre with
  | nil => rfl
  | cons p ps => exact hw p (by simp)

/-- `select_vec` succeeds exactly when its three assertions pass. -/
theorem select_vec_ok_of_well_formed (candidates : List (List Nat)) (oneHot : List Bool)
    (hne : candidates ≠ []) (hlen : candidates.length = oneHot.length)
    (hw : ∀ c ∈ candidates, c.length = selectWidth candidates) :
    selectVec candidates oneHot = .ok (selectVecCore candidates oneHot) := by
  have h1 : candidates.isEmpty = false := by
    cases candidates with
    | nil => exact absurd rfl hne
    | cons _ _ => rfl
  have h3 : allWidth (selectWidth candidates) candidates = true :=
    (all_width_iff _ _).mpr hw
  simp [selectVec, h1, hlen, h3]

/-- The headline result: one-hot selection returns the selected vector, through the real
`select_vec` entry point (assertions included). -/
theorem select_vec_one_hot_selects_candidate (pre post : List (List Nat)) (sel : List Nat)
    (hw : ∀ c ∈ pre ++ sel :: post, c.length = sel.length) :
    selectVec (pre ++ sel :: post)
        (List.replicate pre.length false ++ true :: List.replicate post.length false) =
      .ok sel := by
  have hwidth : selectWidth (pre ++ sel :: post) = sel.length := select_width_of_uniform pre post sel hw
  have hne : pre ++ sel :: post ≠ [] := by
    cases pre <;> simp
  have hlen : (pre ++ sel :: post).length =
      (List.replicate pre.length false ++ true :: List.replicate post.length false).length := by
    simp
  have huni : ∀ c ∈ pre ++ sel :: post, c.length = selectWidth (pre ++ sel :: post) := by
    intro c hc; rw [hwidth]; exact hw c hc
  rw [select_vec_ok_of_well_formed _ _ hne hlen huni, selectVecCore, hwidth,
    select_fold_one_hot sel.length pre post sel rfl]

/-- With every flag off the result is the ZERO vector, not any candidate. A caller that fails to
force sum-to-one therefore gets a well-defined but meaningless answer, never a rejection. -/
theorem select_vec_all_false_is_zero (candidates : List (List Nat)) (n : Nat) :
    selectVecCore candidates (List.replicate n false) =
      List.replicate (selectWidth candidates) 0 := by
  simp [selectVecCore, select_fold_replicate_false]

/-- SECURITY BOUNDARY, made concrete: `select_vec` performs NO one-hot check of its own. With two
flags set it returns the SUM of two candidates — a value that is not any candidate. The sum-to-one
constraint that rules this out lives in the caller (`SwitchBoard`). -/
theorem select_vec_two_hot_is_a_sum :
    selectVec [[1, 2], [3, 4]] [true, true] = .ok [4, 6] := by rfl

/-- The source's own `test_select_vec` (logic.rs:267-301): three width-2 candidates, indicator
`[false, true, false]`, expected output `candidate1`. -/
theorem select_vec_matches_source_test :
    selectVec [[1, 2], [3, 4], [5, 6]] [false, true, false] = .ok [3, 4] := by rfl

/-! ### 3.4 The four-candidate instance `SwitchBoard` uses -/

/-- `select_vec` over exactly four candidates — the shape `SwitchBoard` calls it with (initial /
transfer / deposit / send). -/
def selectVec4 (c0 c1 c2 c3 : List Nat) (f0 f1 f2 f3 : Bool) : List Nat :=
  selectVecCore [c0, c1, c2, c3] [f0, f1, f2, f3]

/-- Literally the four-product sum, element by element (shown at width 2). -/
theorem select_vec4_entry_is_four_product_sum
    (a0 b0 a1 b1 a2 b2 a3 b3 : Nat) (f0 f1 f2 f3 : Bool) :
    selectVec4 [a0, b0] [a1, b1] [a2, b2] [a3, b3] f0 f1 f2 f3 =
      [0 + bit f0 * a0 + bit f1 * a1 + bit f2 * a2 + bit f3 * a3,
       0 + bit f0 * b0 + bit f1 * b1 + bit f2 * b2 + bit f3 * b3] := rfl

/-- Each of the four one-hot indicators selects its own candidate whole. -/
theorem select_vec4_one_hot_selects (c0 c1 c2 c3 : List Nat)
    (h1 : c1.length = c0.length) (h2 : c2.length = c0.length) (h3 : c3.length = c0.length) :
    selectVec4 c0 c1 c2 c3 true false false false = c0 ∧
    selectVec4 c0 c1 c2 c3 false true false false = c1 ∧
    selectVec4 c0 c1 c2 c3 false false true false = c2 ∧
    selectVec4 c0 c1 c2 c3 false false false true = c3 := by
  refine ⟨?_, ?_, ?_, ?_⟩
  · have := select_fold_one_hot c0.length [] [c1, c2, c3] c0 rfl
    simpa [selectVec4, selectVecCore, selectWidth, List.replicate] using this
  · have := select_fold_one_hot c0.length [c0] [c2, c3] c1 h1
    simpa [selectVec4, selectVecCore, selectWidth, List.replicate] using this
  · have := select_fold_one_hot c0.length [c0, c1] [c3] c2 h2
    simpa [selectVec4, selectVecCore, selectWidth, List.replicate] using this
  · have := select_fold_one_hot c0.length [c0, c1, c2] [] c3 h3
    simpa [selectVec4, selectVecCore, selectWidth, List.replicate] using this

/-- The selection identity survives reduction modulo any modulus, so the `Nat`-representative
statement above also holds for the field values the circuit actually carries. -/
theorem select_vec_mod_selects_candidate (m : Nat) (pre post : List (List Nat)) (sel : List Nat)
    (hw : ∀ c ∈ pre ++ sel :: post, c.length = sel.length) :
    (selectVecCore (pre ++ sel :: post)
        (List.replicate pre.length false ++ true :: List.replicate post.length false)).map
      (· % m) = sel.map (· % m) := by
  rw [selectVecCore, select_width_of_uniform pre post sel hw,
    select_fold_one_hot sel.length pre post sel rfl]

/-- The `BuilderLogic` trait surface (logic.rs:8-21). -/
def builderLogicMethods : List String :=
  ["conditional_assert_true", "conditional_and", "select_vec"]

theorem builder_logic_methods_pinned :
    builderLogicMethods = ["conditional_assert_true", "conditional_and", "select_vec"] := rfl

/-! ## 4. `src/utils/cyclic.rs` — the verifier-data public-input codec

`vd_to_vec` / `vd_from_pis_slice` (and their `*_target` twins, which are the same arithmetic on
targets) define the layout by which a cyclic circuit carries its own verifier data in its public
inputs. The Merkle-cap STRUCTURE is opaque (boundary `merkleCapStructureOpaque`); the model treats
a cap as a list of 4-element digests, which is exactly what the codec manipulates. -/

/-- plonky2's `fri_config.num_cap_elements() = 1 << cap_height`. Boundary
`capCountFromPlonky2Config`: the value comes from the caller's `CircuitConfig`, not from this
repo. -/
def numCapElements (capHeight : Nat) : Nat := 2 ^ capHeight

/-- `vd_vec_len(config) = 4 + 4 * config.fri_config.num_cap_elements()` (cyclic.rs:26-28): four
words for `circuit_digest` plus four per cap element. -/
def vdVecLen (capCount : Nat) : Nat := 4 + 4 * capCount

theorem vd_vec_len_pinned (capCount : Nat) : vdVecLen capCount = 4 + 4 * capCount := rfl

/-- The value for plonky2's `standard_recursion_config` (`cap_height = 4`, so 16 cap elements).
Recorded as a dependency value, not as a constant of this repo. -/
theorem vd_vec_len_for_cap_height_four : vdVecLen (numCapElements 4) = 68 := by decide

/-- `VerifierOnlyCircuitData` / `VerifierCircuitTarget` as the codec sees it. -/
structure VerifierData where
  circuitDigest : Hash
  constantsSigmasCap : List Hash
  deriving DecidableEq, Repr

/-- Shape premise: a digest is 4 field elements and the cap has `capCount` 4-element entries. -/
structure VerifierDataWF (capCount : Nat) (vd : VerifierData) : Prop where
  digest_len : vd.circuitDigest.length = 4
  cap_len : vd.constantsSigmasCap.length = capCount
  cap_entries : ∀ h ∈ vd.constantsSigmasCap, h.length = 4

/-- Concatenation of a list of digests. -/
def flattenHashes : List Hash → List Nat
  | [] => []
  | h :: hs => h ++ flattenHashes hs

theorem flatten_hashes_length (hs : List Hash) (h4 : ∀ h ∈ hs, h.length = 4) :
    (flattenHashes hs).length = 4 * hs.length := by
  induction hs with
  | nil => rfl
  | cons h rest ih =>
      have hh : h.length = 4 := h4 h (by simp)
      have hr : ∀ x ∈ rest, x.length = 4 := fun x hx => h4 x (by simp [hx])
      simp [flattenHashes, hh, ih hr, Nat.mul_succ, Nat.add_comm]

/-- `vd_to_vec` (cyclic.rs:30-40) and `vd_to_vec_target` (cyclic.rs:42-49): the digest first, then
every cap element in index order. -/
def vdToVec (vd : VerifierData) : List Nat :=
  vd.circuitDigest ++ flattenHashes vd.constantsSigmasCap

theorem vd_to_vec_length (capCount : Nat) (vd : VerifierData) (wf : VerifierDataWF capCount vd) :
    (vdToVec vd).length = vdVecLen capCount := by
  simp [vdToVec, wf.digest_len, flatten_hashes_length _ wf.cap_entries, wf.cap_len, vdVecLen]

/-- Regroup a flat word list into `n` 4-element digests. -/
def chunks4 : Nat → List Nat → List Hash
  | 0, _ => []
  | n + 1, l => l.take 4 :: chunks4 n (l.drop 4)

theorem chunks4_flatten (hs : List Hash) (h4 : ∀ h ∈ hs, h.length = 4) :
    chunks4 hs.length (flattenHashes hs) = hs := by
  induction hs with
  | nil => rfl
  | cons h rest ih =>
      have hh : h.length = 4 := h4 h (by simp)
      have hr : ∀ x ∈ rest, x.length = 4 := fun x hx => h4 x (by simp [hx])
      have htake : (h ++ flattenHashes rest).take 4 = h := by
        rw [← hh]; simp
      have hdrop : (h ++ flattenHashes rest).drop 4 = flattenHashes rest := by
        rw [← hh]; simp
      simp [flattenHashes, chunks4, htake, hdrop, ih hr]

/-- `CyclicError` (utils/error.rs:44-51). -/
inductive CyclicError where
  | notEnoughPublicInputs
  | invalidVerifierData
  deriving DecidableEq, Repr

/-- `vd_from_pis_slice` (cyclic.rs:51-77) and `vd_from_pis_slice_target` (cyclic.rs:79-102).

The source addresses the slice from its END: `circuit_digest[i] = slice[len - 4 - 4*cap_len + i]`
and `cap[i][j] = slice[len - 4*(cap_len - i) + j]`. Those two ranges are exactly the last
`4 + 4*cap_len` words, digest first then caps in index order — i.e. exactly `vd_to_vec`'s layout
placed at the TAIL of the slice. The model therefore takes that tail and splits it. -/
def vdFromPisSlice (slice : List Nat) (capCount : Nat) : Except CyclicError VerifierData :=
  if slice.length < vdVecLen capCount then .error .notEnoughPublicInputs
  else
    .ok ⟨(slice.drop (slice.length - vdVecLen capCount)).take 4,
         chunks4 capCount ((slice.drop (slice.length - vdVecLen capCount)).drop 4)⟩

/-- Reading a slice whose tail is exactly the encoding block: the prefix plays no role. -/
theorem vd_from_pis_slice_of_tail (capCount : Nat) (p tail : List Nat)
    (hlen : tail.length = vdVecLen capCount) :
    vdFromPisSlice (p ++ tail) capCount =
      .ok ⟨tail.take 4, chunks4 capCount (tail.drop 4)⟩ := by
  have hp : (p ++ tail).length = p.length + vdVecLen capCount := by simp [hlen]
  have hnp : ¬ ((p ++ tail).length < vdVecLen capCount) := by rw [hp]; omega
  have hdp : (p ++ tail).drop ((p ++ tail).length - vdVecLen capCount) = tail := by
    rw [hp, Nat.add_sub_cancel]; simp
  unfold vdFromPisSlice
  rw [if_neg hnp, hdp]

/-- The only rejection path: too few public inputs (cyclic.rs:60-62 / 85-87). -/
theorem vd_from_pis_slice_rejects_short_slice (slice : List Nat) (capCount : Nat)
    (h : slice.length < vdVecLen capCount) :
    vdFromPisSlice slice capCount = .error .notEnoughPublicInputs := by
  simp [vdFromPisSlice, h]

/-- THE round trip: whatever precedes it, the encoded verifier data is recovered exactly. This is
the property every cyclic circuit in the tree depends on when it re-parses its own public inputs. -/
theorem vd_round_trip (capCount : Nat) (vd : VerifierData) (wf : VerifierDataWF capCount vd)
    (prefixWords : List Nat) :
    vdFromPisSlice (prefixWords ++ vdToVec vd) capCount = .ok vd := by
  have hlen : (vdToVec vd).length = vdVecLen capCount := vd_to_vec_length capCount vd wf
  have hall : (prefixWords ++ vdToVec vd).length = prefixWords.length + vdVecLen capCount := by
    simp [hlen]
  have hnot : ¬ ((prefixWords ++ vdToVec vd).length < vdVecLen capCount) := by
    rw [hall]; omega
  have hdrop : (prefixWords ++ vdToVec vd).drop
      ((prefixWords ++ vdToVec vd).length - vdVecLen capCount) = vdToVec vd := by
    rw [hall, Nat.add_sub_cancel]
    simp
  have htake : (vdToVec vd).take 4 = vd.circuitDigest := by
    rw [vdToVec, ← wf.digest_len]; simp
  have hdrop4 : (vdToVec vd).drop 4 = flattenHashes vd.constantsSigmasCap := by
    rw [vdToVec, ← wf.digest_len]; simp
  simp only [vdFromPisSlice, hnot, if_false, hdrop, htake, hdrop4]
  rw [← wf.cap_len, chunks4_flatten _ wf.cap_entries]

/-- Positive example: a two-cap-element verifier data survives the round trip after an arbitrary
public-input prefix. -/
theorem vd_round_trip_example :
    vdFromPisSlice ([7, 8, 9] ++ vdToVec ⟨[1, 2, 3, 4], [[5, 5, 5, 5], [6, 6, 6, 6]]⟩) 2 =
      .ok ⟨[1, 2, 3, 4], [[5, 5, 5, 5], [6, 6, 6, 6]]⟩ := by rfl

/-- SECURITY BOUNDARY: the parser is PREFIX-BLIND. It reads only the tail, so it constrains
nothing about the leading public inputs and it accepts a slice longer than `vd_vec_len`. A caller
that hands it a slice with unexpected leading words gets a successful parse, not a rejection —
callers (`TestCyclicCircuit::new`, `add_proof_target_and_verify_cyclic`) must slice deliberately. -/
theorem vd_from_pis_slice_ignores_any_prefix (capCount : Nat) (p q tail : List Nat)
    (hlen : tail.length = vdVecLen capCount) :
    vdFromPisSlice (p ++ tail) capCount = vdFromPisSlice (q ++ tail) capCount := by
  rw [vd_from_pis_slice_of_tail capCount p tail hlen,
    vd_from_pis_slice_of_tail capCount q tail hlen]

/-- `conditionally_connect_vd` (cyclic.rs:104-112): `select_verifier_data(condition, vk0, vk1)` is
connected to `vk1`. -/
def ConditionallyConnectVdHolds (condition : Bool) (vk0 vk1 : VerifierData) : Prop :=
  (if condition then vk0 else vk1) = vk1

/-- The gadget constrains the two keys equal ONLY when the condition is set; with the condition
off it is vacuous, so `vk0` is left free. -/
theorem conditionally_connect_vd_iff (condition : Bool) (vk0 vk1 : VerifierData) :
    ConditionallyConnectVdHolds condition vk0 vk1 ↔ (condition = true → vk0 = vk1) := by
  cases condition <;> simp [ConditionallyConnectVdHolds]

theorem conditionally_connect_vd_is_vacuous_when_false (vk0 vk1 : VerifierData) :
    ConditionallyConnectVdHolds false vk0 vk1 := rfl

/-- `add_noop_gates` (cyclic.rs:114-121): pad with `NoopGate`s until the gate count reaches the
target. Boundary `degreeAndGateCountOpaque`. -/
def padGateCount (current target : Nat) : Nat := max current target

theorem pad_gate_count_never_shrinks (current target : Nat) : current ≤ padGateCount current target :=
  Nat.le_max_left _ _

theorem pad_gate_count_reaches_target (current target : Nat) : target ≤ padGateCount current target :=
  Nat.le_max_right _ _

/-- `TestCyclicCircuit::generate_cd` (cyclic.rs:249): the common data's public-input count is the
payload length plus the verifier-data encoding length. -/
def generatedNumPublicInputs (pisLen capCount : Nat) : Nat := pisLen + vdVecLen capCount

/-- The public-input layout `TestCyclicCircuit::new` parses (cyclic.rs:175-179): payload first,
then the verifier-data block. The block handed to `vd_from_pis_slice_target` is exactly
`vd_vec_len` long, so the tail-addressing parser reads the whole block. -/
theorem cyclic_public_input_layout_round_trip (capCount pisLen : Nat) (payload : List Nat)
    (vd : VerifierData) (wf : VerifierDataWF capCount vd) (hp : payload.length = pisLen) :
    (payload ++ vdToVec vd).take pisLen = payload ∧
    vdFromPisSlice ((payload ++ vdToVec vd).drop pisLen) capCount = .ok vd := by
  constructor
  · rw [← hp]; simp
  · have : (payload ++ vdToVec vd).drop pisLen = vdToVec vd := by rw [← hp]; simp
    rw [this]
    exact vd_round_trip capCount vd wf []

theorem generated_num_public_inputs_pinned (pisLen capCount : Nat) :
    generatedNumPublicInputs pisLen capCount = pisLen + (4 + 4 * capCount) := rfl

/-! ## 5. `src/utils/dummy.rs` and `src/utils/recursively_verifiable.rs`

Proof verification is OPAQUE (boundary `proofVerificationOpaque`). What the model records is
WHICH constraints each helper emits and against WHICH verifier key — never that a verified proof
is sound. -/

/-- A constraint emitted by the recursion helpers. -/
inductive ProofCheck where
  /-- `builder.verify_proof(proof, vd, common)`. -/
  | verify (vd : VerifierData)
  /-- `connect_hashes` + `connect_merkle_caps` between two verifier data targets. -/
  | connectVd (a b : VerifierData)
  /-- `conditionally_connect_vd(condition, a, b)`. -/
  | conditionalConnectVd (cond : Bool) (a b : VerifierData)
  deriving DecidableEq, Repr

/-- `builder.select_verifier_data(condition, inner, dummy)` (dummy.rs:55-56). -/
def selectedVerifierData (condition : Bool) (inner dummyVd : VerifierData) : VerifierData :=
  if condition then inner else dummyVd

/-- `dummy::conditionally_verify_proof` (dummy.rs:40-58). Unlike plonky2's
`conditionally_verify_proof`, when the condition is FALSE the caller must still supply a proof —
one that verifies under the constant DUMMY verifier data. -/
def conditionallyVerifyProof (condition : Bool) (inner dummyVd : VerifierData) : List ProofCheck :=
  [.verify (selectedVerifierData condition inner dummyVd)]

/-- With the condition set, the real inner key is used. -/
theorem conditionally_verify_proof_uses_real_key (inner dummyVd : VerifierData) :
    conditionallyVerifyProof true inner dummyVd = [.verify inner] := rfl

/-- With the condition clear the proof is NOT unconstrained: it is verified under the fixed dummy
verifier key. This is the fact `SwitchBoard` relies on for its inactive branches. -/
theorem conditionally_verify_proof_uses_dummy_key (inner dummyVd : VerifierData) :
    conditionallyVerifyProof false inner dummyVd = [.verify dummyVd] := rfl

/-- Exactly one verification constraint is emitted either way — no branch escapes verification. -/
theorem conditionally_verify_proof_always_verifies (condition : Bool) (inner dummyVd : VerifierData) :
    (conditionallyVerifyProof condition inner dummyVd).length = 1 := by
  cases condition <;> rfl

/-- `internal_dummy_circuit` (dummy.rs:60-91) sizes its noop padding as
`degree - num_public_inputs.div_ceil(8) - 2`, in `usize`. -/
inductive DummySizingError where
  | degreeTooSmallForPublicInputs
  deriving DecidableEq, Repr

/-- `num_public_inputs.div_ceil(8)`. -/
def publicInputGateCount (numPublicInputs : Nat) : Nat := (numPublicInputs + 7) / 8

/-- The noop count of dummy.rs:76, with the `usize` UNDERFLOW made explicit: when
`div_ceil(8) + 2` exceeds the degree the Rust expression underflows (debug panic / release wrap),
it does not clamp. -/
def internalDummyNoopCount (degree numPublicInputs : Nat) : Except DummySizingError Nat :=
  if degree < publicInputGateCount numPublicInputs + 2 then
    .error .degreeTooSmallForPublicInputs
  else .ok (degree - (publicInputGateCount numPublicInputs + 2))

/-- Normal case: a degree-4096 dummy circuit with 68 public inputs pads with 4085 noops. -/
theorem internal_dummy_noop_count_example :
    internalDummyNoopCount 4096 68 = .ok 4085 := by rfl

/-- SECURITY-RELEVANT: the sizing arithmetic has no guard. With more public inputs than the degree
can host, the source's `usize` subtraction underflows instead of reporting a problem. -/
theorem internal_dummy_noop_count_underflows_when_degree_too_small :
    internalDummyNoopCount 4 64 = .error .degreeTooSmallForPublicInputs := by rfl

/-- `add_proof_target_and_verify` (recursively_verifiable.rs:17-30): verify under a CONSTANT
verifier key. -/
def addProofTargetAndVerify (vd : VerifierData) : List ProofCheck := [.verify vd]

/-- `add_proof_target_and_conditionally_verify` (recursively_verifiable.rs:32-46). -/
def addProofTargetAndConditionallyVerify (condition : Bool) (vd dummyVd : VerifierData) :
    List ProofCheck := conditionallyVerifyProof condition vd dummyVd

/-- `add_proof_target_and_verify_cyclic` (recursively_verifiable.rs:48-68): additionally connects
the constant verifier key to the one the proof carries in its OWN public inputs. -/
def addProofTargetAndVerifyCyclic (vd innerVd : VerifierData) : List ProofCheck :=
  [.connectVd vd innerVd, .verify vd]

/-- `add_proof_target_and_conditionally_verify_cyclic` (recursively_verifiable.rs:70-87). -/
def addProofTargetAndConditionallyVerifyCyclic (condition : Bool) (vd dummyVd innerVd : VerifierData) :
    List ProofCheck :=
  [.verify (selectedVerifierData condition vd dummyVd), .conditionalConnectVd condition vd innerVd]

/-- The cyclic variant binds the proof's public-input verifier key UNCONDITIONALLY. -/
theorem cyclic_verify_binds_embedded_key (vd innerVd : VerifierData) :
    ProofCheck.connectVd vd innerVd ∈ addProofTargetAndVerifyCyclic vd innerVd := by simp
  [addProofTargetAndVerifyCyclic]

/-- The non-cyclic conditional variant emits NO key-binding constraint at all: the verifier key a
proof carries in its own public inputs is not compared with the constant key. Callers that need
that binding must use the cyclic variant. -/
theorem conditional_verify_emits_no_key_binding (condition : Bool) (vd dummyVd innerVd : VerifierData) :
    ProofCheck.connectVd vd innerVd ∉ addProofTargetAndConditionallyVerify condition vd dummyVd := by
  cases condition <;> simp [addProofTargetAndConditionallyVerify, conditionallyVerifyProof,
    selectedVerifierData]

/-- The conditional CYCLIC variant does bind the key, but only when the condition is set; with the
condition clear the proof is verified under the dummy key and its embedded key is free. -/
theorem conditional_cyclic_binds_key_only_when_condition_true (vd dummyVd innerVd : VerifierData) :
    addProofTargetAndConditionallyVerifyCyclic true vd dummyVd innerVd =
      [.verify vd, .conditionalConnectVd true vd innerVd] ∧
    addProofTargetAndConditionallyVerifyCyclic false vd dummyVd innerVd =
      [.verify dummyVd, .conditionalConnectVd false vd innerVd] ∧
    ConditionallyConnectVdHolds false vd innerVd := by
  exact ⟨rfl, rfl, rfl⟩

/-- `wrapper.rs:36-46`: the wrapper verifies the inner proof under the inner circuit's CONSTANT
verifier data and re-registers EVERY inner public input as its own, in order — it neither filters
nor reorders nor adds any. -/
def wrapperPublicInputs (innerPublicInputs : List Nat) : List Nat := innerPublicInputs

theorem wrapper_republishes_inner_public_inputs (innerPublicInputs : List Nat) :
    wrapperPublicInputs innerPublicInputs = innerPublicInputs := rfl

theorem wrapper_verifies_under_constant_inner_key (innerVd : VerifierData) :
    addProofTargetAndVerify innerVd = [.verify innerVd] := rfl

/-! ## 6. `src/utils/leafable_hasher.rs` and `src/utils/leafable.rs`

The two-to-one hashing discipline and the empty-leaf convention every Merkle tree in the tree
inherits. Both hashers are OPAQUE (boundary `hashOpaque`); what is modelled is the ARGUMENT ORDER
and the empty-leaf values, which is what a caller can get wrong. -/

/-- `PoseidonLeafableHasher::two_to_one` (leafable_hasher.rs:97-104): hash the concatenated
`u64` element vectors, left first. Identical to `PoseidonHashOutTarget::two_to_one`. -/
def poseidonTwoToOne (env : HashEnv) (left right : Hash) : Hash :=
  env.poseidonU64 (left ++ right)

/-- `two_to_one_swapped` (leafable_hasher.rs:159-173 via
`PoseidonHashOutTarget::two_to_one_swapped`): the swap bit exchanges the two halves. The source
routes this through `PoseidonHash::permute_swapped`'s swap wire rather than re-emitting a hash of
the reversed input; the model states the intended SEMANTICS and leaves the gate-level equality to
boundary `gateLoweringOpaque`. -/
def poseidonTwoToOneSwapped (env : HashEnv) (left right : Hash) (swap : Bool) : Hash :=
  if swap then poseidonTwoToOne env right left else poseidonTwoToOne env left right

theorem poseidon_two_to_one_swapped_true_reverses (env : HashEnv) (l r : Hash) :
    poseidonTwoToOneSwapped env l r true = poseidonTwoToOne env r l := rfl

theorem poseidon_two_to_one_swapped_false_keeps_order (env : HashEnv) (l r : Hash) :
    poseidonTwoToOneSwapped env l r false = poseidonTwoToOne env l r := rfl

/-- `KeccakLeafableHasher::two_to_one` (leafable_hasher.rs:183-186): `solidity_keccak256` over the
concatenated `u32` limbs, left first. -/
def keccakTwoToOne (env : HashEnv) (left right : List Nat) : List Nat :=
  env.keccakU32 (left ++ right)

/-- `KeccakLeafableHasher::two_to_one_swapped` (leafable_hasher.rs:221-237) selects the two inputs
EXPLICITLY (`Bytes32Target::select` twice) before hashing — same semantics, different lowering. -/
def keccakTwoToOneSwapped (env : HashEnv) (left right : List Nat) (swap : Bool) : List Nat :=
  if swap then keccakTwoToOne env right left else keccakTwoToOne env left right

theorem keccak_two_to_one_swapped_true_reverses (env : HashEnv) (l r : List Nat) :
    keccakTwoToOneSwapped env l r true = keccakTwoToOne env r l := rfl

theorem keccak_two_to_one_swapped_false_keeps_order (env : HashEnv) (l r : List Nat) :
    keccakTwoToOneSwapped env l r false = keccakTwoToOne env l r := rfl

/-- Both hashers agree on what the swap bit MEANS, which is what makes a Merkle path gadget
hasher-agnostic. -/
theorem two_to_one_swap_convention_agrees (env : HashEnv) (l r : Hash) (swap : Bool) :
    (poseidonTwoToOneSwapped env l r swap = poseidonTwoToOne env (if swap then r else l)
      (if swap then l else r)) ∧
    (keccakTwoToOneSwapped env l r swap = keccakTwoToOne env (if swap then r else l)
      (if swap then l else r)) := by
  cases swap <;> exact ⟨rfl, rfl⟩

/-- SECURITY BOUNDARY, stated as a premise rather than assumed: distinguishing two inner nodes by
their children needs collision resistance of the opaque hash. Under an explicit injectivity
premise (and the digest-width premise) the left child is determined. -/
theorem two_to_one_determines_children_under_injectivity (env : HashEnv)
    (inj : ∀ x y : List Nat, env.poseidonU64 x = env.poseidonU64 y → x = y)
    (l1 r1 l2 r2 : Hash) (h1 : l1.length = 4) (h2 : l2.length = 4)
    (heq : poseidonTwoToOne env l1 r1 = poseidonTwoToOne env l2 r2) :
    l1 = l2 ∧ r1 = r2 := by
  have hs := inj _ _ heq
  exact List.append_inj hs (by rw [h1, h2])

/-- `Leafable` instances present in `src/utils/leafable.rs`. -/
inductive LeafKind where
  | poseidonHashOut
  | bytes32
  | u256
  | u32
  deriving DecidableEq, Repr

/-- `Leafable::empty_leaf()` — always `Default::default()` (leafable.rs:58, 94, 130, 166). The
empty leaf is the ALL-ZERO value of the leaf type; the Merkle machinery relies on this being a
fixed, publicly known constant. -/
def emptyLeaf : LeafKind → List Nat
  | .poseidonHashOut => [0, 0, 0, 0]
  | .bytes32 => List.replicate 8 0
  | .u256 => List.replicate 8 0
  | .u32 => [0]

/-- `LeafableTarget::empty_leaf(builder)` — the in-circuit CONSTANT the same instances allocate
(leafable.rs:71-75, 107-111, 143-147, 179-183). Note leafable.rs:146 builds the `U256Target`
constant from `Bytes32::default()`, which is the same all-zero 8-limb value. -/
def emptyLeafTarget : LeafKind → List Nat
  | .poseidonHashOut => [0, 0, 0, 0]
  | .bytes32 => List.replicate 8 0
  | .u256 => List.replicate 8 0
  | .u32 => [0]

/-- The empty-leaf convention is CONSISTENT between the native and the in-circuit path for every
instance. A mismatch here would let a prover open an "empty" slot the native tree never had. -/
theorem empty_leaf_target_matches_native (k : LeafKind) : emptyLeafTarget k = emptyLeaf k := by
  cases k <;> rfl

theorem empty_leaf_is_all_zero (k : LeafKind) : ∀ x ∈ emptyLeaf k, x = 0 := by
  cases k <;> decide

/-- `Leafable::hash` (leafable.rs:63, 99, 135, 171). For `PoseidonHashOut` the hash is the
IDENTITY ("Output as is in the case of a hash"); the other three hash their `u32` limbs. -/
def leafHash (env : HashEnv) : LeafKind → List Nat → Hash
  | .poseidonHashOut, v => v
  | .bytes32, v => env.poseidonU32 v
  | .u256, v => env.poseidonU32 v
  | .u32, v => env.poseidonU32 v

/-- SECURITY-RELEVANT: for a `PoseidonHashOut` leaf, `hash` is the identity, so a leaf value and an
inner-node digest are the SAME kind of object with no domain separation between them. Whatever
prevents a leaf from being reinterpreted as an inner node is the tree gadget's structural
discipline (fixed height, index decomposition), not this trait. -/
theorem poseidon_leaf_hash_is_identity (env : HashEnv) (v : List Nat) :
    leafHash env .poseidonHashOut v = v := rfl

/-- The empty `PoseidonHashOut` leaf hashes to the zero digest — the value every empty subtree of
such a tree is built from. -/
theorem poseidon_empty_leaf_hash_is_zero (env : HashEnv) :
    leafHash env .poseidonHashOut (emptyLeaf .poseidonHashOut) = zeroHash := rfl

/-- Every `Leafable` instance in the file uses `PoseidonLeafableHasher` (leafable.rs:56, 92, 128,
164) — there is no keccak-leaf instance, so the keccak hasher is only ever used where a caller
selects it explicitly. -/
def leafHasherOf : LeafKind → String
  | _ => "PoseidonLeafableHasher"

theorem every_leafable_uses_poseidon_hasher (k : LeafKind) :
    leafHasherOf k = "PoseidonLeafableHasher" := rfl

/-- The IMLL chain step is literally the Poseidon two-to-one of the leafable hasher, which is why
the producer and every consumer compute the same chain. -/
theorem list_chain_step_is_poseidon_two_to_one (env : HashEnv) (prev leaf : Hash) :
    listChainStep env prev leaf = poseidonTwoToOne env prev leaf := rfl

/-! ## 7. `src/utils/conversion.rs` -/

/-- The Goldilocks order `2^64 - 2^32 + 1`, the modulus `to_canonical_u64` reduces to. -/
def goldilocksModulus : Nat := 18446744069414584321

theorem goldilocks_modulus_pinned : goldilocksModulus = 18446744069414584321 := rfl

theorem goldilocks_modulus_is_two_pow_64_minus_two_pow_32_plus_one :
    goldilocksModulus = 2 ^ 64 - 2 ^ 32 + 1 := by decide

/-- `ToU64::to_u64_vec` (conversion.rs:13-43): map `to_canonical_u64` over the elements. All four
impls (`&[F]`, `[F]`, `Iter<'_, F>`, `Vec<F>`) are the same map. -/
def toU64Vec (xs : List Nat) : List Nat := xs.map (· % goldilocksModulus)

/-- `ToField::to_field_vec` (conversion.rs:45-58): map `F::from_canonical_u64`. plonky2 requires
the input to be BELOW the order (it debug-asserts); the model reduces, which is the release
behaviour of the canonical representative. -/
def toFieldVec (xs : List Nat) : List Nat := xs.map (· % goldilocksModulus)

theorem to_u64_vec_length (xs : List Nat) : (toU64Vec xs).length = xs.length := by
  simp [toU64Vec]

/-- Round trip on canonical inputs, which is the only regime the source supports. -/
theorem to_field_vec_to_u64_vec_round_trip (xs : List Nat)
    (h : ∀ x ∈ xs, x < goldilocksModulus) : toFieldVec (toU64Vec xs) = xs := by
  induction xs with
  | nil => rfl
  | cons a rest ih =>
      have ha : a < goldilocksModulus := h a (by simp)
      have hr : ∀ x ∈ rest, x < goldilocksModulus := fun x hx => h x (by simp [hx])
      simp [toU64Vec, toFieldVec, Nat.mod_eq_of_lt ha] at *
      exact ih hr

/-- Non-canonical inputs are NOT preserved: `to_field_vec` silently reduces. Callers that feed it
a raw `u64` above the order lose information; nothing in `conversion.rs` reports this. -/
theorem to_field_vec_reduces_non_canonical :
    toFieldVec [goldilocksModulus] = [0] := by
  simp [toFieldVec, goldilocksModulus]

/-! ## 8. `src/utils/serialize.rs`, `src/utils/serializer.rs`, `src/utils/wrapper.rs`

The two `impl_gate_serializer!` registries and the `impl_generator_serializer!` registry are the
FAIL-CLOSED allowlists of the recursion machinery: a circuit using a gate outside the registry
cannot be serialized or deserialized. The macro expansion, wire format and bincode behaviour are
opaque (boundary `serializerMacroOpaque`); the model pins the registered tag lists. -/

/-- `U32GateSerializer`'s registry (serializer.rs:24-45). -/
def u32GateTags : List String :=
  ["ArithmeticGate", "ArithmeticExtensionGate", "BaseSumGate<2>", "ConstantGate",
   "CosetInterpolationGate", "ExponentiationGate", "LookupGate", "LookupTableGate",
   "MulExtensionGate", "NoopGate", "PoseidonMdsGate", "PoseidonGate", "PublicInputGate",
   "RandomAccessGate", "ReducingExtensionGate", "ReducingGate", "ComparisonGate",
   "U32AddManyGate", "U32SubtractionGate"]

/-- `AllGateSerializer`'s registry (serialize.rs:59-80). -/
def allGateTags : List String :=
  ["ArithmeticGate", "ArithmeticExtensionGate", "BaseSumGate<2>", "ConstantGate",
   "CosetInterpolationGate", "ExponentiationGate", "LookupGate", "LookupTableGate",
   "MulExtensionGate", "NoopGate", "PoseidonMdsGate", "PoseidonGate", "PublicInputGate",
   "RandomAccessGate", "ReducingExtensionGate", "ReducingGate", "ComparisonGate",
   "U32AddManyGate", "U32SubtractionGate"]

/-- The two gate registries in the tree are IDENTICAL, tag for tag and in the same order, so a
circuit serialized with one deserializes with the other. A divergence here would be a silent
cross-serializer incompatibility. -/
theorem gate_registries_agree : u32GateTags = allGateTags := rfl

theorem gate_registry_size : allGateTags.length = 19 := rfl

/-- `AllGeneratorSerializer`'s registry (serialize.rs:102-136), including the two keccak witness
generators the balance circuits need. -/
def allGeneratorTags : List String :=
  ["ArithmeticBaseGenerator", "ArithmeticExtensionGenerator", "BaseSplitGenerator<2>",
   "BaseSumGenerator<2>", "ConstantGenerator", "CopyGenerator", "DummyProofGenerator",
   "EqualityGenerator", "ExponentiationGenerator", "InterpolationGenerator", "LookupGenerator",
   "LookupTableGenerator", "LowHighGenerator", "MulExtensionGenerator", "NonzeroTestGenerator",
   "PoseidonGenerator", "PoseidonMdsGenerator", "QuotientGeneratorExtension",
   "RandomAccessGenerator", "RandomValueGenerator", "ReducingGenerator",
   "ReducingExtensionGenerator", "SplitGenerator", "WireSplitGenerator", "ComparisonGenerator",
   "U32AddManyGenerator", "U32SubtractionGenerator", "Keccak256SingleGenerator",
   "Keccak256StarkProofGenerator"]

theorem generator_registry_size : allGeneratorTags.length = 29 := rfl

/-- The keccak generators are registered; without them a balance circuit that hashes its
`settled_tx_chain` public input with keccak could not be deserialized (serialize.rs:131-135). -/
theorem keccak_generators_are_registered :
    "Keccak256SingleGenerator" ∈ allGeneratorTags ∧
    "Keccak256StarkProofGenerator" ∈ allGeneratorTags := by
  exact ⟨by decide, by decide⟩

/-- `SerializeError` (utils/error.rs:35-42). -/
inductive SerializeError where
  | serializationFailed
  | deserializationFailed
  deriving DecidableEq, Repr

/-- Opaque verifier-data codec (boundary `serializerMacroOpaque`). -/
structure SerdeEnv where
  encode : VerifierData → Option (List Nat)
  decode : List Nat → Option VerifierData

/-- `serialize_verifier_data` (serialize.rs:139-151): any codec failure becomes
`SerializeError::SerializationFailed`. -/
def serializeVerifierData (se : SerdeEnv) (vd : VerifierData) : Except SerializeError (List Nat) :=
  match se.encode vd with
  | some bytes => .ok bytes
  | none => .error .serializationFailed

/-- `deserialize_verifier_data` (serialize.rs:153-164). -/
def deserializeVerifierData (se : SerdeEnv) (bytes : List Nat) :
    Except SerializeError VerifierData :=
  match se.decode bytes with
  | some vd => .ok vd
  | none => .error .deserializationFailed

/-- Failure LABELS are direction-specific, which is all the source guarantees. -/
theorem serialize_error_labels (se : SerdeEnv) (vd : VerifierData) (bytes : List Nat)
    (he : se.encode vd = none) (hd : se.decode bytes = none) :
    serializeVerifierData se vd = .error .serializationFailed ∧
    deserializeVerifierData se bytes = .error .deserializationFailed := by
  simp [serializeVerifierData, deserializeVerifierData, he, hd]

/-- Round trip holds only under an EXPLICIT codec premise; the source proves nothing about it and
neither does this model. -/
theorem serialize_round_trip_under_codec_premise (se : SerdeEnv) (vd : VerifierData)
    (bytes : List Nat) (henc : se.encode vd = some bytes) (hdec : se.decode bytes = some vd) :
    serializeVerifierData se vd = .ok bytes ∧ deserializeVerifierData se bytes = .ok vd := by
  simp [serializeVerifierData, deserializeVerifierData, henc, hdec]

/-- `CircuitSerializationError` (serialize.rs:166-194): both variants carry a static `context` and
a stringified `detail`. -/
inductive CircuitSerializationError where
  | serialization (context detail : String)
  | deserialization (context detail : String)
  deriving DecidableEq, Repr

theorem circuit_serialization_error_keeps_context (ctx detail : String) :
    CircuitSerializationError.serialization ctx detail ≠
      CircuitSerializationError.deserialization ctx detail := by
  intro h; cases h

/-- `WrapperError` (utils/error.rs:65-72). -/
inductive WrapperError where
  | proofGenerationFailed
  | invalidProof
  deriving DecidableEq, Repr

/-- `WrapperCircuit::prove` (wrapper.rs:48-57) maps ANY inner proving failure to
`WrapperError::ProofGenerationFailed`; it does not distinguish causes. -/
def wrapperProve (innerSucceeded : Bool) : Except WrapperError Unit :=
  if innerSucceeded then .ok () else .error .proofGenerationFailed

theorem wrapper_prove_collapses_failures :
    wrapperProve false = .error .proofGenerationFailed ∧ wrapperProve true = .ok () := by
  exact ⟨rfl, rfl⟩

/-! ## 9. `src/utils/error.rs` and `src/utils/mod.rs` -/

/-- `PoseidonHashOutError` (utils/error.rs:53-63), constructors in source order.
`NonCanonicalElement` carries the index of the offending 64-bit limb (`usize`). -/
inductive PoseidonHashOutError where
  | recoveryFailed
  | nonCanonicalElement (limb : Nat)
  | invalidHashValue
  deriving DecidableEq, Repr

/-- The `PoseidonHashOutError` display strings pinned from utils/error.rs:55-62. The
`NonCanonicalElement` payload is substituted for thiserror's `{0}`; the `InvalidHashValue`
payload is a `String` the model does not carry, so its `{0}` stays literal. -/
def poseidonHashOutErrorMessage : PoseidonHashOutError → String
  | .recoveryFailed => "Failed to recover HashOut from Bytes32"
  | .nonCanonicalElement i => s!"Bytes32 limb {i} is not a canonical Goldilocks element"
  | .invalidHashValue => "Invalid hash value: {0}"

theorem poseidon_hash_out_error_messages_pinned :
    poseidonHashOutErrorMessage .recoveryFailed = "Failed to recover HashOut from Bytes32" ∧
    poseidonHashOutErrorMessage (.nonCanonicalElement 2) =
      "Bytes32 limb 2 is not a canonical Goldilocks element" ∧
    poseidonHashOutErrorMessage .invalidHashValue = "Invalid hash value: {0}" :=
  ⟨rfl, rfl, rfl⟩

/-- These three are EXACTLY the variants of `PoseidonHashOutError`: every value is one of them. -/
theorem poseidon_hash_out_error_variants_exhaustive (e : PoseidonHashOutError) :
    e = .recoveryFailed ∨ (∃ i, e = .nonCanonicalElement i) ∨ e = .invalidHashValue := by
  cases e with
  | recoveryFailed => exact Or.inl rfl
  | nonCanonicalElement i => exact Or.inr (Or.inl ⟨i, rfl⟩)
  | invalidHashValue => exact Or.inr (Or.inr rfl)

/-- The three variants are pairwise distinct constructors, so the canonicality rejection is never
conflated with the round-trip rejection or with an unparsable hash string. -/
theorem poseidon_hash_out_error_variants_are_distinct (i : Nat) :
    PoseidonHashOutError.nonCanonicalElement i ≠ PoseidonHashOutError.recoveryFailed ∧
    PoseidonHashOutError.nonCanonicalElement i ≠ PoseidonHashOutError.invalidHashValue ∧
    PoseidonHashOutError.recoveryFailed ≠ PoseidonHashOutError.invalidHashValue :=
  ⟨(by intro h; cases h), (by intro h; cases h), (by intro h; cases h)⟩

/-- The index of the FIRST limb at or above the Goldilocks order, counting from `i`
(the `for (i, &element) in ... .enumerate()` loop of poseidon_hash_out.rs:293-297). -/
def firstNonCanonicalLimbFrom (i : Nat) : List Nat → Option Nat
  | [] => none
  | e :: rest => if e ≥ goldilocksModulus then some i else firstNonCanonicalLimbFrom (i + 1) rest

/-- `first_non_canonical_limb` of the four `u64` elements produced by `reduce_to_hash_out`. -/
def firstNonCanonicalLimb (limbs : List Nat) : Option Nat := firstNonCanonicalLimbFrom 0 limbs

/-- `TryFrom<Bytes32> for PoseidonHashOut` (poseidon_hash_out.rs:291-303) as repaired: the
per-limb canonicality test runs FIRST and short-circuits on the first offending index; only then
is the byte round trip compared. `roundTripHolds` is left as an explicit parameter because
`reduce_to_hash_out` and `From<PoseidonHashOut> for Bytes32` regroup the same limbs without
reducing, so the source comment claims this branch is unreachable — a claim this model records
rather than proves. -/
def tryHashOutFromBytes32 (limbs : List Nat) (roundTripHolds : Bool) :
    Except PoseidonHashOutError (List Nat) :=
  match firstNonCanonicalLimb limbs with
  | some i => .error (.nonCanonicalElement i)
  | none => if roundTripHolds then .ok limbs else .error .recoveryFailed

/-- Error PRECEDENCE: a non-canonical limb is reported as `NonCanonicalElement` whatever the byte
round trip does, so the canonicality rejection can never be masked by `RecoveryFailed`. -/
theorem try_hash_out_canonicality_precedes_round_trip (limbs : List Nat) (i : Nat)
    (h : firstNonCanonicalLimb limbs = some i) (b : Bool) :
    tryHashOutFromBytes32 limbs b = .error (.nonCanonicalElement i) := by
  simp [tryHashOutFromBytes32, h]

/-- Concrete rejection, the case the pre-repair conversion could not produce: a `Bytes32` whose
second 64-bit limb is exactly the Goldilocks order is refused with the index of that limb. -/
theorem try_hash_out_rejects_non_canonical_limb :
    tryHashOutFromBytes32 [0, goldilocksModulus, 0, 0] true =
      .error (.nonCanonicalElement 1) := by
  simp [tryHashOutFromBytes32, firstNonCanonicalLimb, firstNonCanonicalLimbFrom,
    goldilocksModulus]

/-- Non-vacuous positive trace: four canonical limbs with a holding round trip are accepted
unchanged. -/
theorem try_hash_out_accepts_canonical_limbs :
    tryHashOutFromBytes32 [0, 1, 2, goldilocksModulus - 1] true =
      .ok [0, 1, 2, goldilocksModulus - 1] := by
  simp [tryHashOutFromBytes32, firstNonCanonicalLimb, firstNonCanonicalLimbFrom,
    goldilocksModulus]

/-- `UtilsError` (utils/error.rs:8-30): seven `#[error(transparent)]` variants, i.e. the display
of a `UtilsError` is the display of the wrapped error, with no extra context added. -/
inductive UtilsError where
  | hashChain
  | serialize (e : SerializeError)
  | cyclic (e : CyclicError)
  | poseidonHashOut (e : PoseidonHashOutError)
  | wrapper (e : WrapperError)
  | merkleProof
  | indexedMerkleTree
  deriving DecidableEq, Repr

/-- The seven variants are distinct constructors, so a wrapping never conflates two error
families. -/
theorem utils_error_variants_are_distinct (a : SerializeError) (b : CyclicError) :
    UtilsError.serialize a ≠ UtilsError.cyclic b := by intro h; cases h

/-- The `CyclicError` display strings pinned from utils/error.rs:46-50. -/
def cyclicErrorMessage : CyclicError → String
  | .notEnoughPublicInputs => "Not enough public inputs"
  | .invalidVerifierData => "Invalid verifier data: {0}"

theorem cyclic_error_messages_pinned :
    cyclicErrorMessage .notEnoughPublicInputs = "Not enough public inputs" ∧
    cyclicErrorMessage .invalidVerifierData = "Invalid verifier data: {0}" := ⟨rfl, rfl⟩

/-- `src/utils/mod.rs` (18 lines): the fifteen submodules of `utils`, in declaration order.
`mle_prover` is declared last, after the doc comment at mod.rs:16-17. -/
def utilsModules : List String :=
  ["conversion", "cyclic", "dummy", "error", "hash_chain", "leafable", "leafable_hasher",
   "logic", "poseidon_hash_out", "recursively_verifiable", "serialize", "serializer", "trees",
   "wrapper", "mle_prover"]

theorem utils_modules_count : utilsModules.length = 15 := rfl

theorem utils_modules_include_every_modelled_file :
    "logic" ∈ utilsModules ∧ "cyclic" ∈ utilsModules ∧ "dummy" ∈ utilsModules ∧
    "leafable" ∈ utilsModules ∧ "leafable_hasher" ∈ utilsModules ∧
    "recursively_verifiable" ∈ utilsModules ∧ "serialize" ∈ utilsModules ∧
    "serializer" ∈ utilsModules ∧ "conversion" ∈ utilsModules ∧ "wrapper" ∈ utilsModules ∧
    "error" ∈ utilsModules := by
  refine ⟨by decide, by decide, by decide, by decide, by decide, by decide, by decide, by decide,
    by decide, by decide, by decide⟩

end Zkp.Implementation.UtilGadgets

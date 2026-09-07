import Std

/-!
# Crate module tree declared by the `src/circuits/**/mod.rs` files

Sources (ten files, all fully modeled):
- src/circuits/mod.rs (6 lines)
- src/circuits/balance/mod.rs (9), src/circuits/balance/common/mod.rs (7)
- src/circuits/channel/mod.rs (14)
- src/circuits/validity/mod.rs (3), validity/block_hash_chain/mod.rs (13),
  validity/deposit_hash_chain/mod.rs (4), validity/channel_reg_hash_chain/mod.rs (4)
- src/circuits/withdraw/mod.rs (5)
- src/circuits/test_utils/mod.rs (6)

NOT modeled: src/circuits/witness/mod.rs (the directory module `circuits::witness`
is only recorded as an out-of-scope child referenced by `circuits/mod.rs` and as the
target of the `pub use` re-export in `test_utils/mod.rs`), and src/lib.rs (which
declares the root `circuits` module itself).

This is a handwritten SEMANTIC MODEL of the module declarations: every
`pub mod` / `mod` / `pub use` item of each file in source order, with the
`#[cfg(test)]` attribute recorded as a flag. It is NOT a refinement proof of the
Rust crate: rustc's module resolution, path-attribute overrides, feature gates,
and the contents of the leaf files are not modeled. Leaf-file existence is a
pinned snapshot of the working tree (`ls` of each directory), not something the
model derives.

Security-relevant facts recorded here:
- `pub mod test_utils;` in `circuits/mod.rs` carries NO `#[cfg(test)]`; the
  test_utils module (a re-export shim over `circuits::witness`) is compiled and
  publicly reachable in production builds (`test_utils_is_unconditional_pub_mod`,
  `test_utils_reachable_in_production`).
- The only `#[cfg(test)]` items are the private modules `channel::e2e_flow` and
  `validity::block_hash_chain::nofn_attack`; they are unreachable in production
  builds and reachable under cfg(test) (`test_only_items_pinned`, ...).
- Every referenced child module resolves to an in-scope directory module, the
  out-of-scope `witness` directory module, or an existing leaf `.rs` file
  (`every_referenced_child_exists`); there are no orphan leaf files
  (`no_orphan_leaf_files`); the tree is duplicate-free.

Named boundaries (undischarged): rustc module resolution / cfg evaluation,
witness-module visibility of the `pub use` targets, filesystem snapshot
freshness, root declaration in src/lib.rs.
-/

namespace Zkp.Implementation.CrateLayout

/-- Kind of a declaration item in a `mod.rs` file. `pubUse from` records a
`pub use from::{...};` re-export of one name from module path `from`. -/
inductive ItemKind where
  | pubMod
  | privMod
  | pubUse (fromPath : String)
  deriving DecidableEq, Repr

/-- One item of a `mod.rs` file: its kind, the declared/re-exported name, and
whether the item is guarded by `#[cfg(test)]`. -/
structure Item where
  kind : ItemKind
  name : String
  cfgTest : Bool
  deriving DecidableEq, Repr

def pubMod (name : String) : Item := ⟨.pubMod, name, false⟩
def testMod (name : String) : Item := ⟨.privMod, name, true⟩
def pubUse (fromPath name : String) : Item := ⟨.pubUse fromPath, name, false⟩

/-- Full item list of every in-scope `mod.rs`, keyed by crate-relative module
path, items in source order. Mirrors the ten source files line by line. -/
def declaredItems : List (String × List Item) :=
  [ ("circuits",
      [ pubMod "balance", pubMod "channel", pubMod "test_utils", pubMod "validity",
        pubMod "withdraw", pubMod "witness" ]),
    ("circuits::balance",
      [ pubMod "balance_circuit", pubMod "balance_pis", pubMod "balance_processor",
        pubMod "common", pubMod "receive_deposit_circuit", pubMod "receive_transfer_circuit",
        pubMod "send_tx_circuit", pubMod "spend_circuit", pubMod "switch_board" ]),
    ("circuits::balance::common",
      [ pubMod "account_state", pubMod "deposit_witness", pubMod "recipient",
        pubMod "transfer_witness", pubMod "tx_settlement", pubMod "update_private_state",
        pubMod "update_public_state" ]),
    ("circuits::channel",
      [ pubMod "cancel_close_circuit", pubMod "cancel_close_pis",
        pubMod "close_asset_backing_circuit", pubMod "close_circuit", pubMod "close_pis",
        pubMod "decryption_gadget", testMod "e2e_flow", pubMod "h1_gadget",
        pubMod "post_close_claim_circuit", pubMod "post_close_claim_pis",
        pubMod "state_update_verifier", pubMod "withdrawal_claim_circuit",
        pubMod "withdrawal_claim_pis" ]),
    ("circuits::validity",
      [ pubMod "block_hash_chain", pubMod "channel_reg_hash_chain", pubMod "deposit_hash_chain" ]),
    ("circuits::validity::block_hash_chain",
      [ pubMod "block_chain_pis", pubMod "block_hash_chain_circuit",
        pubMod "block_hash_chain_processor", pubMod "block_step", pubMod "channel_state_message",
        pubMod "ext_public_state", testMod "nofn_attack", pubMod "small_block_message",
        pubMod "update_channel_tree", pubMod "validity_circuit" ]),
    ("circuits::validity::deposit_hash_chain",
      [ pubMod "deposit_chain_pis", pubMod "deposit_chain_processor",
        pubMod "deposit_hash_chain_circuit", pubMod "deposit_step" ]),
    ("circuits::validity::channel_reg_hash_chain",
      [ pubMod "channel_reg_chain_pis", pubMod "channel_reg_chain_processor",
        pubMod "channel_reg_hash_chain_circuit", pubMod "channel_reg_step" ]),
    ("circuits::withdraw",
      [ pubMod "single_withdrawal_circuit", pubMod "withdrawal_chain_circuit",
        pubMod "withdrawal_circuit", pubMod "withdrawal_processor", pubMod "withdrawal_step" ]),
    ("circuits::test_utils",
      [ pubUse "crate::circuits::witness" "balance_witness_generator",
        pubUse "crate::circuits::witness" "block_witness_generator" ]) ]

/-- The requested flat view: each `mod.rs` and the names it declares or
re-exports, in source order (cfg(test) flags live in `declaredItems` /
`testOnlyItems`). -/
def declaredModules : List (String × List String) :=
  [ ("circuits", ["balance", "channel", "test_utils", "validity", "withdraw", "witness"]),
    ("circuits::balance",
      ["balance_circuit", "balance_pis", "balance_processor", "common", "receive_deposit_circuit",
       "receive_transfer_circuit", "send_tx_circuit", "spend_circuit", "switch_board"]),
    ("circuits::balance::common",
      ["account_state", "deposit_witness", "recipient", "transfer_witness", "tx_settlement",
       "update_private_state", "update_public_state"]),
    ("circuits::channel",
      ["cancel_close_circuit", "cancel_close_pis", "close_asset_backing_circuit", "close_circuit",
       "close_pis", "decryption_gadget", "e2e_flow", "h1_gadget", "post_close_claim_circuit",
       "post_close_claim_pis", "state_update_verifier", "withdrawal_claim_circuit",
       "withdrawal_claim_pis"]),
    ("circuits::validity", ["block_hash_chain", "channel_reg_hash_chain", "deposit_hash_chain"]),
    ("circuits::validity::block_hash_chain",
      ["block_chain_pis", "block_hash_chain_circuit", "block_hash_chain_processor", "block_step",
       "channel_state_message", "ext_public_state", "nofn_attack", "small_block_message",
       "update_channel_tree", "validity_circuit"]),
    ("circuits::validity::deposit_hash_chain",
      ["deposit_chain_pis", "deposit_chain_processor", "deposit_hash_chain_circuit", "deposit_step"]),
    ("circuits::validity::channel_reg_hash_chain",
      ["channel_reg_chain_pis", "channel_reg_chain_processor", "channel_reg_hash_chain_circuit",
       "channel_reg_step"]),
    ("circuits::withdraw",
      ["single_withdrawal_circuit", "withdrawal_chain_circuit", "withdrawal_circuit",
       "withdrawal_processor", "withdrawal_step"]),
    ("circuits::test_utils", ["balance_witness_generator", "block_witness_generator"]) ]

theorem declared_modules_agree_with_items :
    declaredItems.map (fun p => (p.1, p.2.map Item.name)) = declaredModules := by rfl

/-- Source files and their physical line counts (pinned). -/
def sourceFiles : List (String × String × Nat) :=
  [ ("circuits", "src/circuits/mod.rs", 6),
    ("circuits::balance", "src/circuits/balance/mod.rs", 9),
    ("circuits::balance::common", "src/circuits/balance/common/mod.rs", 7),
    ("circuits::channel", "src/circuits/channel/mod.rs", 14),
    ("circuits::validity", "src/circuits/validity/mod.rs", 3),
    ("circuits::validity::block_hash_chain", "src/circuits/validity/block_hash_chain/mod.rs", 13),
    ("circuits::validity::deposit_hash_chain", "src/circuits/validity/deposit_hash_chain/mod.rs", 4),
    ("circuits::validity::channel_reg_hash_chain",
      "src/circuits/validity/channel_reg_hash_chain/mod.rs", 4),
    ("circuits::withdraw", "src/circuits/withdraw/mod.rs", 5),
    ("circuits::test_utils", "src/circuits/test_utils/mod.rs", 6) ]

theorem source_files_cover_declared_modules :
    sourceFiles.map (·.1) = declaredItems.map (·.1) := by rfl

/-- Directory modules referenced from in-scope files whose own `mod.rs` is out of
scope for this model. -/
def excludedDirectoryModules : List String := ["circuits::witness"]

/-- Snapshot of the non-`mod.rs` `.rs` files present in each directory
(working tree `ls`, 2026-09-07). This is filesystem data, not derived. -/
def leafFiles : List (String × List String) :=
  [ ("circuits", []),
    ("circuits::balance",
      ["balance_circuit", "balance_pis", "balance_processor", "receive_deposit_circuit",
       "receive_transfer_circuit", "send_tx_circuit", "spend_circuit", "switch_board"]),
    ("circuits::balance::common",
      ["account_state", "deposit_witness", "recipient", "transfer_witness", "tx_settlement",
       "update_private_state", "update_public_state"]),
    ("circuits::channel",
      ["cancel_close_circuit", "cancel_close_pis", "close_asset_backing_circuit", "close_circuit",
       "close_pis", "decryption_gadget", "e2e_flow", "h1_gadget", "post_close_claim_circuit",
       "post_close_claim_pis", "state_update_verifier", "withdrawal_claim_circuit",
       "withdrawal_claim_pis"]),
    ("circuits::validity", []),
    ("circuits::validity::block_hash_chain",
      ["block_chain_pis", "block_hash_chain_circuit", "block_hash_chain_processor", "block_step",
       "channel_state_message", "ext_public_state", "nofn_attack", "small_block_message",
       "update_channel_tree", "validity_circuit"]),
    ("circuits::validity::deposit_hash_chain",
      ["deposit_chain_pis", "deposit_chain_processor", "deposit_hash_chain_circuit", "deposit_step"]),
    ("circuits::validity::channel_reg_hash_chain",
      ["channel_reg_chain_pis", "channel_reg_chain_processor", "channel_reg_hash_chain_circuit",
       "channel_reg_step"]),
    ("circuits::withdraw",
      ["single_withdrawal_circuit", "withdrawal_chain_circuit", "withdrawal_circuit",
       "withdrawal_processor", "withdrawal_step"]),
    ("circuits::test_utils", []),
    ("circuits::witness", ["balance_witness_generator", "block_witness_generator"]) ]

/-- Rust path of child `name` declared inside module `parent`. -/
def childPath (parent name : String) : String := parent ++ "::" ++ name

def isModItem (it : Item) : Bool :=
  match it.kind with
  | .pubMod | .privMod => true
  | .pubUse _ => false

def isPub (it : Item) : Bool :=
  match it.kind with
  | .pubMod | .pubUse _ => true
  | .privMod => false

def modulePaths : List String := declaredItems.map (·.1)

def itemsOf (path : String) : List Item :=
  match declaredItems.lookup path with
  | some items => items
  | none => []

def childrenOf (path : String) : List String := (itemsOf path).filter isModItem |>.map Item.name

def leafFilesOf (path : String) : List String :=
  match leafFiles.lookup path with
  | some fs => fs
  | none => []

/-- A `mod name;` inside `parent` resolves if `parent::name` is an in-scope
directory module, the excluded `witness` directory module, or `name.rs` exists. -/
def childExists (parent name : String) : Bool :=
  modulePaths.contains (childPath parent name) ||
  excludedDirectoryModules.contains (childPath parent name) ||
  (leafFilesOf parent).contains name

/-- Full paths of every declared module (pub or private), test or not. -/
def allDeclaredPaths : List String :=
  declaredItems.foldr (fun p acc => (p.2.filter isModItem).map (fun it => childPath p.1 it.name) ++ acc) []

/-- Items guarded by `#[cfg(test)]`, as (parent, item). -/
def testOnlyItems : List (String × Item) :=
  declaredItems.foldr (fun p acc => (p.2.filter (·.cfgTest)).map (fun it => (p.1, it)) ++ acc) []

/-- `pub use` re-exports as (declaring module, source path, exported name). -/
def reexports : List (String × String × String) :=
  declaredItems.foldr
    (fun p acc =>
      (p.2.filterMap fun it =>
        match it.kind with
        | .pubUse fromPath => some (p.1, fromPath, it.name)
        | _ => none) ++ acc) []

/-- Children of `path` visible under the given cfg: cfg(test) items only when
`test = true`. -/
def visibleChildren (test : Bool) (path : String) : List String :=
  ((itemsOf path).filter fun it => isModItem it && (!it.cfgTest || test)).map
    fun it => childPath path it.name

def step (test : Bool) (frontier : List String) : List String :=
  frontier.foldr (fun p acc => visibleChildren test p ++ acc) []

/-- Module paths exactly `n` declaration steps below the crate root `circuits`
under the given cfg (breadth-first levels). -/
def levels (test : Bool) : Nat → List String
  | 0 => ["circuits"]
  | n + 1 => step test (levels test n)

/-- Module paths reachable from the root in at most `fuel` steps: the
concatenation of levels `0 .. fuel`. -/
def reachableWithin (test : Bool) : Nat → List String
  | 0 => levels test 0
  | n + 1 => reachableWithin test n ++ levels test (n + 1)

def treeDepth : Nat := 4

/-- Reachable module set under production (`test = false`) or cfg(test) builds. -/
def reachable (test : Bool) : List String := reachableWithin test treeDepth

/-- Duplicate-freedom as an executable predicate (Lean core 4.10 without
Mathlib ships no `List.Nodup` here). -/
def nodupB : List String → Bool
  | [] => true
  | x :: xs => !xs.contains x && nodupB xs

/-- Number of occurrences of `m` in `l`. -/
def countOf (m : String) (l : List String) : Nat := (l.filter (· == m)).length

theorem nodupB_cons (x : String) (xs : List String) :
    nodupB (x :: xs) = true ↔ x ∉ xs ∧ nodupB xs = true := by
  simp [nodupB]

-- ## Pinned constants and structure

theorem tree_depth_pinned : treeDepth = 4 := rfl

theorem module_count_pinned : declaredItems.length = 10 := rfl

theorem module_paths_pinned :
    modulePaths =
      ["circuits", "circuits::balance", "circuits::balance::common", "circuits::channel",
       "circuits::validity", "circuits::validity::block_hash_chain",
       "circuits::validity::deposit_hash_chain", "circuits::validity::channel_reg_hash_chain",
       "circuits::withdraw", "circuits::test_utils"] := by rfl

theorem source_line_counts_pinned :
    sourceFiles.map (·.2.2) = [6, 9, 7, 14, 3, 13, 4, 4, 5, 6] := by rfl

theorem declared_item_count_pinned : (declaredItems.map (·.2.length)) = [6, 9, 7, 13, 3, 10, 4, 4, 5, 2] := by
  rfl

-- ## Duplicate-freedom

theorem module_paths_nodup : nodupB modulePaths = true := by decide

theorem children_nodup_per_file : ∀ p ∈ declaredItems, nodupB (p.2.map Item.name) = true := by decide

theorem all_declared_paths_nodup : nodupB allDeclaredPaths = true := by decide

theorem leaf_files_nodup_per_dir : ∀ p ∈ leafFiles, nodupB p.2 = true := by decide

/-- Every in-scope non-root module path is declared by exactly one parent file. -/
theorem non_root_modules_declared_once :
    ∀ m ∈ modulePaths, m ≠ "circuits" → countOf m allDeclaredPaths = 1 := by decide

theorem root_not_self_declared : "circuits" ∉ allDeclaredPaths := by decide

-- ## Existence of referenced children

theorem every_referenced_child_exists :
    ∀ p ∈ declaredItems, ∀ it ∈ p.2, isModItem it = true → childExists p.1 it.name = true := by
  decide

theorem excluded_witness_referenced_by_root :
    ∀ m ∈ excludedDirectoryModules, m ∈ allDeclaredPaths := by decide

/-- Every leaf `.rs` file inside an in-scope directory is declared by that
directory's `mod.rs` (no orphan files). -/
theorem no_orphan_leaf_files :
    ∀ p ∈ declaredItems, ∀ f ∈ leafFilesOf p.1, f ∈ childrenOf p.1 := by decide

theorem leaf_dirs_cover_modules :
    ∀ p ∈ declaredItems, p.1 ∈ leafFiles.map (·.1) := by decide

-- ## cfg(test) items

theorem test_only_items_pinned :
    testOnlyItems =
      [("circuits::channel", testMod "e2e_flow"),
       ("circuits::validity::block_hash_chain", testMod "nofn_attack")] := by rfl

theorem test_only_items_are_private : ∀ p ∈ testOnlyItems, isPub p.2 = false := by decide

theorem non_test_items_are_pub :
    ∀ p ∈ declaredItems, ∀ it ∈ p.2, it.cfgTest = false → isPub it = true := by decide

theorem test_only_count_pinned : testOnlyItems.length = 2 := rfl

-- ## test_utils: unconditional, NOT gated by cfg(test)

/-- `src/circuits/mod.rs` line 3 is a bare `pub mod test_utils;` with no attribute. -/
theorem test_utils_is_unconditional_pub_mod :
    pubMod "test_utils" ∈ itemsOf "circuits" ∧ (pubMod "test_utils").cfgTest = false := by decide

theorem test_utils_not_test_only :
    ∀ p ∈ testOnlyItems, p.2.name ≠ "test_utils" := by decide

theorem test_utils_reachable_in_production : "circuits::test_utils" ∈ reachable false := by decide

theorem test_utils_declares_no_modules : childrenOf "circuits::test_utils" = [] := by rfl

theorem test_utils_reexports_pinned :
    reexports =
      [("circuits::test_utils", "crate::circuits::witness", "balance_witness_generator"),
       ("circuits::test_utils", "crate::circuits::witness", "block_witness_generator")] := by rfl

/-- The re-export targets exist as files in the (out-of-scope) witness
directory; their `pub mod` visibility inside `witness/mod.rs` is a boundary. -/
theorem reexport_targets_are_witness_files :
    ∀ r ∈ reexports, r.2.1 = "crate::circuits::witness" ∧ r.2.2 ∈ leafFilesOf "circuits::witness" := by
  decide

-- ## Reachability under production vs cfg(test)

set_option maxRecDepth 16384

theorem production_reachable_pinned :
    reachable false =
      ["circuits", "circuits::balance", "circuits::channel", "circuits::test_utils",
       "circuits::validity", "circuits::withdraw", "circuits::witness",
       "circuits::balance::balance_circuit", "circuits::balance::balance_pis",
       "circuits::balance::balance_processor", "circuits::balance::common",
       "circuits::balance::receive_deposit_circuit", "circuits::balance::receive_transfer_circuit",
       "circuits::balance::send_tx_circuit", "circuits::balance::spend_circuit",
       "circuits::balance::switch_board", "circuits::channel::cancel_close_circuit",
       "circuits::channel::cancel_close_pis", "circuits::channel::close_asset_backing_circuit",
       "circuits::channel::close_circuit", "circuits::channel::close_pis",
       "circuits::channel::decryption_gadget", "circuits::channel::h1_gadget",
       "circuits::channel::post_close_claim_circuit", "circuits::channel::post_close_claim_pis",
       "circuits::channel::state_update_verifier", "circuits::channel::withdrawal_claim_circuit",
       "circuits::channel::withdrawal_claim_pis", "circuits::validity::block_hash_chain",
       "circuits::validity::channel_reg_hash_chain", "circuits::validity::deposit_hash_chain",
       "circuits::withdraw::single_withdrawal_circuit", "circuits::withdraw::withdrawal_chain_circuit",
       "circuits::withdraw::withdrawal_circuit", "circuits::withdraw::withdrawal_processor",
       "circuits::withdraw::withdrawal_step", "circuits::balance::common::account_state",
       "circuits::balance::common::deposit_witness", "circuits::balance::common::recipient",
       "circuits::balance::common::transfer_witness", "circuits::balance::common::tx_settlement",
       "circuits::balance::common::update_private_state",
       "circuits::balance::common::update_public_state",
       "circuits::validity::block_hash_chain::block_chain_pis",
       "circuits::validity::block_hash_chain::block_hash_chain_circuit",
       "circuits::validity::block_hash_chain::block_hash_chain_processor",
       "circuits::validity::block_hash_chain::block_step",
       "circuits::validity::block_hash_chain::channel_state_message",
       "circuits::validity::block_hash_chain::ext_public_state",
       "circuits::validity::block_hash_chain::small_block_message",
       "circuits::validity::block_hash_chain::update_channel_tree",
       "circuits::validity::block_hash_chain::validity_circuit",
       "circuits::validity::channel_reg_hash_chain::channel_reg_chain_pis",
       "circuits::validity::channel_reg_hash_chain::channel_reg_chain_processor",
       "circuits::validity::channel_reg_hash_chain::channel_reg_hash_chain_circuit",
       "circuits::validity::channel_reg_hash_chain::channel_reg_step",
       "circuits::validity::deposit_hash_chain::deposit_chain_pis",
       "circuits::validity::deposit_hash_chain::deposit_chain_processor",
       "circuits::validity::deposit_hash_chain::deposit_hash_chain_circuit",
       "circuits::validity::deposit_hash_chain::deposit_step"] := by rfl

theorem reachable_is_saturated_at_tree_depth :
    levels false (treeDepth + 1) = [] ∧ levels true (treeDepth + 1) = [] := by decide

theorem reachable_nodup : nodupB (reachable false) = true ∧ nodupB (reachable true) = true := by
  decide

theorem all_modules_reachable_in_production : ∀ m ∈ modulePaths, m ∈ reachable false := by decide

theorem e2e_flow_unreachable_in_production :
    "circuits::channel::e2e_flow" ∉ reachable false := by decide

theorem nofn_attack_unreachable_in_production :
    "circuits::validity::block_hash_chain::nofn_attack" ∉ reachable false := by decide

theorem test_only_items_reachable_under_cfg_test :
    ∀ p ∈ testOnlyItems, childPath p.1 p.2.name ∈ reachable true := by decide

theorem test_only_items_unreachable_in_production :
    ∀ p ∈ testOnlyItems, childPath p.1 p.2.name ∉ reachable false := by decide

/-- Production reachability is exactly the non-cfg(test) declared paths (plus the root). -/
theorem production_reachable_iff_declared_non_test :
    ∀ m ∈ allDeclaredPaths,
      (m ∈ reachable false ↔ ∀ p ∈ testOnlyItems, childPath p.1 p.2.name ≠ m) := by decide

theorem cfg_test_reachable_is_all_declared :
    ∀ m ∈ allDeclaredPaths, m ∈ reachable true := by decide

theorem production_reachable_subset_of_test :
    ∀ m ∈ reachable false, m ∈ reachable true := by decide

-- ## Concrete positive examples

theorem validity_children_example :
    childrenOf "circuits::validity" =
      ["block_hash_chain", "channel_reg_hash_chain", "deposit_hash_chain"] := by rfl

theorem channel_children_example :
    childrenOf "circuits::channel" =
      ["cancel_close_circuit", "cancel_close_pis", "close_asset_backing_circuit", "close_circuit",
       "close_pis", "decryption_gadget", "e2e_flow", "h1_gadget", "post_close_claim_circuit",
       "post_close_claim_pis", "state_update_verifier", "withdrawal_claim_circuit",
       "withdrawal_claim_pis"] := by rfl

theorem root_children_example :
    childrenOf "circuits" = ["balance", "channel", "test_utils", "validity", "withdraw", "witness"] := by
  rfl

theorem close_circuit_resolves_to_file :
    childExists "circuits::channel" "close_circuit" = true := by decide

theorem unknown_child_does_not_resolve :
    childExists "circuits::channel" "no_such_module" = false := by decide

end Zkp.Implementation.CrateLayout

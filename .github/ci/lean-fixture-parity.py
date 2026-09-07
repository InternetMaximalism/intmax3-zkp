#!/usr/bin/env python3
"""Fixture-level parity evidence for the handwritten Lean public-input codecs.

This is NOT a refinement proof.  It is *evidence* that, on the checked-in prover
fixtures, the Lean models in ``doc/audit/zkp/Zkp/Implementation`` decode the real
public-input word vectors to the same field values that the Rust prover recorded
in its companion JSON and that the Solidity consumers recompute.

How it works
------------
For every fixture we

1. read the u64 public-input words the prover emitted (``*_mle.json`` ->
   ``proof.publicInputs``, or a raw word-list fixture),
2. generate a *temporary* Lean probe that imports the already-built module,
   binds those words, ``#eval``s the module's own decoder and prints flat
   ``FIELD <name> <value>`` lines through a **probe-local** printer (no module
   is edited),
3. run ``lake env lean <probe>`` in ``doc/audit/zkp``,
4. compare each printed field against the value derived from the companion
   fixture (and, where the Solidity consumer recomputes a digest, against a
   pure-Python keccak recomputation of the exact Solidity preimage),
5. where the model has an encoder, re-encode the decoded value and compare the
   words against the prover's original words.

Fields that genuinely cannot be compared (a companion fixture does not record
them, or they are opaque hash pre-images) are reported ``not-comparable`` and
never silently dropped.  Any mismatch, any undecodable fixture and any missing
field is a FAILURE and exits non-zero: a mismatch is a finding about the model.
"""

from __future__ import annotations

import argparse
import json
import os
import shutil
import subprocess
import sys
import tempfile
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, Iterable, List, Optional, Sequence, Tuple

REPO_ROOT = Path(__file__).resolve().parents[2]
DATA_DIR = REPO_ROOT / "contracts" / "test" / "data"
LEAN_DIR = REPO_ROOT / "doc" / "audit" / "zkp"

WORD_BASE = 1 << 32

PASS = "PASS"
FAIL = "FAIL"
NOT_COMPARABLE = "not-comparable"


# --------------------------------------------------------------------------
# keccak-256 (pure Python, no third-party dependency, fully offline)
# --------------------------------------------------------------------------

_KECCAK_RC = [
    0x0000000000000001, 0x0000000000008082, 0x800000000000808A, 0x8000000080008000,
    0x000000000000808B, 0x0000000080000001, 0x8000000080008081, 0x8000000000008009,
    0x000000000000008A, 0x0000000000000088, 0x0000000080008009, 0x000000008000000A,
    0x000000008000808B, 0x800000000000008B, 0x8000000000008089, 0x8000000000008003,
    0x8000000000008002, 0x8000000000000080, 0x000000000000800A, 0x800000008000000A,
    0x8000000080008081, 0x8000000000008080, 0x0000000080000001, 0x8000000080008008,
]
_KECCAK_ROT = [
    [0, 36, 3, 41, 18],
    [1, 44, 10, 45, 2],
    [62, 6, 43, 15, 61],
    [28, 55, 25, 21, 56],
    [27, 20, 39, 8, 14],
]
_MASK64 = 0xFFFFFFFFFFFFFFFF


def _rotl64(value: int, shift: int) -> int:
    return ((value << shift) | (value >> (64 - shift))) & _MASK64


def _keccak_f(state: List[List[int]]) -> List[List[int]]:
    for rnd in range(24):
        c = [state[x][0] ^ state[x][1] ^ state[x][2] ^ state[x][3] ^ state[x][4] for x in range(5)]
        d = [c[(x - 1) % 5] ^ _rotl64(c[(x + 1) % 5], 1) for x in range(5)]
        for x in range(5):
            for y in range(5):
                state[x][y] ^= d[x]
        b = [[0] * 5 for _ in range(5)]
        for x in range(5):
            for y in range(5):
                b[y][(2 * x + 3 * y) % 5] = _rotl64(state[x][y], _KECCAK_ROT[x][y])
        for x in range(5):
            for y in range(5):
                state[x][y] = b[x][y] ^ ((~b[(x + 1) % 5][y]) & b[(x + 2) % 5][y])
        state[0][0] ^= _KECCAK_RC[rnd]
    return state


def keccak256(data: bytes) -> bytes:
    """Ethereum keccak-256 (original padding, not SHA3-256)."""
    rate = 136
    state = [[0] * 5 for _ in range(5)]
    message = bytearray(data)
    message.append(0x01)
    while len(message) % rate != 0:
        message.append(0x00)
    message[-1] ^= 0x80
    for offset in range(0, len(message), rate):
        block = message[offset:offset + rate]
        for i in range(rate // 8):
            state[i % 5][i // 5] ^= int.from_bytes(block[i * 8:i * 8 + 8], "little")
        _keccak_f(state)
    out = b""
    for i in range(4):
        out += state[i % 5][i // 5].to_bytes(8, "little")
    return out[:32]


# --------------------------------------------------------------------------
# limb helpers (big-endian u32 limbs, the `U32LimbTrait::to_u32_vec` order)
# --------------------------------------------------------------------------

def be_limbs(value: int, count: int = 8) -> List[int]:
    """`count` big-endian u32 limbs, most-significant first."""
    return [(value >> (32 * (count - 1 - i))) & 0xFFFFFFFF for i in range(count)]


def hex_limbs(text: str, count: int = 8) -> List[int]:
    return be_limbs(int(text, 16), count)


def address_limbs(text: str) -> List[int]:
    """20-byte address as five big-endian u32 limbs."""
    return be_limbs(int(text, 16), 5)


def be_value(limbs: Sequence[int]) -> int:
    acc = 0
    for limb in limbs:
        acc = acc * WORD_BASE + limb
    return acc


def as_int(value) -> int:
    if isinstance(value, bool):
        raise TypeError("bool is not an accepted numeric fixture value")
    if isinstance(value, int):
        return value
    text = str(value).strip()
    return int(text, 16) if text.startswith("0x") else int(text)


def norm_num(value) -> str:
    return str(as_int(value))


def norm_words(words: Iterable[int]) -> str:
    return ",".join(str(int(w)) for w in words)


def norm_bool(value: bool) -> str:
    return "true" if value else "false"


# --------------------------------------------------------------------------
# Solidity recomputations (IntmaxRollup.sol)
# --------------------------------------------------------------------------

def fold_withdrawal_leaf(prev: bytes, withdrawal: dict) -> bytes:
    """`IntmaxRollup._foldWithdrawalLeaf`: keccak over a 152-byte packed leaf."""
    preimage = (
        prev
        + bytes.fromhex(withdrawal["recipient"][2:])
        + as_int(withdrawal["token_index"]).to_bytes(4, "big")
        + as_int(withdrawal["amount"]).to_bytes(32, "big")
        + bytes.fromhex(withdrawal["nullifier"][2:])
        + bytes.fromhex(withdrawal["aux_data"][2:])
    )
    assert len(preimage) == 152, len(preimage)
    return keccak256(preimage)


def withdrawal_pis_hash(payout: dict) -> Tuple[int, bytes]:
    """`IntmaxRollup._withdrawalPisHash` with the 2**253 `remove_3bits` mask.

    Returns (masked hash as int, the 92-byte preimage)."""
    chain = b"\x00" * 32
    for withdrawal in payout["withdrawals"]:
        chain = fold_withdrawal_leaf(chain, withdrawal)
    preimage = (
        chain
        + bytes.fromhex(payout["withdrawal_prover"][2:])
        + bytes.fromhex(payout["ext_commitment"][2:])
        + as_int(payout["block_number"]).to_bytes(8, "big")
    )
    assert len(preimage) == 92, len(preimage)
    return int.from_bytes(keccak256(preimage), "big") & ((1 << 253) - 1), preimage


def validity_u32_words(vpis: dict) -> List[int]:
    """`ValidityPublicInputs::to_u32_vec` = the 41-word keccak preimage order."""
    initial_block = as_int(vpis["initial_block_number"])
    final_block = as_int(vpis["final_block_number"])
    return (
        [initial_block // WORD_BASE, initial_block % WORD_BASE]
        + hex_limbs(vpis["initial_block_chain"])
        + hex_limbs(vpis["initial_ext_commitment"])
        + [final_block // WORD_BASE, final_block % WORD_BASE]
        + hex_limbs(vpis["final_block_chain"])
        + hex_limbs(vpis["final_ext_commitment"])
        + address_limbs(vpis["prover"])
    )


def validity_preimage(vpis: dict) -> bytes:
    return b"".join(w.to_bytes(4, "big") for w in validity_u32_words(vpis))


# --------------------------------------------------------------------------
# Lean probe construction / execution
# --------------------------------------------------------------------------

PROBE_PRELUDE = """\
-- Auto-generated by .github/ci/lean-fixture-parity.py.  Throw-away probe file:
-- it only IMPORTS the audited modules and prints with a probe-local printer.
private def emitNat (name : String) (v : Nat) : IO Unit :=
  IO.println ("FIELD " ++ name ++ " " ++ toString v)

private def emitWords (name : String) (v : List Nat) : IO Unit :=
  IO.println ("FIELD " ++ name ++ " " ++ String.intercalate "," (v.map toString))

private def emitBool (name : String) (v : Bool) : IO Unit :=
  IO.println ("FIELD " ++ name ++ " " ++ (if v then "true" else "false"))
"""


def lean_nat_list(words: Sequence[int]) -> str:
    return "[" + ", ".join(str(int(w)) for w in words) + "]"


def default_elan_bin() -> str:
    """elan installs outside the default PATH on this project's machines."""
    override = os.environ.get("LEAN_PARITY_ELAN_BIN")
    if override is not None:
        return override
    return str(Path.home() / ".elan" / "bin")


@dataclass
class ProbeResult:
    ok: bool
    fields: Dict[str, str]
    stdout: str
    stderr: str
    error: Optional[str] = None


def parse_probe_output(text: str) -> ProbeResult:
    """Parse the flat ``FIELD name value`` protocol emitted by a probe."""
    fields: Dict[str, str] = {}
    decoded = False
    error: Optional[str] = None
    for raw in text.splitlines():
        line = raw.strip()
        if line == "DECODE_OK":
            decoded = True
        elif line.startswith("DECODE_ERROR"):
            error = line[len("DECODE_ERROR"):].strip() or "(no detail)"
        elif line.startswith("FIELD "):
            rest = line[len("FIELD "):]
            parts = rest.split(" ", 1)
            if len(parts) == 2:
                fields[parts[0]] = parts[1].strip()
    if error is not None:
        return ProbeResult(False, fields, text, "", f"decoder rejected the fixture: {error}")
    if not decoded:
        return ProbeResult(False, fields, text, "", "probe printed no DECODE_OK marker")
    return ProbeResult(True, fields, text, "")


class LeanRunner:
    """Runs ``lake env lean`` on a generated probe inside the Lean project."""

    def __init__(self, lean_dir: Path, elan_bin: Optional[str] = None):
        self.lean_dir = Path(lean_dir)
        self.env = dict(os.environ)
        if elan_bin is None:
            elan_bin = default_elan_bin()
        if elan_bin and Path(elan_bin).is_dir():
            self.env["PATH"] = elan_bin + os.pathsep + self.env.get("PATH", "")

    def available(self) -> bool:
        return shutil.which("lake", path=self.env.get("PATH")) is not None

    def run(self, source: str, name: str) -> ProbeResult:
        with tempfile.TemporaryDirectory(prefix="lean-parity-") as tmp:
            probe = Path(tmp) / f"{name}.lean"
            probe.write_text(source, encoding="utf-8")
            try:
                proc = subprocess.run(
                    ["lake", "env", "lean", str(probe)],
                    cwd=str(self.lean_dir),
                    env=self.env,
                    capture_output=True,
                    text=True,
                    timeout=600,
                )
            except FileNotFoundError:
                return ProbeResult(False, {}, "", "", "`lake` not found on PATH")
            except subprocess.TimeoutExpired:
                return ProbeResult(False, {}, "", "", "`lake env lean` timed out")
        combined = proc.stdout
        if proc.returncode != 0:
            detail = (proc.stderr or proc.stdout).strip().splitlines()
            head = " | ".join(detail[:6]) if detail else f"exit {proc.returncode}"
            return ProbeResult(False, {}, proc.stdout, proc.stderr, f"lean failed: {head}")
        result = parse_probe_output(combined)
        result.stderr = proc.stderr
        return result


# --------------------------------------------------------------------------
# Case model
# --------------------------------------------------------------------------

@dataclass
class Case:
    name: str
    module: str
    decoder: str
    words_source: str
    companion: str
    probe: str
    expected: Dict[str, str] = field(default_factory=dict)
    not_comparable: Dict[str, str] = field(default_factory=dict)
    notes: List[str] = field(default_factory=list)


@dataclass
class FieldResult:
    field: str
    status: str
    lean: Optional[str] = None
    expected: Optional[str] = None
    detail: str = ""


@dataclass
class CaseResult:
    case: Case
    ok: bool
    fields: List[FieldResult]
    error: Optional[str] = None


def evaluate(case: Case, probe: ProbeResult) -> CaseResult:
    """Compare every expected field against what the Lean probe printed."""
    if not probe.ok:
        return CaseResult(case, False, [], probe.error or "probe failed")
    results: List[FieldResult] = []
    ok = True
    for name in sorted(case.expected):
        want = case.expected[name]
        got = probe.fields.get(name)
        if got is None:
            ok = False
            results.append(FieldResult(name, FAIL, None, want, "field missing from probe output"))
        elif got == want:
            results.append(FieldResult(name, PASS, got, want))
        else:
            ok = False
            results.append(FieldResult(name, FAIL, got, want, "model value differs from fixture"))
    for name in sorted(case.not_comparable):
        results.append(FieldResult(name, NOT_COMPARABLE, probe.fields.get(name), None,
                                   case.not_comparable[name]))
    return CaseResult(case, ok, results)


# --------------------------------------------------------------------------
# Probe sources
# --------------------------------------------------------------------------

def _probe(imports: Sequence[str], opens: Sequence[str], words: Sequence[int], body: str) -> str:
    lines = [f"import {m}" for m in imports]
    lines += [f"open {o}" for o in opens]
    lines.append("")
    lines.append(PROBE_PRELUDE)
    lines.append(f"private def probeWords : List Nat := {lean_nat_list(words)}")
    lines.append("")
    lines.append("#eval show IO Unit from do")
    lines.append('  emitNat "input.length" probeWords.length')
    lines.append(body.rstrip())
    lines.append("")
    return "\n".join(lines)


# --------------------------------------------------------------------------
# Case builders
# --------------------------------------------------------------------------

def _load(data_dir: Path, name: str) -> dict:
    return json.loads((Path(data_dir) / name).read_text(encoding="utf-8"))


def _pi_words(data_dir: Path, name: str) -> List[int]:
    payload = _load(data_dir, name)
    return [int(w, 16) for w in payload["proof"]["publicInputs"]]


def build_close_case(data_dir: Path, mle_name: str, companion_name: Optional[str],
                     case_name: str) -> Case:
    words = _pi_words(data_dir, mle_name)
    body = """
  match Zkp.Implementation.ClosePublicInputs.fromU64Slice probeWords with
  | .error e => IO.println ("DECODE_ERROR " ++ toString (repr e))
  | .ok p => do
    IO.println "DECODE_OK"
    emitNat "channelId" p.channelId
    emitNat "closeNonce" (Zkp.Implementation.ClosePublicInputs.joinValue p.closeNonce.hi p.closeNonce.lo)
    emitNat "finalEpoch" (Zkp.Implementation.ClosePublicInputs.joinValue p.finalEpoch.hi p.finalEpoch.lo)
    emitNat "finalSmallBlock" (Zkp.Implementation.ClosePublicInputs.joinValue p.finalSmallBlock.hi p.finalSmallBlock.lo)
    emitNat "freezeNonce" (Zkp.Implementation.ClosePublicInputs.joinValue p.freezeNonce.hi p.freezeNonce.lo)
    emitWords "stateDigest" p.stateDigest.words
    emitWords "h1" p.h1.words
    emitWords "genesisFund" p.genesisFund.words
    emitWords "fundRoot" p.fundRoot.words
    emitWords "burnHash" p.burnHash.words
    emitWords "withdrawalDigest" p.withdrawalDigest.words
    emitWords "closeId" p.closeId.words
    emitNat "snapshot" (Zkp.Implementation.ClosePublicInputs.joinValue p.snapshot.hi p.snapshot.lo)
    emitNat "stateVersion" (Zkp.Implementation.ClosePublicInputs.joinValue p.stateVersion.hi p.stateVersion.lo)
    emitWords "settledChain" p.settledChain.words
    emitWords "accumulatorRoot" p.accumulatorRoot.words
    emitWords "memberSet" p.memberSet.words
    emitNat "memberCount" p.memberCount
    emitNat "delegateCount" p.delegateCount
    emitWords "tokenFundsDigest" p.tokenFundsDigest.words
    emitWords "reencoded" (Zkp.Implementation.ClosePublicInputs.toU64Vec p)
"""
    case = Case(
        name=case_name,
        module="Zkp.Implementation.ClosePublicInputs",
        decoder="ClosePublicInputs.fromU64Slice",
        words_source=f"{mle_name} -> proof.publicInputs (103 words)",
        companion=companion_name or "(none)",
        probe=_probe(["Zkp.Implementation.ClosePublicInputs"], [], words, body),
    )
    case.expected["input.length"] = "103"
    case.expected["reencoded"] = norm_words(words)
    if companion_name is None:
        for name in ("channelId", "closeNonce", "finalEpoch", "finalSmallBlock", "freezeNonce",
                     "stateDigest", "h1", "genesisFund", "fundRoot", "burnHash",
                     "withdrawalDigest", "closeId", "snapshot", "stateVersion", "settledChain",
                     "accumulatorRoot", "memberSet", "memberCount", "delegateCount",
                     "tokenFundsDigest"):
            case.not_comparable[name] = "no companion prover JSON is checked in for this fixture"
        case.notes.append("decode + re-encode roundtrip only (no companion record)")
        return case

    c = _load(data_dir, companion_name)
    case.expected.update({
        "channelId": norm_num(c["channel_id"]),
        "closeNonce": norm_num(c["close_nonce"]),
        "finalEpoch": norm_num(c["final_epoch"]),
        "finalSmallBlock": norm_num(c["final_small_block_number"]),
        "freezeNonce": norm_num(c["close_freeze_nonce"]),
        "stateDigest": norm_words(hex_limbs(c["final_channel_state_digest"])),
        "h1": norm_words(hex_limbs(c["final_balance_state_h1"])),
        "genesisFund": norm_words(be_limbs(as_int(c["channel_fund_amount"]))),
        "fundRoot": norm_words(hex_limbs(c["channel_fund_intmax_state_root"])),
        "burnHash": norm_words(hex_limbs(c["burn_tx_hash"])),
        "withdrawalDigest": norm_words(hex_limbs(c["close_withdrawal_digest"])),
        "closeId": norm_words(hex_limbs(c["close_intent_digest"])),
        "snapshot": norm_num(c["snapshot_medium_block_number"]),
        "stateVersion": norm_num(c["final_state_version"]),
        "settledChain": norm_words(hex_limbs(c["final_settled_tx_chain"])),
        "accumulatorRoot": norm_words(hex_limbs(c["final_settled_tx_accumulator_root"])),
        "memberSet": norm_words(hex_limbs(c["member_set_commitment"])),
        "memberCount": norm_num(c["member_count"]),
        "delegateCount": norm_num(c["delegate_count"]),
        "tokenFundsDigest": norm_words(hex_limbs(c["token_funds_digest"])),
    })
    case.notes.append(
        "companion fields member_pk_gs, channel_fund_amounts[1..9], token_registry and "
        "token_count are not separately registered: they only enter through the opaque "
        "token_funds_digest / member_set_commitment pre-images")
    return case


def build_cancel_close_case(data_dir: Path) -> Case:
    words = _pi_words(data_dir, "cancel_close_mle.json")
    c = _load(data_dir, "cancel_close.json")
    body = """
  match Zkp.Implementation.CancelClosePublicInputs.fromU64Slice probeWords with
  | .error e => IO.println ("DECODE_ERROR " ++ toString (repr e))
  | .ok p => do
    IO.println "DECODE_OK"
    emitNat "channelId" p.channelId
    emitWords "closeId" p.closeId.words
    emitWords "memberSet" p.memberSet.words
    emitNat "closeVersion" p.closeVersion
    emitNat "revivedVersion" p.revivedVersion
    emitWords "revivedDigest" p.revivedDigest.words
    emitWords "reencoded" (Zkp.Implementation.CancelClosePublicInputs.toU64Vec p)
"""
    case = Case(
        name="cancel_close",
        module="Zkp.Implementation.CancelClosePublicInputs",
        decoder="CancelClosePublicInputs.fromU64Slice",
        words_source="cancel_close_mle.json -> proof.publicInputs (29 words)",
        companion="cancel_close.json",
        probe=_probe(["Zkp.Implementation.CancelClosePublicInputs"], [], words, body),
    )
    case.expected.update({
        "input.length": "29",
        "channelId": norm_num(c["channel_id"]),
        "closeId": norm_words(hex_limbs(c["close_intent_digest"])),
        "memberSet": norm_words(hex_limbs(c["member_set_commitment"])),
        "closeVersion": norm_num(c["close_final_state_version"]),
        "revivedVersion": norm_num(c["revived_state_version"]),
        "revivedDigest": norm_words(hex_limbs(c["revived_channel_state_digest"])),
        "reencoded": norm_words(words),
    })
    case.notes.append("companion member_pk_gs is not registered; only its commitment is")
    return case


def build_withdrawal_claim_case(data_dir: Path) -> Case:
    words = _pi_words(data_dir, "withdrawal_claim_mle.json")
    c = _load(data_dir, "withdrawal_claim.json")
    body = """
  match Zkp.Implementation.WithdrawalClaimPublicInputs.fromU64Slice probeWords with
  | .error e => IO.println ("DECODE_ERROR " ++ toString (repr e))
  | .ok p => do
    IO.println "DECODE_OK"
    emitWords "closeId" p.closeId.words
    emitNat "channelId" p.channelId
    emitWords "h1" p.h1.words
    emitWords "memberPk" p.memberPk.words
    emitWords "recipient" [p.recipient.a0, p.recipient.a1, p.recipient.a2, p.recipient.a3, p.recipient.a4]
    emitWords "ciphertextDigest" p.ciphertextDigest.words
    emitWords "nullifier" p.nullifier.words
    emitNat "amount" (Zkp.Implementation.ClosePublicInputs.joinValue p.amount.hi p.amount.lo)
    emitNat "tokenSlot" p.tokenSlot
    emitNat "tokenIndex" p.tokenIndex
    emitWords "reencoded" (Zkp.Implementation.WithdrawalClaimPublicInputs.toU64Vec p)
"""
    case = Case(
        name="withdrawal_claim",
        module="Zkp.Implementation.WithdrawalClaimPublicInputs",
        decoder="WithdrawalClaimPublicInputs.fromU64Slice",
        words_source="withdrawal_claim_mle.json -> proof.publicInputs (50 words)",
        companion="withdrawal_claim.json",
        probe=_probe(["Zkp.Implementation.WithdrawalClaimPublicInputs",
                      "Zkp.Implementation.ClosePublicInputs"], [], words, body),
    )
    case.expected.update({
        "input.length": "50",
        "closeId": norm_words(hex_limbs(c["close_intent_digest"])),
        "channelId": norm_num(c["channel_id"]),
        "h1": norm_words(hex_limbs(c["final_balance_state_h1"])),
        "memberPk": norm_words(hex_limbs(c["member_pk_g"])),
        "recipient": norm_words(address_limbs(c["recipient"])),
        "ciphertextDigest": norm_words(hex_limbs(c["user_amount_digest"])),
        "nullifier": norm_words(hex_limbs(c["withdrawal_nullifier"])),
        "amount": norm_num(c["amount"]),
        "tokenSlot": norm_num(c["token_slot"]),
        "tokenIndex": norm_num(c["token_index"]),
        "reencoded": norm_words(words),
    })
    return case


def build_post_close_claim_case(data_dir: Path) -> Case:
    words = _pi_words(data_dir, "post_close_claim_mle.json")
    c = _load(data_dir, "post_close_claim.json")
    body = """
  match Zkp.Implementation.PostCloseClaimPublicInputs.fromU64Slice probeWords with
  | .error e => IO.println ("DECODE_ERROR " ++ toString (repr e))
  | .ok p => do
    IO.println "DECODE_OK"
    emitWords "closeIntentDigest" p.closeIntentDigest.words
    emitNat "receiverChannelId" p.receiverChannelId
    emitWords "incomingTxHash" p.incomingTxHash.words
    emitWords "receiverPkG" p.receiverPkG.words
    emitWords "recipient" p.recipient.words
    emitWords "sharedNativeNullifier" p.sharedNativeNullifier.words
    emitNat "amount" (Zkp.Implementation.PostCloseClaimPublicInputs.joinValue p.amount.hi p.amount.lo)
    emitWords "finalBalanceStateH1" p.finalBalanceStateH1.words
    emitWords "finalAccumulatorRoot" p.finalAccumulatorRoot.words
    emitNat "tokenIndex" p.tokenIndex
    emitWords "reencoded" (Zkp.Implementation.PostCloseClaimPublicInputs.toU64Vec p)
"""
    case = Case(
        name="post_close_claim",
        module="Zkp.Implementation.PostCloseClaimPublicInputs",
        decoder="PostCloseClaimPublicInputs.fromU64Slice",
        words_source="post_close_claim_mle.json -> proof.publicInputs (57 words)",
        companion="post_close_claim.json",
        probe=_probe(["Zkp.Implementation.PostCloseClaimPublicInputs"], [], words, body),
    )
    case.expected.update({
        "input.length": "57",
        "closeIntentDigest": norm_words(hex_limbs(c["close_intent_digest"])),
        "receiverChannelId": norm_num(c["receiver_channel_id"]),
        "incomingTxHash": norm_words(hex_limbs(c["incoming_tx_hash"])),
        "receiverPkG": norm_words(hex_limbs(c["receiver_pk_g"])),
        "recipient": norm_words(address_limbs(c["recipient"])),
        "sharedNativeNullifier": norm_words(hex_limbs(c["shared_native_nullifier"])),
        "amount": norm_num(c["amount"]),
        "tokenIndex": norm_num(c["token_index"]),
        "reencoded": norm_words(words),
    })
    case.not_comparable["finalBalanceStateH1"] = \
        "post_close_claim.json does not record final_balance_state_h1"
    case.not_comparable["finalAccumulatorRoot"] = \
        "post_close_claim.json does not record final_settled_tx_accumulator_root"
    return case


def build_close_asset_backing_case(data_dir: Path) -> Case:
    raw = _load(data_dir, "close_asset_backing_public_inputs.json")
    words = [as_int(w) for w in raw]
    manifest = _load(data_dir, "close_asset_backing_manifest.json")
    intent = _load(data_dir, "close_intent.json")
    mle_words = _pi_words(data_dir, "close_asset_backing_mle.json")
    body = """
  match Zkp.Implementation.CloseAssetBacking.parsePublicInputs probeWords with
  | .error _ => IO.println "DECODE_ERROR CloseAssetBacking.Error"
  | .ok p => do
    IO.println "DECODE_OK"
    emitNat "channelId" p.channelId
    emitWords "settledTxChain" p.settledTxChain.words
    emitWords "tokenFundsDigest" p.tokenFundsDigest.words
    emitWords "extendedStateCommitment" p.extendedStateCommitment.words
    emitNat "anchorBlockNumber" p.anchorBlockNumber
    emitWords "reencoded" (Zkp.Implementation.CloseAssetBacking.PublicInputs.words p)
"""
    case = Case(
        name="close_asset_backing",
        module="Zkp.Implementation.CloseAssetBacking",
        decoder="CloseAssetBacking.parsePublicInputs",
        words_source="close_asset_backing_public_inputs.json (raw 26 words)",
        companion="close_asset_backing_manifest.json + close_intent.json",
        probe=_probe(["Zkp.Implementation.CloseAssetBacking"], [], words, body),
    )
    case.expected.update({
        "input.length": "26",
        "channelId": norm_num(manifest["channelId"]),
        "settledTxChain": norm_words(hex_limbs(intent["final_settled_tx_chain"])),
        "tokenFundsDigest": norm_words(hex_limbs(intent["token_funds_digest"])),
        "extendedStateCommitment":
            norm_words(hex_limbs(manifest["backingFinalizedExtendedStateCommitment"])),
        "anchorBlockNumber": norm_num(manifest["backingAnchorBlockNumber"]),
        "reencoded": norm_words(words),
    })
    if as_int(manifest["backingPublicInputCount"]) != len(words):
        raise ValueError("manifest backingPublicInputCount disagrees with the raw word list")
    if mle_words != words:
        raise ValueError("close_asset_backing_mle.json publicInputs differ from the raw word list")
    case.notes.append(
        "raw word list cross-checked against close_asset_backing_mle.json proof.publicInputs "
        "and against manifest.backingPublicInputCount before the probe runs")
    return case


def build_withdrawal_chain_case(data_dir: Path, prefix: str) -> Case:
    mle_name = f"{prefix}withdrawal_mle.json"
    payout_name = f"{prefix}withdrawal_payout.json"
    words = _pi_words(data_dir, mle_name)
    payout = _load(data_dir, payout_name)
    pis_hash, _preimage = withdrawal_pis_hash(payout)
    ext = int(payout["ext_commitment"], 16)
    block = as_int(payout["block_number"])
    body = f"""
  emitNat "solidity.limbsToBytes32(pi,8)" (Zkp.Implementation.RollupValue.limbsToBytes32 probeWords 8)
  emitBool "solidity.limbsMatchBytes32(pi,0,pisHash)"
    (Zkp.Implementation.RollupValue.limbsMatchBytes32 probeWords 0 {pis_hash})
  emitNat "solidity.pi16" (probeWords.getD 16 0)
  match Zkp.Implementation.WithdrawalChain.fromU64Slice probeWords with
  | .error e => IO.println ("DECODE_ERROR " ++ toString (repr e))
  | .ok p => do
    IO.println "DECODE_OK"
    emitWords "pisHash" p.pisHash.words
    emitWords "extCommitment" p.extCommitment.words
    emitNat "blockNumber" p.blockNumber
    emitWords "reencoded" (Zkp.Implementation.WithdrawalChain.PublicInputs.toU64Vec p)
"""
    case = Case(
        name=f"withdrawal_chain[{prefix or 'plain'}]",
        module="Zkp.Implementation.WithdrawalChain",
        decoder="WithdrawalChain.fromU64Slice + RollupValue.limbsToBytes32/limbsMatchBytes32",
        words_source=f"{mle_name} -> proof.publicInputs (17 words)",
        companion=f"{payout_name} + IntmaxRollup._withdrawalPisHash keccak recomputation",
        probe=_probe(["Zkp.Implementation.WithdrawalChain"], [], words, body),
    )
    case.expected.update({
        "input.length": "17",
        "pisHash": norm_words(be_limbs(pis_hash)),
        "extCommitment": norm_words(be_limbs(ext)),
        "blockNumber": str(block),
        "solidity.limbsToBytes32(pi,8)": str(ext),
        "solidity.limbsMatchBytes32(pi,0,pisHash)": "true",
        "solidity.pi16": str(block),
        "reencoded": norm_words(words),
    })
    case.notes.append(
        "pisHash is the Python keccak recomputation of the Solidity 92-byte preimage "
        "(folded withdrawal chain || prover || ext_commitment || block_number), masked to 2^253")
    return case


def build_validity_case(data_dir: Path, name: str, vpis: dict,
                        registered_pi: Optional[List[int]],
                        pi_source: str) -> Case:
    words = validity_u32_words(vpis)
    preimage = validity_preimage(vpis)
    digest = int.from_bytes(keccak256(preimage), "big")
    ib = as_int(vpis["initial_block_number"])
    fb = as_int(vpis["final_block_number"])

    def w8(text: str) -> str:
        return "⟨" + ", ".join(str(x) for x in hex_limbs(text)) + "⟩"

    prover = address_limbs(vpis["prover"])
    lean_value = (
        "{ initialBlockNumber := %d\n"
        "  initialBlockChain := %s\n"
        "  initialExtCommitment := %s\n"
        "  finalBlockNumber := %d\n"
        "  finalBlockChain := %s\n"
        "  finalExtCommitment := %s\n"
        "  prover := ⟨%s⟩ }"
    ) % (ib, w8(vpis["initial_block_chain"]), w8(vpis["initial_ext_commitment"]),
         fb, w8(vpis["final_block_chain"]), w8(vpis["final_ext_commitment"]),
         ", ".join(str(x) for x in prover))

    lines = [
        "import Zkp.Implementation.ValidityChain",
        "",
        PROBE_PRELUDE,
        f"private def probeWords : List Nat := {lean_nat_list(registered_pi or [])}",
        "",
        "private def probeVPIs : Zkp.Implementation.ValidityChain.ValidityPIs :=",
        "  " + lean_value.replace("\n", "\n  "),
        "",
        "#eval show IO Unit from do",
        '  IO.println "DECODE_OK"',
        '  emitNat "input.length" probeWords.length',
        '  emitWords "u32Words" (Zkp.Implementation.ValidityChain.ValidityPIs.u32Words probeVPIs)',
        '  emitWords "preimage" ((Zkp.Implementation.ValidityChain.ValidityPIs.preimage probeVPIs).map UInt8.toNat)',
        '  emitNat "toRollup.initialBlock" (Zkp.Implementation.ValidityChain.ValidityPIs.toRollup probeVPIs).initialBlock',
        '  emitNat "toRollup.initialChain" (Zkp.Implementation.ValidityChain.ValidityPIs.toRollup probeVPIs).initialChain',
        '  emitNat "toRollup.initialRoot" (Zkp.Implementation.ValidityChain.ValidityPIs.toRollup probeVPIs).initialRoot',
        '  emitNat "toRollup.finalBlock" (Zkp.Implementation.ValidityChain.ValidityPIs.toRollup probeVPIs).finalBlock',
        '  emitNat "toRollup.finalChain" (Zkp.Implementation.ValidityChain.ValidityPIs.toRollup probeVPIs).finalChain',
        '  emitNat "toRollup.finalRoot" (Zkp.Implementation.ValidityChain.ValidityPIs.toRollup probeVPIs).finalRoot',
        '  emitNat "toRollup.prover" (Zkp.Implementation.ValidityChain.ValidityPIs.toRollup probeVPIs).prover',
    ]
    if registered_pi is not None:
        lines.append(
            '  emitBool "solidity.limbsMatchBytes32(pi,0,keccak)"'
            f' (Zkp.Implementation.RollupValue.limbsMatchBytes32 probeWords 0 {digest})')
    lines.append("")
    probe = "\n".join(lines)

    case = Case(
        name=name,
        module="Zkp.Implementation.ValidityChain",
        decoder="ValidityChain.ValidityPIs.u32Words / .preimage / .toRollup",
        words_source=pi_source,
        companion="the same fixture's vpis record",
        probe=probe,
    )
    case.expected.update({
        "input.length": str(len(registered_pi or [])),
        "u32Words": norm_words(words),
        "preimage": norm_words(preimage),
        "toRollup.initialBlock": str(ib),
        "toRollup.initialChain": str(int(vpis["initial_block_chain"], 16)),
        "toRollup.initialRoot": str(int(vpis["initial_ext_commitment"], 16)),
        "toRollup.finalBlock": str(fb),
        "toRollup.finalChain": str(int(vpis["final_block_chain"], 16)),
        "toRollup.finalRoot": str(int(vpis["final_ext_commitment"], 16)),
        "toRollup.prover": str(int(vpis["prover"], 16)),
    })
    if registered_pi is not None:
        if be_limbs(digest) != registered_pi:
            # Reported as a FAIL through the normal channel rather than raising.
            case.expected["solidity.limbsMatchBytes32(pi,0,keccak)"] = "true"
            case.notes.append(
                "WARNING: keccak(Lean preimage) does not equal the registered public inputs")
        else:
            case.expected["solidity.limbsMatchBytes32(pi,0,keccak)"] = "true"
        case.notes.append(
            "the registered 8 public-input limbs are keccak256 of the Lean-model preimage")
    else:
        case.notes.append(
            "no proof fixture registers this vpis record; only the preimage layout and the "
            "toRollup recomposition are compared")
    return case


def build_cases(data_dir: Path) -> List[Case]:
    data_dir = Path(data_dir)
    cases: List[Case] = []
    cases.append(build_close_case(data_dir, "close_intent_mle.json", "close_intent.json",
                                  "close_intent"))
    if (data_dir / "pw_close_intent_mle.json").exists():
        cases.append(build_close_case(data_dir, "pw_close_intent_mle.json", None,
                                      "pw_close_intent"))
    cases.append(build_cancel_close_case(data_dir))
    cases.append(build_withdrawal_claim_case(data_dir))
    cases.append(build_post_close_claim_case(data_dir))
    cases.append(build_close_asset_backing_case(data_dir))
    for prefix in ("close_", "c2c_", "burn_", "", "sepolia_"):
        if (data_dir / f"{prefix}withdrawal_mle.json").exists() and \
           (data_dir / f"{prefix}withdrawal_payout.json").exists():
            cases.append(build_withdrawal_chain_case(data_dir, prefix))
    for prefix in ("close_", "c2c_", "burn_", "", "sepolia_"):
        lifecycle = f"{prefix}lifecycle.json"
        mle = f"{prefix}lifecycle_validity_mle.json"
        if (data_dir / lifecycle).exists() and (data_dir / mle).exists():
            cases.append(build_validity_case(
                data_dir, f"validity[{prefix or 'plain'}]",
                _load(data_dir, lifecycle)["vpis"],
                _pi_words(data_dir, mle),
                f"{mle} -> proof.publicInputs (8 words)"))
    if (data_dir / "e2e_fixture.json").exists():
        e2e = _load(data_dir, "e2e_fixture.json")
        cases.append(build_validity_case(
            data_dir, "validity[e2e_fixture]", e2e["validity_public_inputs"],
            be_limbs(int(e2e["pi_hash"], 16)),
            "e2e_fixture.json -> pi_hash (8 big-endian u32 limbs)"))
    if (data_dir / "vpi_fixture.json").exists():
        cases.append(build_validity_case(
            data_dir, "validity[vpi_fixture]", _load(data_dir, "vpi_fixture.json"),
            None, "vpi_fixture.json (no companion proof)"))
    return cases


# --------------------------------------------------------------------------
# Reporting
# --------------------------------------------------------------------------

def format_report(results: List[CaseResult], elapsed: float) -> str:
    out: List[str] = []
    out.append("Lean <-> prover fixture parity (fixture-level agreement evidence, NOT a proof)")
    out.append("=" * 78)
    total_pass = total_fail = total_nc = 0
    for result in results:
        case = result.case
        out.append("")
        out.append(f"[{case.name}]")
        out.append(f"  module    : {case.module}")
        out.append(f"  decoder   : {case.decoder}")
        out.append(f"  words     : {case.words_source}")
        out.append(f"  companion : {case.companion}")
        if result.error:
            out.append(f"  ERROR     : {result.error}")
            continue
        for fr in result.fields:
            if fr.status == PASS:
                total_pass += 1
                out.append(f"    PASS            {fr.field} = {_ellipsis(fr.lean)}")
            elif fr.status == FAIL:
                total_fail += 1
                out.append(f"    FAIL            {fr.field}")
                out.append(f"        lean     : {_ellipsis(fr.lean)}")
                out.append(f"        fixture  : {_ellipsis(fr.expected)}")
                out.append(f"        detail   : {fr.detail}")
            else:
                total_nc += 1
                out.append(f"    not-comparable  {fr.field} ({fr.detail})")
        for note in case.notes:
            out.append(f"    note: {note}")
    out.append("")
    out.append("-" * 78)
    failed_cases = [r.case.name for r in results if not r.ok]
    out.append(f"cases: {len(results)}   fields PASS: {total_pass}   "
               f"FAIL: {total_fail}   not-comparable: {total_nc}")
    out.append(f"runtime: {elapsed:.1f}s")
    if failed_cases:
        out.append("FAILED cases: " + ", ".join(failed_cases))
    else:
        out.append("all fixtures decoded and every comparable field agreed")
    return "\n".join(out)


def _ellipsis(text: Optional[str], limit: int = 110) -> str:
    if text is None:
        return "(absent)"
    return text if len(text) <= limit else text[:limit] + f"... ({len(text)} chars)"


def results_to_json(results: List[CaseResult], elapsed: float) -> dict:
    return {
        "kind": "fixture-level agreement evidence (not a refinement proof)",
        "runtimeSeconds": round(elapsed, 3),
        "cases": [
            {
                "name": r.case.name,
                "module": r.case.module,
                "decoder": r.case.decoder,
                "words": r.case.words_source,
                "companion": r.case.companion,
                "ok": r.ok,
                "error": r.error,
                "notes": r.case.notes,
                "fields": [
                    {"field": f.field, "status": f.status, "lean": f.lean,
                     "fixture": f.expected, "detail": f.detail}
                    for f in r.fields
                ],
            }
            for r in results
        ],
    }


# --------------------------------------------------------------------------

def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--data-dir", default=str(DATA_DIR))
    parser.add_argument("--lean-dir", default=str(LEAN_DIR))
    parser.add_argument("--case", action="append", default=None,
                        help="only run cases whose name contains this substring")
    parser.add_argument("--json", dest="json_out", default=None,
                        help="write the machine-readable report here")
    parser.add_argument("--dump-probes", default=None,
                        help="also write every generated probe into this directory")
    parser.add_argument("--elan-bin", default=None,
                        help="directory prepended to PATH so `lake` is found "
                             "(default: $LEAN_PARITY_ELAN_BIN or ~/.elan/bin)")
    args = parser.parse_args(argv)

    started = time.time()
    try:
        cases = build_cases(Path(args.data_dir))
    except (FileNotFoundError, KeyError, ValueError) as exc:
        print(f"fixture survey failed: {exc}", file=sys.stderr)
        return 2
    if args.case:
        cases = [c for c in cases if any(sub in c.name for sub in args.case)]
    if not cases:
        print("no cases selected", file=sys.stderr)
        return 2

    if args.dump_probes:
        dump = Path(args.dump_probes)
        dump.mkdir(parents=True, exist_ok=True)
        for case in cases:
            safe = case.name.replace("[", "_").replace("]", "").replace("/", "_")
            (dump / f"{safe}.lean").write_text(case.probe, encoding="utf-8")

    runner = LeanRunner(Path(args.lean_dir), elan_bin=args.elan_bin)
    if not runner.available():
        print("`lake` is not on PATH; cannot run the Lean probes", file=sys.stderr)
        return 2

    results: List[CaseResult] = []
    for case in cases:
        safe = case.name.replace("[", "_").replace("]", "").replace("/", "_")
        probe = runner.run(case.probe, f"probe_{safe}")
        results.append(evaluate(case, probe))

    elapsed = time.time() - started
    print(format_report(results, elapsed))
    if args.json_out:
        Path(args.json_out).write_text(
            json.dumps(results_to_json(results, elapsed), indent=2), encoding="utf-8")
    return 0 if all(r.ok for r in results) else 1


if __name__ == "__main__":
    raise SystemExit(main())

//! Sign and broadcast L1 transactions without putting large data on a command line.
//!
//! Linux refuses to start a process when any single argument is longer than 131,071 bytes
//! (`MAX_ARG_STRLEN`), failing with E2BIG ("Argument list too long", os error 7). macOS has no
//! per-argument limit, which is why local rehearsals did not show it. Two kinds of L1 data exceed
//! the limit:
//!
//! - A validity post carries its proof in blobs: two blobs make a raw transaction of about 526,000
//!   hex characters (about 550,000 in the EIP-7594 form sent after Osaka, see
//!   [`send_raw_transaction`]), so `cast publish <raw>` failed on every post from the Linux host.
//! - A withdrawal payout, a close attestation, a close-funding payout and a late-deposit claim
//!   carry a proof in calldata: about 260,000 hex characters (a measured payout: 261,130), so `cast
//!   send <to> <calldata>`, `cast mktx <to> <calldata>` and `cast keccak <calldata>` fail.
//!
//! Nothing here passes calldata or a raw transaction as an argument:
//!
//! - JSON-RPC calls go through `cast rpc --raw <method>`, which reads its params from stdin when
//!   none are given on the command line.
//! - [`sign_call`] builds the EIP-1559 transaction here and has `cast wallet sign --no-hash` sign
//!   only its 32-byte digest, so key material stays inside Foundry (a keystore account or the
//!   public Anvil key) exactly as with `cast mktx`. The signed bytes are then decoded by `cast
//!   decode-transaction` (on stdin) and must name the expected signer, target, value, calldata,
//!   nonce, chain and hash before they are returned.
//! - Hashes are computed here.

use std::{
    io::Write,
    process::{Command, Stdio},
};

use serde_json::{Value, json};

/// Send `eth_sendRawTransaction` for `raw_transaction` with the transaction on stdin, and return
/// the transaction hash the RPC answered.
///
/// A blob transaction in the EIP-4844 form (one proof per blob, as `cast mktx --blob` builds it)
/// is sent in the EIP-7594 form instead (128 cell proofs per blob), which is the only form a node
/// takes after Osaka. A node that cannot decode that form (Anvil 1.5.1) is then sent the original
/// bytes. Both forms carry the same signed transaction, so the hash is the same.
///
/// The caller compares that hash with the one it signed, and on an error checks whether the RPC
/// already knows the signed hash (a node may accept the transaction and then fail to answer).
pub fn send_raw_transaction(rpc: &str, raw_transaction: &str) -> Result<String, String> {
    let raw_transaction = raw_transaction.trim();
    if raw_transaction.starts_with("0x03") {
        let raw = decode_hex(raw_transaction)?;
        if crate::blob_sidecar::sidecar_version(&raw)? == crate::blob_sidecar::SidecarVersion::V0 {
            let v1 = crate::blob_sidecar::to_v1(&raw, crate::blob_sidecar::settings())?;
            match send_one_raw_transaction(rpc, &format!("0x{}", hex::encode(v1))) {
                Ok(hash) => {
                    eprintln!(
                        "blob transaction {hash} sent with the EIP-7594 (cell proof) sidecar"
                    );
                    return Ok(hash);
                }
                Err(v1_error) if v1_error.to_ascii_lowercase().contains("decode") => {
                    return send_one_raw_transaction(rpc, raw_transaction)
                        .inspect(|hash| {
                            eprintln!(
                                "blob transaction {hash} sent with the EIP-4844 sidecar: the \
                                 node could not decode the EIP-7594 form ({v1_error})"
                            )
                        })
                        .map_err(|v0_error| {
                            format!("EIP-7594 form: {v1_error}; EIP-4844 form: {v0_error}")
                        });
                }
                Err(v1_error) => return Err(v1_error),
            }
        }
    }
    send_one_raw_transaction(rpc, raw_transaction)
}

fn send_one_raw_transaction(rpc: &str, raw_transaction: &str) -> Result<String, String> {
    let answer = rpc_call(rpc, "eth_sendRawTransaction", &json!([raw_transaction]))?;
    answer
        .as_str()
        .map(str::to_owned)
        .ok_or_else(|| format!("eth_sendRawTransaction answered {answer}, not a transaction hash"))
}

/// Call JSON-RPC `method` with `params` written to `cast rpc --raw`'s stdin, and return the
/// result. An RPC error (including a revert) is an `Err` carrying cast's stderr.
pub fn rpc_call(rpc: &str, method: &str, params: &Value) -> Result<Value, String> {
    let params =
        serde_json::to_vec(params).map_err(|error| format!("encode {method} params: {error}"))?;
    let mut child = Command::new("cast")
        .args(["rpc", "--raw", method, "--rpc-url", rpc])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|error| format!("start cast rpc {method}: {error}"))?;
    // cast reads all of stdin before it sends anything, so writing the whole request before
    // collecting the output cannot deadlock. If cast exits early, the write fails with a broken
    // pipe; its stderr then says why, so report that first.
    let written = child
        .stdin
        .take()
        .ok_or_else(|| "cast rpc has no stdin".to_string())
        .and_then(|mut stdin| {
            stdin
                .write_all(&params)
                .map_err(|error| format!("write {method} params to cast rpc: {error}"))
        });
    let output = child
        .wait_with_output()
        .map_err(|error| format!("wait for cast rpc {method}: {error}"))?;
    if !output.status.success() {
        return Err(format!(
            "{method} failed: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        ));
    }
    written?;
    serde_json::from_slice(&output.stdout).map_err(|error| {
        format!(
            "{method} answered {:?}, not JSON: {error}",
            String::from_utf8_lossy(&output.stdout).trim()
        )
    })
}

/// Keccak-256 of `bytes`.
pub fn keccak256(bytes: &[u8]) -> [u8; 32] {
    keccak_hash::keccak(bytes).0
}

/// Keccak-256 of the bytes that `hex` (with or without `0x`) encodes, as `0x` + 64 hex digits.
pub fn keccak256_hex(hex: &str) -> Result<String, String> {
    Ok(format!("0x{}", hex::encode(keccak256(&decode_hex(hex)?))))
}

/// The bytes that `hex` (with or without `0x`) encodes.
pub fn decode_hex(hex: &str) -> Result<Vec<u8>, String> {
    let digits = hex.trim();
    let digits = digits.strip_prefix("0x").unwrap_or(digits);
    hex::decode(digits).map_err(|error| format!("not hex data: {error}"))
}

/// An EIP-1559 contract call to sign.
pub struct CallTransaction<'a> {
    pub chain_id: u64,
    /// The signer's address; the signed transaction must recover to it.
    pub from: &'a str,
    pub to: &'a str,
    pub value: u128,
    pub data: &'a [u8],
    /// `None` uses the sender's nonce at the latest block.
    pub nonce: Option<u64>,
}

/// A signed transaction, ready for [`send_raw_transaction`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SignedCall {
    /// `0x` + the EIP-2718 bytes.
    pub raw: String,
    /// `0x` + keccak-256 of those bytes.
    pub hash: String,
    pub nonce: u64,
    pub gas_limit: u64,
}

/// The fee fields of an EIP-1559 transaction.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Fees {
    pub max_priority_fee_per_gas: u128,
    pub max_fee_per_gas: u128,
}

/// Sign `call` as `cast mktx <to> <data>` would, without putting the data on a command line.
///
/// The gas limit is the RPC's `eth_estimateGas`, and the fees follow the estimator `cast` uses
/// (alloy's default): the priority fee is the median of the non-zero 20th-percentile rewards of
/// the last 10 blocks (at least 1 wei), and the fee cap is twice the next block's base fee plus
/// that priority fee. `append_wallet` adds the Foundry wallet flags (`--account <name>` or the
/// public Anvil key); `cast wallet sign --no-hash` then signs the 32-byte digest.
pub fn sign_call(
    rpc: &str,
    call: &CallTransaction<'_>,
    append_wallet: &dyn Fn(&mut Command),
) -> Result<SignedCall, String> {
    let from = normalize_address(call.from, "sender")?;
    let to = normalize_address(call.to, "target")?;
    let nonce = match call.nonce {
        Some(nonce) => nonce,
        None => quantity(
            &rpc_call(rpc, "eth_getTransactionCount", &json!([from, "latest"]))?,
            "sender nonce",
        )?
        .try_into()
        .map_err(|_| "sender nonce exceeds u64".to_string())?,
    };
    let data_hex = format!("0x{}", hex::encode(call.data));
    let value_hex = format!("0x{:x}", call.value);
    let gas_limit: u64 = quantity(
        &rpc_call(
            rpc,
            "eth_estimateGas",
            &json!([{
                "from": from,
                "to": to,
                "value": value_hex,
                "data": data_hex,
                "input": data_hex,
            }]),
        )?,
        "gas estimate",
    )?
    .try_into()
    .map_err(|_| "gas estimate exceeds u64".to_string())?;
    let fees = estimate_fees(&rpc_call(
        rpc,
        "eth_feeHistory",
        &json!(["0xa", "latest", [20.0]]),
    )?)?;
    let to_bytes: [u8; 20] = decode_hex(&to)?
        .try_into()
        .map_err(|_| "target is not 20 bytes".to_string())?;
    let fields = Eip1559Fields {
        chain_id: call.chain_id,
        nonce,
        fees,
        gas_limit,
        to: to_bytes,
        value: call.value,
        data: call.data,
    };
    let digest = keccak256(&fields.unsigned());
    let mut command = Command::new("cast");
    command.args([
        "wallet",
        "sign",
        "--no-hash",
        &format!("0x{}", hex::encode(digest)),
    ]);
    append_wallet(&mut command);
    let output = command
        .stdin(Stdio::null())
        .output()
        .map_err(|error| format!("start cast wallet sign: {error}"))?;
    if !output.status.success() {
        return Err(format!(
            "cast wallet sign failed: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        ));
    }
    let signature = decode_hex(String::from_utf8_lossy(&output.stdout).trim())?;
    let signature: [u8; 65] = signature
        .try_into()
        .map_err(|_| "cast wallet sign did not print a 65-byte signature".to_string())?;
    let raw_bytes = fields.signed(&signature)?;
    let signed = SignedCall {
        raw: format!("0x{}", hex::encode(&raw_bytes)),
        hash: format!("0x{}", hex::encode(keccak256(&raw_bytes))),
        nonce,
        gas_limit,
    };
    check_signed_call(&signed, &fields, &from, &to, &data_hex)?;
    Ok(signed)
}

/// Decode `signed` with `cast decode-transaction` (on stdin) and require every field to be the
/// one asked for, the recovered signer to be `from`, and cast's hash to be ours.
fn check_signed_call(
    signed: &SignedCall,
    fields: &Eip1559Fields<'_>,
    from: &str,
    to: &str,
    data_hex: &str,
) -> Result<(), String> {
    let mut child = Command::new("cast")
        .args(["decode-transaction", "--json"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|error| format!("start cast decode-transaction: {error}"))?;
    let written = child
        .stdin
        .take()
        .ok_or_else(|| "cast decode-transaction has no stdin".to_string())
        .and_then(|mut stdin| {
            stdin
                .write_all(signed.raw.as_bytes())
                .map_err(|error| format!("write the signed transaction to cast: {error}"))
        });
    let output = child
        .wait_with_output()
        .map_err(|error| format!("wait for cast decode-transaction: {error}"))?;
    if !output.status.success() {
        return Err(format!(
            "cast decode-transaction refused the signed transaction: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        ));
    }
    written?;
    let decoded: Value = serde_json::from_slice(&output.stdout)
        .map_err(|error| format!("parse cast decode-transaction output: {error}"))?;
    let text = |name: &str| -> Result<&str, String> {
        decoded
            .get(name)
            .and_then(Value::as_str)
            .ok_or_else(|| format!("decoded transaction has no {name}"))
    };
    let number = |name: &str| -> Result<u128, String> { quantity(&json!(text(name)?), name) };
    let same = |left: &str, right: &str| left.eq_ignore_ascii_case(right);
    let checks = [
        (number("type")? == 2, "type"),
        (number("chainId")? == u128::from(fields.chain_id), "chainId"),
        (number("nonce")? == u128::from(fields.nonce), "nonce"),
        (number("gas")? == u128::from(fields.gas_limit), "gas"),
        (
            number("maxFeePerGas")? == fields.fees.max_fee_per_gas,
            "maxFeePerGas",
        ),
        (
            number("maxPriorityFeePerGas")? == fields.fees.max_priority_fee_per_gas,
            "maxPriorityFeePerGas",
        ),
        (number("value")? == fields.value, "value"),
        (same(text("to")?, to), "to"),
        (same(text("input")?, data_hex), "input"),
        (same(text("signer")?, from), "signer"),
        (same(text("hash")?, &signed.hash), "hash"),
    ];
    match checks.iter().find(|(ok, _)| !ok) {
        Some((_, field)) => Err(format!(
            "the signed transaction decodes with another {field} than was signed"
        )),
        None => Ok(()),
    }
}

/// cast's (alloy's default) EIP-1559 fee estimate from an `eth_feeHistory(10, latest, [20])`
/// answer.
pub fn estimate_fees(history: &Value) -> Result<Fees, String> {
    let base_fees = history
        .get("baseFeePerGas")
        .and_then(Value::as_array)
        .ok_or_else(|| "eth_feeHistory has no baseFeePerGas".to_string())?;
    // The last entry is the base fee of the block after the newest one.
    let next_base_fee = quantity(
        base_fees
            .last()
            .ok_or_else(|| "eth_feeHistory has an empty baseFeePerGas".to_string())?,
        "next base fee",
    )?;
    let mut rewards = Vec::new();
    if let Some(blocks) = history.get("reward").and_then(Value::as_array) {
        for block in blocks {
            if let Some(first) = block.as_array().and_then(|r| r.first()) {
                let reward = quantity(first, "priority fee reward")?;
                if reward > 0 {
                    rewards.push(reward);
                }
            }
        }
    }
    rewards.sort_unstable();
    let max_priority_fee_per_gas = match rewards.len() {
        0 => 1,
        n if n % 2 == 0 => (rewards[n / 2 - 1] + rewards[n / 2]) / 2,
        n => rewards[n / 2],
    }
    .max(1);
    let max_fee_per_gas = next_base_fee
        .checked_mul(2)
        .and_then(|fee| fee.checked_add(max_priority_fee_per_gas))
        .ok_or_else(|| "fee cap overflows".to_string())?;
    Ok(Fees {
        max_priority_fee_per_gas,
        max_fee_per_gas,
    })
}

/// A JSON-RPC quantity (`"0x…"`, or a JSON number) as an integer.
fn quantity(value: &Value, what: &str) -> Result<u128, String> {
    if let Some(number) = value.as_u64() {
        return Ok(u128::from(number));
    }
    let text = value
        .as_str()
        .ok_or_else(|| format!("{what} is not a quantity: {value}"))?;
    let digits = text
        .strip_prefix("0x")
        .ok_or_else(|| format!("{what} is not a hex quantity: {text}"))?;
    if digits.is_empty() {
        return Err(format!("{what} is an empty quantity"));
    }
    u128::from_str_radix(digits, 16).map_err(|error| format!("{what} {text}: {error}"))
}

fn normalize_address(address: &str, what: &str) -> Result<String, String> {
    let address = address.trim();
    let digits = address
        .strip_prefix("0x")
        .filter(|digits| digits.len() == 40 && digits.bytes().all(|b| b.is_ascii_hexdigit()))
        .ok_or_else(|| format!("{what} {address:?} is not a 20-byte hex address"))?;
    Ok(format!("0x{}", digits.to_ascii_lowercase()))
}

/// The fields of an EIP-1559 (type 2) transaction with an empty access list.
struct Eip1559Fields<'a> {
    chain_id: u64,
    nonce: u64,
    fees: Fees,
    gas_limit: u64,
    to: [u8; 20],
    value: u128,
    data: &'a [u8],
}

impl Eip1559Fields<'_> {
    fn payload_items(&self) -> Vec<Vec<u8>> {
        vec![
            rlp_uint(u128::from(self.chain_id)),
            rlp_uint(u128::from(self.nonce)),
            rlp_uint(self.fees.max_priority_fee_per_gas),
            rlp_uint(self.fees.max_fee_per_gas),
            rlp_uint(u128::from(self.gas_limit)),
            rlp_bytes(&self.to),
            rlp_uint(self.value),
            rlp_bytes(self.data),
            rlp_list(&[]),
        ]
    }

    /// `0x02 || rlp([chainId, nonce, maxPriorityFeePerGas, maxFeePerGas, gas, to, value, data,
    /// accessList])`, whose keccak-256 is the signing digest.
    fn unsigned(&self) -> Vec<u8> {
        let mut out = vec![2];
        out.extend(rlp_list(&self.payload_items()));
        out
    }

    /// The signed transaction for a 65-byte `r || s || v` signature (v is 27/28 or 0/1).
    fn signed(&self, signature: &[u8; 65]) -> Result<Vec<u8>, String> {
        let y_parity = match signature[64] {
            0 | 27 => 0u128,
            1 | 28 => 1u128,
            v => return Err(format!("signature has recovery id {v}")),
        };
        let mut items = self.payload_items();
        items.push(rlp_uint(y_parity));
        items.push(rlp_bytes(strip_leading_zeros(&signature[..32])));
        items.push(rlp_bytes(strip_leading_zeros(&signature[32..64])));
        let mut out = vec![2];
        out.extend(rlp_list(&items));
        Ok(out)
    }
}

fn strip_leading_zeros(bytes: &[u8]) -> &[u8] {
    let start = bytes.iter().position(|&b| b != 0).unwrap_or(bytes.len());
    &bytes[start..]
}

fn rlp_length_prefix(length: usize, short_base: u8, long_base: u8) -> Vec<u8> {
    if length <= 55 {
        vec![short_base + length as u8]
    } else {
        let length_bytes = strip_leading_zeros(&(length as u64).to_be_bytes()).to_vec();
        let mut out = vec![long_base + length_bytes.len() as u8];
        out.extend(length_bytes);
        out
    }
}

fn rlp_bytes(bytes: &[u8]) -> Vec<u8> {
    if bytes.len() == 1 && bytes[0] < 0x80 {
        return bytes.to_vec();
    }
    let mut out = rlp_length_prefix(bytes.len(), 0x80, 0xb7);
    out.extend_from_slice(bytes);
    out
}

fn rlp_uint(value: u128) -> Vec<u8> {
    rlp_bytes(strip_leading_zeros(&value.to_be_bytes()))
}

fn rlp_list(items: &[Vec<u8>]) -> Vec<u8> {
    let length = items.iter().map(Vec::len).sum();
    let mut out = rlp_length_prefix(length, 0xc0, 0xf7);
    for item in items {
        out.extend_from_slice(item);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn signature(r: &str, s: &str, v: u8) -> [u8; 65] {
        let mut out = [0u8; 65];
        out[..32].copy_from_slice(&decode_hex(r).unwrap());
        out[32..64].copy_from_slice(&decode_hex(s).unwrap());
        out[64] = v;
        out
    }

    /// `cast mktx 0x1111…1111 0xdeadbeef --nonce 7 --gas-limit 100000 --priority-gas-price
    /// 1000000000 --gas-price 3000000000 --chain 31338 --value 5 --private-key <Anvil key 0>`
    /// (cast 1.5.1), rebuilt byte for byte from its fields and its signature.
    #[test]
    fn short_call_matches_cast_mktx() {
        let fields = Eip1559Fields {
            chain_id: 31338,
            nonce: 7,
            fees: Fees {
                max_priority_fee_per_gas: 1_000_000_000,
                max_fee_per_gas: 3_000_000_000,
            },
            gas_limit: 100_000,
            to: [0x11; 20],
            value: 5,
            data: &[0xde, 0xad, 0xbe, 0xef],
        };
        let raw = fields
            .signed(&signature(
                "0x86a4afbd6b54fdd000f490dbfb1ab1b78b760d76e1f9ac51eae267a43d5ce92b",
                "0x29f314a6813ac23c601f62b63de67534f1eb55d6e19e62defd0756688e8a6f78",
                1,
            ))
            .unwrap();
        assert_eq!(
            format!("0x{}", hex::encode(raw)),
            "0x02f871827a6a07843b9aca0084b2d05e00830186a09411111111111111111111111111111111111111\
             110584deadbeefc001a086a4afbd6b54fdd000f490dbfb1ab1b78b760d76e1f9ac51eae267a43d5ce92b\
             a029f314a6813ac23c601f62b63de67534f1eb55d6e19e62defd0756688e8a6f78"
        );
    }

    /// 70,000 bytes of calldata (140,000 hex characters, over Linux's per-argument limit), the
    /// size class of a proof payout: `cast mktx 0x2222…2222 <data> --nonce 300 --gas-limit
    /// 16777216 --priority-gas-price 1500000000 --gas-price 40000000000 --chain 11155111
    /// --private-key <Anvil key 0>` (cast 1.5.1, on macOS) gave this hash, r, s and yParity.
    #[test]
    fn long_call_matches_cast_mktx() {
        let data: Vec<u8> = (0..70_000u32).map(|i| (i % 251) as u8).collect();
        let fields = Eip1559Fields {
            chain_id: 11_155_111,
            nonce: 300,
            fees: Fees {
                max_priority_fee_per_gas: 1_500_000_000,
                max_fee_per_gas: 40_000_000_000,
            },
            gas_limit: 16_777_216,
            to: [0x22; 20],
            value: 0,
            data: &data,
        };
        let raw = fields
            .signed(&signature(
                "0x14ad40ffdfebc6535c77c709b1e2a6bff0636ed5b742750640ed1d616682648c",
                "0x6ecf94b06a2bbf217ec05aabd780a3916f9a71c64b335ac8655ac2cdf6d53b3f",
                28,
            ))
            .unwrap();
        assert_eq!(raw.len() * 2 + 2, 140_246);
        assert_eq!(
            format!("0x{}", hex::encode(keccak256(&raw))),
            "0x9d05629e62a670a3175b8d5259c1a31ac79dea5d02d2d70f01a82ab3c751356b"
        );
    }

    #[test]
    fn fee_estimate_follows_the_cast_default() {
        let history = json!({
            "baseFeePerGas": ["0x1", "0x2", "0x64"],
            "reward": [["0x0"], ["0x5"], ["0x9"], ["0x3"], ["0x7"]],
        });
        // Non-zero rewards 3, 5, 7, 9: the median is (5 + 7) / 2.
        assert_eq!(
            estimate_fees(&history).unwrap(),
            Fees {
                max_priority_fee_per_gas: 6,
                max_fee_per_gas: 2 * 100 + 6,
            }
        );
        let quiet = json!({ "baseFeePerGas": ["0x7"], "reward": [["0x0"]] });
        assert_eq!(
            estimate_fees(&quiet).unwrap(),
            Fees {
                max_priority_fee_per_gas: 1,
                max_fee_per_gas: 15,
            }
        );
    }

    #[test]
    fn keccak_of_hex_matches_cast_keccak() {
        // `cast keccak 0xdeadbeef`
        assert_eq!(
            keccak256_hex("0xdeadbeef").unwrap(),
            "0xd4fd4e189132273036449fc9e11198c739161b4c0116a9a2dccdfa1c492006f1"
        );
    }
}

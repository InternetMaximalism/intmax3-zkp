//! Private, durable capacity admission before the API releases an L1 deposit transaction.
//! The parent CLI holds its process lock throughout these commands. Nothing here signs a
//! transaction/state or substitutes for finality, deposit ownership, or import verification.

use super::*;

const MAX_PENDING_RESERVATIONS: usize = 128;

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct CapacityResult {
    schema_version: u32,
    channel_id: u64,
    state_digest: String,
    recipient_slots: Vec<u16>,
    token_index: u32,
    amount: String,
    completed: bool,
}

fn decimal(value: &str, label: &str, maximum: u64) -> Result<u64, String> {
    if value.is_empty()
        || !value.bytes().all(|byte| byte.is_ascii_digit())
        || (value.len() > 1 && value.starts_with('0'))
    {
        return Err(format!(
            "{label} must be a canonical unsigned decimal integer"
        ));
    }
    let parsed = value
        .parse::<u64>()
        .map_err(|_| format!("{label} is out of range"))?;
    if parsed > maximum {
        return Err(format!("{label} is out of range"));
    }
    Ok(parsed)
}

fn token_and_amount(token: &str, amount: &str) -> Result<(u32, u64), String> {
    let token = decimal(token, "tokenIndex", u32::MAX as u64)? as u32;
    let amount = decimal(amount, "amount", u64::MAX)?;
    if amount == 0 {
        return Err("amount must be positive".into());
    }
    Ok((token, amount))
}

fn reservation_id(value: &str) -> Result<String, String> {
    let digest = value
        .strip_prefix("deposit:")
        .ok_or_else(|| "reservation id must be deposit:<64 hex digits>".to_string())?;
    if digest.len() != 64 || !digest.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err("reservation id must be deposit:<64 hex digits>".into());
    }
    Ok(format!("deposit:{}", digest.to_ascii_lowercase()))
}

fn transaction_hash(value: &str) -> Result<Bytes32, String> {
    let digits = value
        .strip_prefix("0x")
        .or_else(|| value.strip_prefix("0X"))
        .unwrap_or(value);
    if digits.len() != 64 || !digits.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err("transaction hash must be exactly 32 bytes of hexadecimal".into());
    }
    let hash = Bytes32::from_hex(digits).map_err(|error| format!("transaction hash: {error}"))?;
    if hash == Bytes32::default() {
        return Err("transaction hash must be nonzero".into());
    }
    Ok(hash)
}

pub(super) fn split_reservation_option(
    args: &[String],
) -> Result<(Vec<String>, Option<String>), String> {
    let mut normalized = Vec::new();
    let mut id = None;
    let mut index = 0;
    while index < args.len() {
        let value = if args[index] == "--deposit-reservation" {
            index += 1;
            Some(
                args.get(index)
                    .ok_or("--deposit-reservation needs an id")?
                    .as_str(),
            )
        } else {
            args[index].strip_prefix("--deposit-reservation=")
        };
        if let Some(value) = value {
            if id.replace(reservation_id(value)?).is_some() {
                return Err("--deposit-reservation must name exactly one reservation".into());
            }
        } else {
            normalized.push(args[index].clone());
        }
        index += 1;
    }
    Ok((normalized, id))
}

fn tagged_recipient(value: &str) -> Result<Bytes32, String> {
    let recipient = transaction_hash(value)?;
    if recipient.to_bytes_be()[0] != 1 {
        return Err("reserved deposit recipient must have the channel-recipient tag".into());
    }
    Ok(recipient)
}

pub(super) fn reserved_recipient(
    cli: &CliState,
    id: &str,
    tx_hash: &str,
    legacy: Bytes32,
) -> Result<Bytes32, String> {
    let reservation = cli
        .deposit_capacity_reservations
        .get(id)
        .ok_or("deposit capacity reservation is missing")?;
    if reservation.tx_hash != Some(transaction_hash(tx_hash)?) {
        return Err(
            "deposit recipient lookup requires the reservation's exact bound transaction".into(),
        );
    }
    Ok(reservation.deposit_recipient.unwrap_or(legacy))
}

fn slots_csv(value: &str) -> Result<Vec<u16>, String> {
    let mut slots = value
        .split(',')
        .map(|slot| decimal(slot, "recipient slot", u16::MAX as u64).map(|slot| slot as u16))
        .collect::<Result<Vec<_>, _>>()?;
    if slots.len() > MAX_CHANNEL_MEMBERS {
        return Err("too many recipient slots".into());
    }
    slots.sort_unstable();
    if slots.windows(2).any(|pair| pair[0] == pair[1]) {
        return Err("recipient slots must not contain duplicates".into());
    }
    Ok(slots)
}

fn trusted_state() -> CliState {
    let cli = load_state();
    verify_snapshot(&cli.snapshot, None).unwrap_or_else(|error| {
        die(format!(
            "deposit capacity requires a verified signed head: {error}"
        ))
    });
    if cli.snapshot.record.channel_id.as_u64() != u64::from(channel_id_env()) {
        die("deposit capacity snapshot belongs to another configured channel");
    }
    if cli.snapshot.state.balance_state.member_count != cli.snapshot.record.member_count
        || cli.snapshot.state.balance_state.delegate_count != cli.snapshot.record.delegate_count
    {
        die("deposit capacity participant counts disagree with the trusted record");
    }
    cli
}

fn require_open(cli: &CliState) -> Result<(), String> {
    if cli.snapshot.record.status != intmax3_zkp::common::channel::ChannelStatus::Active
        || terminal_signing_reservation(&cli.state_signing_ledger)?.is_some()
    {
        return Err(
            "deposit capacity unavailable: channel is closing or closed; do not send a new deposit"
                .into(),
        );
    }
    Ok(())
}

/// A multi-candidate reservation must remain importable at EACH candidate. Reserving the
/// amount at every candidate is conservative; only the actual import will credit one of them.
fn pending_at(
    reservations: &BTreeMap<String, DepositCapacityReservation>,
    excluded: Option<&str>,
    slot: u16,
    token_index: u32,
) -> Result<(u64, u32), String> {
    let mut amount = 0u64;
    let mut count = 0u32;
    for (id, reservation) in reservations {
        if reservation.completed
            || Some(id.as_str()) == excluded
            || reservation.token_index != token_index
            || !reservation.recipient_slots.contains(&slot)
        {
            continue;
        }
        amount = amount.checked_add(reservation.amount)
            .ok_or_else(|| "recoverable deposit capacity error: pending amount exceeds this slot's u64 capacity".to_string())?;
        count = count
            .checked_add(1)
            .ok_or_else(|| "too many pending deposits".to_string())?;
    }
    Ok((amount, count))
}

fn check_pending_adds(current: u32, other_reserved: u32) -> Result<(), String> {
    let total = current
        .checked_add(other_reserved)
        .and_then(|value| value.checked_add(1));
    if total.is_none_or(|value| value > intmax3_zkp::regev::MAX_HOMO_ADDS_BEFORE_REFRESH) {
        return Err("recoverable deposit capacity error: recipient must refresh before another deposit is sent".into());
    }
    Ok(())
}

pub(super) fn check_candidates(
    cli: &CliState,
    token_index: u32,
    amount: u64,
    candidates: &[u16],
    excluded: Option<&str>,
    require_every: bool,
) -> Result<Vec<u16>, String> {
    require_open(cli)?;
    let head = &cli.snapshot.state;
    let active = usize::from(cli.snapshot.record.member_count)
        + usize::from(cli.snapshot.record.delegate_count);
    let token_slot = resolve_local_token_slot(&head.balance_state, token_index)
        .map_err(|error| format!("deposit token is not registered: {error}"))?;
    let bounds = credit_bounds_for(cli, head)?;
    let owned = owned_credit_plaintexts(cli, head)?;
    let mut accepted = Vec::new();
    for &slot in candidates {
        let check = || -> Result<(), String> {
            if usize::from(slot) >= active {
                return Err(format!("recipient slot {slot} is not active"));
            }
            let (reserved, count) = pending_at(
                &cli.deposit_capacity_reservations,
                excluded,
                slot,
                token_index,
            )?;
            let combined = reserved.checked_add(amount).ok_or_else(|| {
                "recoverable deposit capacity error: proposed and pending deposits exceed u64"
                    .to_string()
            })?;
            check_pending_adds(
                head.balance_state.pending_adds[usize::from(slot)][token_slot],
                count,
            )?;
            bounds
                .can_credit(
                    head,
                    usize::from(slot),
                    token_slot,
                    combined,
                    owned.get(&(usize::from(slot), token_slot)).copied(),
                )
                .map_err(|error| format!("recoverable deposit capacity error: {error}"))
        };
        match check() {
            Ok(()) => accepted.push(slot),
            Err(error) if require_every => return Err(error),
            Err(_) => {}
        }
    }
    if accepted.is_empty() {
        return Err("recoverable deposit capacity error: no eligible recipient; keep the current head, refresh or obtain recipient range evidence before sending funds".into());
    }
    Ok(accepted)
}

fn same_intent(
    reservation: &DepositCapacityReservation,
    token: u32,
    amount: u64,
    slots: &[u16],
) -> bool {
    reservation.token_index == token
        && reservation.amount == amount
        && reservation.recipient_slots == slots
}

fn includes_import_selection(
    reservation: &DepositCapacityReservation,
    token: u32,
    amount: u64,
    slots: &[u16],
) -> bool {
    reservation.token_index == token
        && reservation.amount == amount
        && !slots.is_empty()
        && slots
            .iter()
            .all(|slot| reservation.recipient_slots.contains(slot))
}

fn invalidate_future_admissions(bounds: &mut BTreeMap<String, ChannelCreditBounds>, head: Bytes32) {
    let head_digest = head.to_hex();
    bounds.retain(|digest, _| digest == &head_digest);
}

fn is_new_reservation(
    reservations: &BTreeMap<String, DepositCapacityReservation>,
    id: &str,
    token: u32,
    amount: u64,
    slots: &[u16],
) -> Result<bool, String> {
    if let Some(existing) = reservations.get(id) {
        if !same_intent(existing, token, amount, slots) {
            return Err("reservation id is already bound to a different deposit intent; use a new id for a new deposit".into());
        }
        return Ok(false);
    }
    if reservations
        .values()
        .filter(|reservation| !reservation.completed)
        .count()
        >= MAX_PENDING_RESERVATIONS
    {
        return Err("recoverable deposit capacity error: pending reservation limit reached; complete existing deposits before reserving another".into());
    }
    Ok(true)
}

fn result(
    cli: &CliState,
    slots: Vec<u16>,
    token: u32,
    amount: u64,
    completed: bool,
) -> CapacityResult {
    CapacityResult {
        schema_version: 1,
        channel_id: cli.snapshot.state.channel_id.as_u64(),
        state_digest: cli.snapshot.state.digest.to_hex(),
        recipient_slots: slots,
        token_index: token,
        amount: amount.to_string(),
        completed,
    }
}

pub(super) fn preflight(args: &[String]) {
    if args.len() != 5 && !(args.len() == 7 && args[5] == "--reservation") {
        die(
            "usage: preflight-l1-deposit <slot|auto> <tokenIndex> <amount> <out> [--reservation <id>]",
        );
    }
    let (token, amount) = token_and_amount(&args[2], &args[3]).unwrap_or_else(|error| die(error));
    let id = args
        .get(6)
        .map(|value| reservation_id(value).unwrap_or_else(|error| die(error)));
    let cli = trusted_state();
    let existing = id.as_ref().map(|id| {
        cli.deposit_capacity_reservations
            .get(id)
            .unwrap_or_else(|| {
                die("deposit capacity reservation is missing; do not send or replace a transaction")
            })
    });
    let candidates = if args[1] == "auto" {
        existing
            .map(|reservation| reservation.recipient_slots.clone())
            .unwrap_or_else(|| {
                (0..u16::from(cli.snapshot.record.member_count)
                    + cli.snapshot.record.delegate_count)
                    .collect()
            })
    } else {
        vec![
            decimal(&args[1], "recipient slot", u16::MAX as u64).unwrap_or_else(|error| die(error))
                as u16,
        ]
    };
    if let Some(reservation) = existing {
        // The two-stage /l1-send reserves several acceptable recipients; its later import
        // chooses ONE of those slots. Only reserve/re-reserve requires the whole exact vector.
        if !includes_import_selection(reservation, token, amount, &candidates) {
            die("preflight does not match the reserved deposit intent");
        }
    }
    let completed = existing.is_some_and(|reservation| reservation.completed);
    let slots = if completed {
        candidates
    } else {
        check_candidates(
            &cli,
            token,
            amount,
            &candidates,
            id.as_deref(),
            existing.is_some() || args[1] != "auto",
        )
        .unwrap_or_else(|error| die(error))
    };
    write_json(&args[4], &result(&cli, slots, token, amount, completed));
}

pub(super) fn reserve(args: &[String]) {
    if args.len() != 6 && args.len() != 7 {
        die(
            "usage: reserve-l1-deposit <id> <tokenIndex> <amount> <slotsCsv> <out> [--recipient=<trusted-live-recipient>]",
        );
    }
    let deposit_recipient = args.get(6).map(|value| {
        tagged_recipient(
            value
                .strip_prefix("--recipient=")
                .unwrap_or_else(|| die("expected --recipient=<trusted-live-recipient>")),
        )
        .unwrap_or_else(|error| die(error))
    });
    let id = reservation_id(&args[1]).unwrap_or_else(|error| die(error));
    let (token, amount) = token_and_amount(&args[2], &args[3]).unwrap_or_else(|error| die(error));
    let slots = slots_csv(&args[4]).unwrap_or_else(|error| die(error));
    let mut cli = trusted_state();
    if let Some(existing) = cli.deposit_capacity_reservations.get(&id) {
        if existing.deposit_recipient != deposit_recipient {
            die("reservation is already bound to a different live deposit recipient");
        }
    }
    let is_new = is_new_reservation(
        &cli.deposit_capacity_reservations,
        &id,
        token,
        amount,
        &slots,
    )
    .unwrap_or_else(|error| die(error));
    if is_new {
        check_candidates(&cli, token, amount, &slots, None, true)
            .unwrap_or_else(|error| die(error));
        // A prepared-exit-kit save may retain bounds for an unsigned future head. Adding a
        // reservation tightens admission even though the current head digest is unchanged:
        // invalidate those future approvals so a resumed proposal rechecks ALL reservations.
        invalidate_future_admissions(&mut cli.credit_safety_bounds, cli.snapshot.state.digest);
        cli.deposit_capacity_reservations.insert(
            id.clone(),
            DepositCapacityReservation {
                token_index: token,
                amount,
                recipient_slots: slots.clone(),
                deposit_recipient,
                tx_hash: None,
                completed: false,
            },
        );
        // The private reservation is fsynced BEFORE publishing success to the transaction caller.
        save_state(&cli);
    }
    let completed = cli.deposit_capacity_reservations[&id].completed;
    write_json(&args[5], &result(&cli, slots, token, amount, completed));
}

fn bind_hash(
    reservations: &mut BTreeMap<String, DepositCapacityReservation>,
    id: &str,
    hash: Bytes32,
) -> Result<bool, String> {
    if !reservations.contains_key(id) {
        return Err("deposit capacity reservation is missing".into());
    }
    if reservations
        .iter()
        .any(|(other, reservation)| other != id && reservation.tx_hash == Some(hash))
    {
        return Err("transaction hash already belongs to another deposit reservation".into());
    }
    let reservation = reservations.get_mut(id).expect("reservation checked above");
    match reservation.tx_hash {
        Some(previous) if previous == hash => Ok(false),
        Some(_) => Err("deposit reservation is bound to another transaction hash; replacing its intent is forbidden".into()),
        None if reservation.completed => Err("completed deposit reservation has no transaction hash".into()),
        None => { reservation.tx_hash = Some(hash); Ok(true) },
    }
}

pub(super) fn bind(args: &[String]) {
    if args.len() != 3 {
        die("usage: bind-l1-deposit-reservation <id> <txhash>");
    }
    let id = reservation_id(&args[1]).unwrap_or_else(|error| die(error));
    let hash = transaction_hash(&args[2]).unwrap_or_else(|error| die(error));
    let mut cli = trusted_state();
    if bind_hash(&mut cli.deposit_capacity_reservations, &id, hash)
        .unwrap_or_else(|error| die(error))
    {
        save_state(&cli);
    }
    let reservation = &cli.deposit_capacity_reservations[&id];
    let output = result(
        &cli,
        reservation.recipient_slots.clone(),
        reservation.token_index,
        reservation.amount,
        reservation.completed,
    );
    println!(
        "{}",
        serde_json::to_string(&output).unwrap_or_else(|error| die(error))
    );
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pending(amount: u64, slots: Vec<u16>) -> DepositCapacityReservation {
        DepositCapacityReservation {
            token_index: 55,
            amount,
            recipient_slots: slots,
            deposit_recipient: None,
            tx_hash: None,
            completed: false,
        }
    }

    #[test]
    fn decimal_inputs_have_explicit_integer_ranges() {
        assert_eq!(
            token_and_amount("4294967295", "18446744073709551615").unwrap(),
            (u32::MAX, u64::MAX)
        );
        for invalid in ["", " 1", "+1", "1.0", "1e3", "0x10", "-1", "01"] {
            assert!(token_and_amount("0", invalid).is_err());
        }
        assert!(token_and_amount("4294967296", "1").is_err());
        assert!(token_and_amount("0", "18446744073709551616").is_err());
        assert!(token_and_amount("0", "0").is_err());
    }

    #[test]
    fn two_stage_import_selects_one_reserved_candidate_without_reallocating() {
        let reservation = pending(7, vec![0, 1]);
        assert!(includes_import_selection(&reservation, 55, 7, &[1]));
        assert!(includes_import_selection(&reservation, 55, 7, &[0, 1]));
        assert!(!includes_import_selection(&reservation, 55, 8, &[1]));
        assert!(!includes_import_selection(&reservation, 55, 7, &[2]));
        assert!(!includes_import_selection(&reservation, 55, 7, &[]));
        assert!(!same_intent(&reservation, 55, 7, &[1]));
    }

    #[test]
    fn reservation_change_keeps_only_the_current_head_admission() {
        let head = Bytes32::from_u32_slice(&[1; 8]).unwrap();
        let future = Bytes32::from_u32_slice(&[2; 8]).unwrap();
        let bound = |digest| ChannelCreditBounds {
            schema_version: intmax3_zkp::channel_credit_safety::CREDIT_BOUNDS_SCHEMA_VERSION,
            channel_id: ChannelId::new(7).unwrap(),
            state_digest: digest,
            upper_bounds: Vec::new(),
        };
        let mut bounds = BTreeMap::from([
            (head.to_hex(), bound(head)),
            (future.to_hex(), bound(future)),
        ]);
        invalidate_future_admissions(&mut bounds, head);
        assert_eq!(bounds.len(), 1);
        assert_eq!(bounds[&head.to_hex()].state_digest, head);
    }

    #[test]
    fn reservation_options_leave_positional_arguments_unchanged() {
        let id = format!("deposit:{}", "ab".repeat(32));
        let base = vec![
            "inspect-l1-deposit".to_string(),
            "transaction".into(),
            "rpc".into(),
            "producer_deposit.json".into(),
        ];
        for flags in [
            vec!["--deposit-reservation".into(), id.clone()],
            vec![format!("--deposit-reservation={id}")],
        ] {
            let mut args = base.clone();
            args.extend(flags);
            let (positional, selected) = split_reservation_option(&args).unwrap();
            assert_eq!(positional, base);
            assert_eq!(selected, Some(id.clone()));
        }
    }

    #[test]
    fn reservation_and_hash_encodings_are_unambiguous() {
        assert_eq!(
            reservation_id(&format!("deposit:{}", "AB".repeat(32))).unwrap(),
            format!("deposit:{}", "ab".repeat(32))
        );
        assert!(reservation_id("deposit:1").is_err());
        assert!(reservation_id(&format!("other:{}", "ab".repeat(32))).is_err());
        assert!(transaction_hash("0x1").is_err());
        assert!(transaction_hash(&"00".repeat(32)).is_err());
        assert_eq!(
            transaction_hash(&format!("0x{}", "ab".repeat(32))).unwrap(),
            transaction_hash(&"ab".repeat(32)).unwrap()
        );
        assert_eq!(slots_csv("2,0,1").unwrap(), vec![0, 1, 2]);
        assert!(slots_csv("1,1").is_err());
        assert!(slots_csv("").is_err());
    }

    #[test]
    fn candidate_reservations_sum_only_the_matching_active_cell() {
        let mut reservations = BTreeMap::new();
        reservations.insert("a".into(), pending(7, vec![0, 1]));
        reservations.insert("b".into(), pending(11, vec![1]));
        let mut finished = pending(99, vec![1]);
        finished.completed = true;
        finished.tx_hash = Some(Bytes32::from_u32_slice(&[1; 8]).unwrap());
        reservations.insert("finished".into(), finished);
        assert_eq!(pending_at(&reservations, None, 1, 55).unwrap(), (18, 2));
        assert_eq!(
            pending_at(&reservations, Some("a"), 1, 55).unwrap(),
            (11, 1)
        );
        assert_eq!(pending_at(&reservations, None, 0, 55).unwrap(), (7, 1));
        assert_eq!(pending_at(&reservations, None, 1, 0).unwrap(), (0, 0));
        assert_eq!(pending_at(&reservations, None, 2, 55).unwrap(), (0, 0));
    }

    #[test]
    fn pending_adds_leave_room_for_every_reserved_import() {
        let maximum = intmax3_zkp::regev::MAX_HOMO_ADDS_BEFORE_REFRESH;
        assert!(check_pending_adds(maximum - 2, 1).is_ok());
        assert!(check_pending_adds(maximum - 1, 1).is_err());
        assert!(check_pending_adds(maximum, 0).is_err());
        assert!(check_pending_adds(u32::MAX, 1).is_err());
    }

    #[test]
    fn exact_intent_retries_do_not_allocate_again() {
        let mut reservations = BTreeMap::new();
        reservations.insert("a".into(), pending(7, vec![0, 1]));
        assert!(!is_new_reservation(&reservations, "a", 55, 7, &[0, 1]).unwrap());
        assert!(is_new_reservation(&reservations, "a", 55, 8, &[0, 1]).is_err());
        assert!(is_new_reservation(&reservations, "a", 55, 7, &[0]).is_err());
        assert!(is_new_reservation(&reservations, "b", 55, 7, &[0, 1]).unwrap());
        reservations.get_mut("a").unwrap().completed = true;
        assert!(!is_new_reservation(&reservations, "a", 55, 7, &[0, 1]).unwrap());
    }

    #[test]
    fn active_limit_preserves_retries_and_completed_tombstones() {
        let mut reservations = BTreeMap::new();
        for index in 0..MAX_PENDING_RESERVATIONS {
            reservations.insert(index.to_string(), pending(1, vec![0]));
        }
        assert!(is_new_reservation(&reservations, "new", 55, 1, &[0]).is_err());
        assert!(!is_new_reservation(&reservations, "0", 55, 1, &[0]).unwrap());
        reservations.get_mut("0").unwrap().completed = true;
        assert!(is_new_reservation(&reservations, "new", 55, 1, &[0]).unwrap());
        assert!(reservations.contains_key("0"));
    }

    #[test]
    fn hash_binding_is_durable_identity_not_replacement_authority() {
        let mut reservations = BTreeMap::new();
        reservations.insert("a".into(), pending(7, vec![0]));
        reservations.insert("b".into(), pending(7, vec![0]));
        let first = Bytes32::from_u32_slice(&[1; 8]).unwrap();
        let other = Bytes32::from_u32_slice(&[2; 8]).unwrap();
        assert!(bind_hash(&mut reservations, "a", first).unwrap());
        assert!(!bind_hash(&mut reservations, "a", first).unwrap());
        assert!(bind_hash(&mut reservations, "a", other).is_err());
        assert!(bind_hash(&mut reservations, "b", first).is_err());
        reservations.get_mut("a").unwrap().completed = true;
        assert!(!bind_hash(&mut reservations, "a", first).unwrap());
        assert_eq!(pending_at(&reservations, None, 0, 55).unwrap(), (7, 1));
    }

    #[test]
    fn public_result_does_not_serialize_private_range_evidence() {
        let output = CapacityResult {
            schema_version: 1,
            channel_id: 7,
            state_digest: "0x01".into(),
            recipient_slots: vec![0, 3],
            token_index: 55,
            amount: u64::MAX.to_string(),
            completed: false,
        };
        let value = serde_json::to_value(output).unwrap();
        assert_eq!(value.as_object().unwrap().len(), 7);
        assert_eq!(value["amount"], "18446744073709551615");
        assert_eq!(value["recipientSlots"], serde_json::json!([0, 3]));
        assert!(value.get("upperBounds").is_none());
        assert!(value.get("ownedPlaintexts").is_none());
    }
}

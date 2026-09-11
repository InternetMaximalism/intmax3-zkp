//! TEST-ONLY mechanical faithfulness support (Layer M of
//! `doc/audit/zkp/tasks/loop-2026-09-11-backing-and-evidence-plan.md`).
//!
//! The Lean per-primitive models under `doc/audit/zkp/Zkp/Implementation/` transcribe each
//! plonky2 builder call of a circuit constructor into a `BuildOp` and give it a local
//! proposition (`BuildOp.holds`). This module lets a `#[cfg(test)]` test check the
//! *structural* half of those propositions — wire equalities, constant wirings, range-check
//! widths and public-input order — against the circuit plonky2 actually built, with no
//! proving.
//!
//! Mechanism: after `CircuitBuilder::build`, `CircuitData.prover_only.representative_map`
//! is the path-compressed disjoint-set forest over every wire and virtual target
//! (`contracts/lib/polygon-plonky2/plonky2/src/plonk/circuit_data.rs:375`, built from
//! `forest.parents` at `circuit_builder.rs:1353`). Two targets are wired equal by
//! `builder.connect` — and hence by `connect_array`, `assert_zero`, `assert_one`,
//! `Bytes32Target::connect`, … — **iff** their representatives coincide. `Target::index`
//! (`iop/target.rs:55`) is the index into that map.
//!
//! Constants: `builder.constant(c)` caches one virtual target per value
//! (`circuit_builder.rs:650`), and `build` connects it to an "extra constant wire" of some
//! gate whose constant polynomial carries `c` (`circuit_builder.rs:1138-1163`; the slots come
//! from `Gate::extra_constant_wires`, implemented by `ConstantGate` and `RandomAccessGate`).
//! A gate forces such a wire to equal its constant, so a target sharing a representative with
//! ANY of those wires is pinned to that value — which is exactly what `is_const` reports. A
//! slot that ended up unused still pins its own wire, but nothing is connected to it, so
//! including it cannot make `is_const` answer `true` for an unconstrained target.
//!
//! Range checks: `builder.range_check(x, n)` is `split_le(x, n)`
//! (`gadgets/range_check.rs:21`), which adds ONE `BaseSumGate<2>` row (63 limbs under the
//! standard configs, so `k = 1` for every width used in this repo), asserts the surplus
//! limbs `n..63` to zero, and connects `x` to `Target::wire(row, BaseSumGate::WIRE_SUM)`
//! (`gadgets/split_join.rs:25-56`; the accumulator fold collapses to the sum wire itself
//! because `arithmetic_special_cases` returns the addend when a multiplicand is the zero
//! constant). The checked width is therefore recoverable as the highest limb index that is
//! NOT wired to zero, plus one.

use std::{
    collections::{BTreeMap, HashMap, HashSet},
    fmt::Write as _,
    fs,
    path::PathBuf,
};

use plonky2::{
    field::{extension::Extendable, types::Field64},
    hash::hash_types::RichField,
    iop::target::Target,
    plonk::{circuit_data::CircuitData, config::GenericConfig},
};

/// Directory the evidence tables and expectation files live in.
pub fn evidence_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("doc/audit/zkp/evidence")
}

/// A read-only view of the copy-constraint partition of a built circuit.
pub struct RepView {
    num_wires: usize,
    degree: usize,
    rep: Vec<usize>,
    /// constant value -> every class pinned to it by a gate constant.
    const_classes: HashMap<u64, HashSet<usize>>,
    /// `BaseSumGate<2>` sum-wire class -> `(row, num_limbs)`.
    base_sum: HashMap<usize, Vec<(usize, usize)>>,
    public_inputs: Vec<Target>,
}

impl RepView {
    pub fn new<F, C, const D: usize>(data: &CircuitData<F, C, D>) -> Self
    where
        F: RichField + Extendable<D>,
        C: GenericConfig<D, F = F>,
    {
        let common = &data.common;
        let num_wires = common.config.num_wires;
        let degree = common.degree();
        let rep = data.prover_only.representative_map.clone();
        assert!(
            rep.len() >= degree * num_wires,
            "representative_map shorter than the wire grid"
        );

        let num_sel = common.selectors_info.num_selectors();
        let const_off = num_sel + common.num_lookup_selectors;
        let evals = &data.prover_only.constant_evals;

        let gate_rows = |gate_index: usize| -> Vec<usize> {
            let sel = common.selectors_info.selector_indices[gate_index];
            let want = F::from_canonical_u64(gate_index as u64);
            (0..degree).filter(|&row| evals[row][sel] == want).collect()
        };

        let mut const_classes: HashMap<u64, HashSet<usize>> = HashMap::new();
        for (gi, gate) in common.gates.iter().enumerate() {
            // Exactly the slots `CircuitBuilder::build` can place a cached constant in.
            let slots = gate.0.extra_constant_wires();
            if slots.is_empty() {
                continue;
            }
            for row in gate_rows(gi) {
                for &(const_index, wire_index) in &slots {
                    let value = evals[row][const_off + const_index].to_canonical_u64();
                    let class = rep[Target::wire(row, wire_index).index(num_wires, degree)];
                    const_classes.entry(value).or_default().insert(class);
                }
            }
        }

        let mut base_sum: HashMap<usize, Vec<(usize, usize)>> = HashMap::new();
        for (gi, gate) in common.gates.iter().enumerate() {
            let id = gate.0.id();
            if !id.starts_with("BaseSumGate") || !id.ends_with("Base: 2") {
                continue;
            }
            let num_limbs: usize = id
                .split("num_limbs: ")
                .nth(1)
                .and_then(|s| s.split(' ').next())
                .and_then(|s| s.trim_end_matches('}').trim().parse().ok())
                .unwrap_or_else(|| panic!("cannot parse BaseSumGate id {id:?}"));
            for row in gate_rows(gi) {
                let class = rep[Target::wire(row, 0).index(num_wires, degree)];
                base_sum.entry(class).or_default().push((row, num_limbs));
            }
        }

        assert!(
            const_classes.contains_key(&0),
            "no gate constant carries the value 0; the constant scan is wrong"
        );

        Self {
            num_wires,
            degree,
            rep,
            const_classes,
            base_sum,
            public_inputs: data.prover_only.public_inputs.clone(),
        }
    }

    pub fn rep(&self, t: Target) -> usize {
        self.rep[t.index(self.num_wires, self.degree)]
    }

    /// `builder.connect(a, b)` (transitively) was emitted between these two targets.
    pub fn same(&self, a: Target, b: Target) -> bool {
        self.rep(a) == self.rep(b)
    }

    pub fn same_slices(&self, a: &[Target], b: &[Target]) -> bool {
        a.len() == b.len() && a.iter().zip(b).all(|(x, y)| self.same(*x, *y))
    }

    /// The target is wired to the cached constant `value`.
    pub fn is_const(&self, t: Target, value: u64) -> bool {
        self.const_classes
            .get(&value)
            .is_some_and(|cs| cs.contains(&self.rep(t)))
    }

    pub fn is_zero(&self, t: Target) -> bool {
        self.is_const(t, 0)
    }

    pub fn is_one(&self, t: Target) -> bool {
        self.is_const(t, 1)
    }

    pub fn all_zero(&self, ts: &[Target]) -> bool {
        ts.iter().all(|t| self.is_zero(*t))
    }

    /// Widths of every `range_check` applied to this target, in bits. Empty = unchecked.
    pub fn range_bits(&self, t: Target) -> Vec<usize> {
        let Some(rows) = self.base_sum.get(&self.rep(t)) else {
            return Vec::new();
        };
        let mut out: Vec<usize> = rows
            .iter()
            .map(|&(row, num_limbs)| {
                let mut bits = 0usize;
                for i in (0..num_limbs).rev() {
                    if !self.is_zero(Target::wire(row, 1 + i)) {
                        bits = i + 1;
                        break;
                    }
                }
                bits
            })
            .collect();
        out.sort_unstable();
        out.dedup();
        out
    }

    /// Every target of the slice carries a range check of exactly `bits` bits.
    pub fn all_range_checked(&self, ts: &[Target], bits: usize) -> bool {
        ts.iter().all(|t| self.range_bits(*t).contains(&bits))
    }

    pub fn none_range_checked(&self, ts: &[Target]) -> bool {
        ts.iter().all(|t| self.range_bits(*t).is_empty())
    }

    /// The registered public-input targets, in `register_public_input(s)` order.
    pub fn public_inputs(&self) -> &[Target] {
        &self.public_inputs
    }

    /// The registered public inputs are exactly `expected`, in order, wire for wire.
    pub fn public_inputs_are(&self, expected: &[Target]) -> bool {
        self.same_slices(&self.public_inputs, expected)
    }
}

/// One line of a faithfulness table.
pub struct EvidenceRow {
    pub op: String,
    pub source: String,
    pub kind: &'static str,
    pub verdict: &'static str,
    pub detail: String,
}

/// Verdicts. `OK` and `MISMATCH` are the only outcomes of an executed structural check;
/// the others declare, in the table itself, why an op is not checked this way.
pub const OK: &str = "ok";
pub const MISMATCH: &str = "MISMATCH";
/// The op's `holds` is arithmetic/gadget semantics, not a copy constraint: the
/// representative map cannot see it.
pub const NOT_STATIC: &str = "not-static";
/// The op's `holds` is vacuously `True` in the Lean model (config choice, struct literal,
/// allocation with no gate), so there is nothing to check.
pub const TRIVIAL: &str = "trivial";
/// Checked by a proving mutation test in the same file.
pub const MUTATION: &str = "mutation";
/// The violation cannot be expressed through the circuit's public witness API.
pub const NOT_INJECTABLE: &str = "not-injectable";

pub struct EvidenceTable {
    circuit: String,
    rows: Vec<EvidenceRow>,
}

impl EvidenceTable {
    pub fn new(circuit: &str) -> Self {
        Self {
            circuit: circuit.to_string(),
            rows: Vec::new(),
        }
    }

    /// A structural check that must hold: `OK` when `holds`, `MISMATCH` otherwise.
    pub fn check(&mut self, op: &str, source: &str, kind: &'static str, holds: bool, detail: &str) {
        self.rows.push(EvidenceRow {
            op: op.to_string(),
            source: source.to_string(),
            kind,
            verdict: if holds { OK } else { MISMATCH },
            detail: detail.to_string(),
        });
    }

    /// A declared non-check (trivial / not-static / mutation / not-injectable).
    pub fn note(
        &mut self,
        op: &str,
        source: &str,
        kind: &'static str,
        verdict: &'static str,
        detail: &str,
    ) {
        self.rows.push(EvidenceRow {
            op: op.to_string(),
            source: source.to_string(),
            kind,
            verdict,
            detail: detail.to_string(),
        });
    }

    pub fn len(&self) -> usize {
        self.rows.len()
    }

    pub fn is_empty(&self) -> bool {
        self.rows.is_empty()
    }

    pub fn count(&self, verdict: &str) -> usize {
        self.rows.iter().filter(|r| r.verdict == verdict).count()
    }

    /// Writes `faithfulness-<circuit>.tsv`, diffs the `(op, kind, verdict)` triples against
    /// the checked-in `faithfulness-<circuit>.ops` expectation file, and asserts that no row
    /// came out `MISMATCH`.
    ///
    /// Set `INTMAX_FAITHFULNESS_BLESS=1` to (re)write the expectation file.
    pub fn finish(self) {
        let dir = evidence_dir();
        fs::create_dir_all(&dir).expect("create evidence dir");

        let mut tsv = String::new();
        writeln!(tsv, "# faithfulness table for {}", self.circuit).unwrap();
        writeln!(
            tsv,
            "# generated by `cargo test --release --lib -- --test-threads=1 faithfulness`; do not hand-edit"
        )
        .unwrap();
        writeln!(tsv, "op\tsource\tkind\tverdict\tdetail").unwrap();
        for r in &self.rows {
            writeln!(
                tsv,
                "{}\t{}\t{}\t{}\t{}",
                r.op, r.source, r.kind, r.verdict, r.detail
            )
            .unwrap();
        }
        let tsv_path = dir.join(format!("faithfulness-{}.tsv", self.circuit));
        fs::write(&tsv_path, &tsv).expect("write faithfulness table");

        let mut expectation = String::new();
        writeln!(
            expectation,
            "# ops of the Lean model of {} covered by the static faithfulness check",
            self.circuit
        )
        .unwrap();
        writeln!(expectation, "# op\tkind\tverdict").unwrap();
        let mut sorted: Vec<String> = self
            .rows
            .iter()
            .map(|r| format!("{}\t{}\t{}", r.op, r.kind, r.verdict))
            .collect();
        sorted.sort();
        for line in &sorted {
            writeln!(expectation, "{line}").unwrap();
        }
        let ops_path = dir.join(format!("faithfulness-{}.ops", self.circuit));
        if std::env::var("INTMAX_FAITHFULNESS_BLESS").is_ok() || !ops_path.exists() {
            fs::write(&ops_path, &expectation).expect("write expectation file");
        } else {
            let checked_in = fs::read_to_string(&ops_path).expect("read expectation file");
            if checked_in != expectation {
                let a: Vec<&str> = checked_in.lines().collect();
                let b: Vec<&str> = expectation.lines().collect();
                let only_in_expected: Vec<&&str> = a.iter().filter(|l| !b.contains(l)).collect();
                let only_in_actual: Vec<&&str> = b.iter().filter(|l| !a.contains(l)).collect();
                panic!(
                    "{} drifted from {}\n  only in expectation: {:?}\n  only in actual: {:?}",
                    self.circuit,
                    ops_path.display(),
                    only_in_expected,
                    only_in_actual
                );
            }
        }

        let bad: Vec<&EvidenceRow> = self.rows.iter().filter(|r| r.verdict == MISMATCH).collect();
        let mut by_verdict: BTreeMap<&str, usize> = BTreeMap::new();
        for r in &self.rows {
            *by_verdict.entry(r.verdict).or_default() += 1;
        }
        println!(
            "[faithfulness {}] {} ops -> {:?} (table: {})",
            self.circuit,
            self.rows.len(),
            by_verdict,
            tsv_path.display()
        );
        assert!(
            bad.is_empty(),
            "{} Lean `holds` claim(s) DISAGREE with the built circuit: {:?}",
            bad.len(),
            bad.iter()
                .map(|r| format!("{} ({}): {}", r.op, r.source, r.detail))
                .collect::<Vec<_>>()
        );
    }
}

#[cfg(test)]
mod self_tests {
    use plonky2::{
        field::{goldilocks_field::GoldilocksField, types::Field},
        plonk::{
            circuit_builder::CircuitBuilder,
            circuit_data::CircuitConfig,
            config::PoseidonGoldilocksConfig,
        },
    };

    use super::*;

    type F = GoldilocksField;
    const D: usize = 2;
    type C = PoseidonGoldilocksConfig;

    /// Pins the three primitives the whole Layer-M static check rests on: `connect`
    /// merges representatives, `builder.constant` / `zero` / `one` are identifiable
    /// classes, and `range_check(t, n)` is recoverable as exactly `n` bits.
    #[test]
    fn faithfulness_repview_self_check() {
        let mut builder =
            CircuitBuilder::<F, D>::new(CircuitConfig::standard_recursion_zk_config());
        let a = builder.add_virtual_target();
        let b = builder.add_virtual_target();
        let c = builder.add_virtual_target();
        let d = builder.add_virtual_target();
        let e = builder.add_virtual_target();
        builder.connect(a, b);
        let zero = builder.zero();
        builder.connect(c, zero);
        builder.assert_one(d);
        builder.range_check(a, 32);
        builder.range_check(e, 11);
        let seven = builder.constant(F::from_canonical_u64(7));
        let g = builder.add_virtual_target();
        builder.connect(g, seven);
        builder.register_public_inputs(&[a, d, e]);
        let data = builder.build::<C>();

        let v = RepView::new(&data);
        assert!(v.same(a, b), "connect must merge representatives");
        assert!(!v.same(a, e), "unrelated targets must not share a class");
        assert!(v.is_zero(c), "assert_zero/connect-to-zero must be visible");
        assert!(!v.is_zero(a));
        assert!(v.is_one(d), "assert_one must be visible");
        assert!(v.is_const(g, 7), "builder.constant(7) must be visible");
        assert!(!v.is_const(g, 5));
        assert_eq!(v.range_bits(a), vec![32], "32-bit range check width");
        assert_eq!(v.range_bits(b), vec![32], "width travels through connect");
        assert_eq!(v.range_bits(e), vec![11], "11-bit range check width");
        assert!(v.range_bits(c).is_empty(), "unchecked target has no width");
        assert!(
            v.public_inputs_are(&[a, d, e]),
            "registered public-input order"
        );
        assert!(!v.public_inputs_are(&[d, a, e]));
    }
}

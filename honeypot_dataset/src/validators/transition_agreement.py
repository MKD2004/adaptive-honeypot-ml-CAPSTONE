"""
src/validators/transition_agreement.py

What transitions does REAL attacker traffic actually make, and how far is that
from `KILL_CHAIN_DAG`? Run as `python -m src.validators.transition_agreement`
from `honeypot_dataset/`.

Decided 2026-11-25 (DATA_INTEGRITY.md section 20): the DAG stays a PRESCRIPTIVE
kill-chain reference. No real session is rejected for violating it --
`kill_chain_simulator.filter_invalid_sequences` exists but is called by nothing,
and must never be pointed at real data. What happens instead is this: observed
transitions are recorded separately and their agreement with the DAG is
measured, exactly as section 8a does for labels (keep the intended value, record
what was observed, report the gap).

Read it the way section 19c says to read KCVR. On GENERATED sequences agreement
is ~100% and that is a tautology: `cowrie_simulator` walks the DAG backwards
from the intended label, so it cannot produce an edge the DAG forbids. Only the
REAL column is a measurement.

Two directions matter and they are different questions:

  observed -> DAG   of the transitions real attackers make, how many does the
                    DAG permit? (low = the DAG is too tight)
  DAG -> observed   of the transitions the DAG permits, how many are ever
                    observed? (low = the DAG is mostly hypothetical)
"""
from __future__ import annotations

import json
import logging
from collections import Counter
from pathlib import Path
from typing import Dict, Iterable, List, Sequence, Tuple

import numpy as np

log = logging.getLogger(__name__)

SELF_LOOP = "self_loop"


def _states(seq: str) -> List[str]:
    return [s.strip() for s in str(seq).split(",") if s.strip()]


def observed_transitions(sequences: Iterable[str]) -> Tuple[Counter, Counter]:
    """(transitions, counters) over comma-joined micro-state walks.

    Self-loops are counted separately rather than dropped: a repeated state is a
    real observation, but the DAG holds no self-edges so scoring them against it
    would be meaningless.
    """
    trans: Counter = Counter()
    stats: Counter = Counter()
    for seq in sequences:
        st = _states(seq)
        if len(st) < 2:
            stats["sequences_single_state"] += 1
            continue
        stats["sequences_multi_state"] += 1
        for a, b in zip(st[:-1], st[1:]):
            if a == b:
                stats[SELF_LOOP] += 1
            else:
                trans[(a, b)] += 1
    return trans, stats


def agreement(trans: Counter) -> Dict[str, object]:
    """Per-edge and aggregate agreement between observed transitions and the DAG."""
    from configs.schema import IDX_TO_PHASE, KILL_CHAIN_DAG, LABEL_TO_IDX

    def phase(label: str) -> int:
        return IDX_TO_PHASE[LABEL_TO_IDX[label]]

    edges = []
    for (a, b), n in trans.most_common():
        permitted = b in KILL_CHAIN_DAG.get(a, ())
        pa, pb = phase(a), phase(b)
        edges.append({
            "from": a, "to": b, "n": int(n),
            "phase_from": pa, "phase_to": pb,
            "phase_delta": pb - pa,
            "in_dag": bool(permitted),
            # the shape of the violation, which is what a reader needs: a
            # forward skip is a gap in the DAG, a backward step contradicts
            # phase monotonicity outright
            "kind": ("permitted" if permitted else
                     "backward" if pb < pa else
                     "same_phase" if pb == pa else
                     "forward_adjacent" if pb - pa == 1 else "forward_skip"),
        })

    total_n = sum(e["n"] for e in edges) or 1
    permitted_n = sum(e["n"] for e in edges if e["in_dag"])
    dag_edge_total = sum(len(v) for v in KILL_CHAIN_DAG.values())
    observed_pairs = {(e["from"], e["to"]) for e in edges}
    dag_pairs = {(a, b) for a, dsts in KILL_CHAIN_DAG.items() for b in dsts}

    by_kind = Counter()
    for e in edges:
        by_kind[e["kind"]] += e["n"]

    return {
        "edges": edges,
        "observed_edge_types": len(edges),
        "observed_instances": int(total_n),
        "observed_permitted_types": sum(1 for e in edges if e["in_dag"]),
        "observed_permitted_instances": int(permitted_n),
        "agreement_by_instance": round(permitted_n / total_n, 4),
        "agreement_by_edge_type": round(
            sum(1 for e in edges if e["in_dag"]) / max(len(edges), 1), 4),
        "dag_edge_types": dag_edge_total,
        "dag_edge_types_ever_observed": len(observed_pairs & dag_pairs),
        "dag_coverage": round(len(observed_pairs & dag_pairs) / max(dag_edge_total, 1), 4),
        "instances_by_kind": dict(by_kind),
    }


def _report(name: str, sequences: Sequence[str], top: int = 14) -> Dict[str, object]:
    trans, stats = observed_transitions(sequences)
    if not trans:
        log.info("%s: no multi-state walks -- nothing to measure", name)
        return {"name": name, "sequences": int(len(sequences)), "edges": []}
    rep = agreement(trans)
    rep["name"] = name
    rep["sequences"] = int(len(sequences))
    rep["sequences_multi_state"] = int(stats["sequences_multi_state"])
    rep["self_loop_instances"] = int(stats[SELF_LOOP])

    log.info("")
    log.info("%s -- %s of %s sequences carry a multi-state walk",
             name, f"{stats['sequences_multi_state']:,}", f"{len(sequences):,}")
    log.info("  %-52s %8s  %7s  %s", "transition", "n", "phases", "in DAG?")
    for e in rep["edges"][:top]:
        log.info("  %-52s %8s  %d->%-4d  %s",
                 f"{e['from']} -> {e['to']}", f"{e['n']:,}",
                 e["phase_from"], e["phase_to"],
                 "yes" if e["in_dag"] else f"NO ({e['kind']})")
    if len(rep["edges"]) > top:
        log.info("  ... %d more edge types", len(rep["edges"]) - top)
    log.info("  agreement: %.1f%% of instances, %d of %d edge types",
             100 * rep["agreement_by_instance"],
             rep["observed_permitted_types"], rep["observed_edge_types"])
    log.info("  DAG coverage: %d of %d DAG edge types are ever observed (%.1f%%)",
             rep["dag_edge_types_ever_observed"], rep["dag_edge_types"],
             100 * rep["dag_coverage"])
    log.info("  instances by kind: %s", rep["instances_by_kind"])
    return rep


def run(data_dir: Path) -> Dict[str, object]:
    """Observed-vs-DAG agreement for the real and generated halves, separately."""
    out: Dict[str, object] = {}
    seq, gen = [], []
    for split in ("train", "val", "test_real", "test_synth"):
        s, g = data_dir / f"seq_{split}.npy", data_dir / f"gen_{split}.npy"
        if not (s.exists() and g.exists()):
            log.warning("%s: seq_/gen_ arrays missing -- skipped", split)
            continue
        seq.append(np.load(s)); gen.append(np.load(g))
    if not seq:
        raise FileNotFoundError(
            f"no seq_<split>.npy in {data_dir}; rerun notebooks 02 then 05")
    seq = np.concatenate(seq)
    gen = np.asarray([str(v) for v in np.concatenate(gen)])

    out["real_honeypot"] = _report("REAL (cowrie_real)", seq[gen == "cowrie_real"])
    out["generated"] = _report("GENERATED (simulated_cowrie_events)",
                               seq[gen == "simulated_cowrie_events"])
    log.info("")
    log.info("The GENERATED row is a tautology -- cowrie_simulator walks the DAG")
    log.info("backwards from the label, so it cannot emit a forbidden edge. Only")
    log.info("the REAL row measures anything (DATA_INTEGRITY.md section 20).")
    return out


def main() -> None:
    import argparse

    logging.basicConfig(level=logging.INFO, format="%(message)s")
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--data-dir", type=Path, default=Path("data/final_v2"))
    ap.add_argument("--out", type=Path, default=None,
                    help="JSON destination (default: <data-dir>/transition_agreement.json)")
    args = ap.parse_args()

    report = run(args.data_dir)
    out = args.out or args.data_dir / "transition_agreement.json"
    out.write_text(json.dumps(report, indent=2), encoding="utf-8")
    log.info("\nSaved -> %s", out)


if __name__ == "__main__":
    main()

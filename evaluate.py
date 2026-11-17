#!/usr/bin/env python3
"""
Evaluacion minima del triaje: compara el veredicto (reglas y LLM) con una etiqueta esperada.

eval/iocs.csv  ->  columnas: ioc,expected,notes     (expected = malicious | benign)

Un IOC cuenta como "marcado" si el veredicto es malicious o suspicious.
  - Acierto : expected=malicious y marcado, o expected=benign y NO marcado
  - FN      : expected=malicious y NO marcado     (lo peligroso: se escapa una amenaza)
  - FP      : expected=benign y marcado           (ruido para el analista)

Uso:
    python evaluate.py eval/iocs.csv                # reglas + LLM (necesita API keys)
    python evaluate.py eval/iocs.csv --no-llm       # solo reglas
"""
from __future__ import annotations

import argparse
import csv
import sys
from pathlib import Path

import triaje

FLAGGED = {"malicious", "suspicious"}


def is_correct(expected: str, verdict: str) -> bool:
    flagged = verdict in FLAGGED
    return flagged if expected == "malicious" else not flagged


def metrics(rows: list[dict], key: str) -> dict:
    """rows: [{'expected':..., key: verdict}, ...] -> aciertos, FP, FN."""
    total = len(rows)
    ok = sum(is_correct(r["expected"], r[key]) for r in rows)
    fp = sum(r["expected"] == "benign" and r[key] in FLAGGED for r in rows)
    fn = sum(r["expected"] == "malicious" and r[key] not in FLAGGED for r in rows)
    return {"total": total, "correct": ok, "accuracy": ok / total if total else 0.0, "fp": fp, "fn": fn}


def run(csv_path: Path, use_llm: bool, offline: bool) -> list[dict]:
    rows = []
    with csv_path.open(encoding="utf-8") as fh:
        reader = csv.DictReader(line for line in fh if line.strip() and not line.startswith("#"))
        for item in reader:
            res = triaje.triage(item["ioc"], offline=offline, use_llm=use_llm)
            llm = res["llm"] or {}
            rows.append({
                "ioc": item["ioc"], "expected": item["expected"].strip().lower(),
                "baseline": res["baseline_verdict"],
                "llm": llm.get("verdict", "n/a") if "error" not in llm else "error",
            })
    return rows


def to_markdown(rows: list[dict], use_llm: bool) -> str:
    out = ["| IOC | Esperado | Reglas | LLM | ¿Acierta reglas? | ¿Acierta LLM? |", "|---|---|---|---|---|---|"]
    for r in rows:
        okb = "✅" if is_correct(r["expected"], r["baseline"]) else "❌"
        okl = ("✅" if is_correct(r["expected"], r["llm"]) else "❌") if use_llm and r["llm"] != "error" else "-"
        out.append(f"| `{r['ioc']}` | {r['expected']} | {r['baseline']} | {r['llm']} | {okb} | {okl} |")
    mb = metrics(rows, "baseline")
    out += ["", f"**Reglas:** {mb['correct']}/{mb['total']} aciertos ({mb['accuracy']:.0%}) · FP={mb['fp']} · FN={mb['fn']}"]
    if use_llm:
        ml = metrics([r for r in rows if r["llm"] != "error"], "llm")
        out.append(f"**LLM:** {ml['correct']}/{ml['total']} aciertos ({ml['accuracy']:.0%}) · FP={ml['fp']} · FN={ml['fn']}")
    return "\n".join(out) + "\n"


def main() -> int:
    triaje.load_env()
    ap = argparse.ArgumentParser()
    ap.add_argument("csv", type=Path)
    ap.add_argument("--no-llm", action="store_true")
    ap.add_argument("--offline", action="store_true", help="Usa fixtures (solo para probar el script)")
    ap.add_argument("--out", type=Path, default=Path("eval/resultados.md"))
    args = ap.parse_args()
    rows = run(args.csv, use_llm=not args.no_llm, offline=args.offline)
    md = to_markdown(rows, use_llm=not args.no_llm)
    args.out.write_text(md, encoding="utf-8")
    print(md)
    return 0


if __name__ == "__main__":
    sys.exit(main())

#!/usr/bin/env python3
"""
risk_register.py — Score, rank, and summarize an information-security risk register.

Reads risks from YAML or CSV, computes inherent and residual risk
(likelihood x impact, 1-5 each), assigns severity bands, optionally computes a
quantitative ALE (SLE x ARO), and prints a ranked register plus a 5x5 heat-map
summary. Output is decision-support for a GRC program.

Input fields (per risk):
  id, risk, asset, threat, likelihood (1-5), impact (1-5),
  control_effectiveness (0-1, optional), treatment, owner, due,
  sle (optional, $), aro (optional, events/yr)

Usage:
    python risk_register.py --input risks.yaml --output register.json
    python risk_register.py --input risks.csv --quant
"""
import argparse
import csv
import json
import sys

try:
    import yaml  # type: ignore
except ImportError:
    yaml = None


def severity(score: int) -> str:
    if score >= 20:
        return "Critical"
    if score >= 12:
        return "High"
    if score >= 6:
        return "Medium"
    if score >= 3:
        return "Low"
    return "Informational"


def load(path: str) -> list[dict]:
    if path.endswith((".yaml", ".yml")):
        if yaml is None:
            print("[!] pip install pyyaml to read YAML", file=sys.stderr)
            sys.exit(1)
        with open(path, encoding="utf-8") as fh:
            data = yaml.safe_load(fh)
        return data.get("risks", data) if isinstance(data, dict) else data
    if path.endswith(".csv"):
        with open(path, encoding="utf-8") as fh:
            return list(csv.DictReader(fh))
    print("[!] Use a .yaml/.yml or .csv input", file=sys.stderr)
    sys.exit(1)


def num(v, default=0.0):
    try:
        return float(v)
    except (TypeError, ValueError):
        return default


def score_risk(r: dict, quant: bool) -> dict:
    like = int(num(r.get("likelihood"), 1))
    imp = int(num(r.get("impact"), 1))
    inherent = like * imp
    eff = num(r.get("control_effectiveness"), 0.0)  # 0..1
    eff = min(max(eff, 0.0), 1.0)
    residual = max(1, round(inherent * (1 - eff)))
    out = {
        "id": r.get("id", ""),
        "risk": r.get("risk", ""),
        "asset": r.get("asset", ""),
        "threat": r.get("threat", ""),
        "likelihood": like,
        "impact": imp,
        "inherent": inherent,
        "inherent_severity": severity(inherent),
        "control_effectiveness": eff,
        "residual": residual,
        "residual_severity": severity(residual),
        "treatment": r.get("treatment", ""),
        "owner": r.get("owner", ""),
        "due": r.get("due", ""),
    }
    if quant:
        sle = num(r.get("sle"))
        aro = num(r.get("aro"))
        out["ale"] = round(sle * aro, 2)
        out["sle"] = sle
        out["aro"] = aro
    return out


def heatmap(rows: list[dict]) -> str:
    # 5x5 grid counts by (impact rows top->bottom 5..1, likelihood cols 1..5)
    grid = [[0] * 5 for _ in range(5)]
    for r in rows:
        i = min(max(r["impact"], 1), 5)
        l = min(max(r["likelihood"], 1), 5)
        grid[5 - i][l - 1] += 1
    lines = ["", "Heat map (rows=Impact 5..1, cols=Likelihood 1..5):"]
    for idx, row in enumerate(grid):
        imp = 5 - idx
        lines.append(f"  I{imp} | " + " ".join(f"{c:>2}" for c in row))
    lines.append("       " + " ".join(f"L{n}" for n in range(1, 6)))
    return "\n".join(lines)


def main() -> None:
    ap = argparse.ArgumentParser(description="Score and rank an information-security risk register")
    ap.add_argument("--input", required=True, help="risks.yaml or risks.csv")
    ap.add_argument("--quant", action="store_true", help="Compute ALE (needs sle, aro)")
    ap.add_argument("--output", help="Write JSON register")
    args = ap.parse_args()

    raw = load(args.input)
    rows = [score_risk(r, args.quant) for r in raw]
    rows.sort(key=lambda x: x["residual"], reverse=True)

    print(f"[*] {len(rows)} risks scored (ranked by residual)\n")
    print(f"  {'ID':<8}{'Residual':<10}{'Sev':<10}{'Risk'}")
    bands = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0, "Informational": 0}
    for r in rows:
        bands[r["residual_severity"]] += 1
        ale = f"  ALE=${r['ale']:,.0f}" if args.quant else ""
        print(f"  {r['id']:<8}{r['residual']:<10}{r['residual_severity']:<10}{r['risk'][:48]}{ale}")

    print("\n  Residual severity distribution:")
    for b in ("Critical", "High", "Medium", "Low", "Informational"):
        if bands[b]:
            print(f"    {b:<14}: {bands[b]}")
    print(heatmap(rows))

    if args.quant:
        total_ale = sum(r.get("ale", 0) for r in rows)
        print(f"\n  Total Annualized Loss Expectancy: ${total_ale:,.0f}")

    if args.output:
        with open(args.output, "w", encoding="utf-8") as fh:
            json.dump({"summary": bands, "risks": rows}, fh, indent=2)
        print(f"\n[+] Wrote {args.output}")


if __name__ == "__main__":
    main()

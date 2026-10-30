"""Step 2: score generated rules against attack events, benign baseline, and ATT&CK tags."""
import json
import re
from collections import Counter, defaultdict
from pathlib import Path

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt  # noqa: E402
import pandas as pd  # noqa: E402
import yaml  # noqa: E402

from generate import sample_cases  # noqa: E402
from sigbench.matcher import SigmaError, UnknownModifier, compile_rule  # noqa: E402

ROOT = Path(__file__).parent
RES = ROOT / "results"
YAML_BLOCK = re.compile(r"```(?:yaml|yml)?\s*\n(.*?)```", re.S | re.I)
NOISY = 0.01  # a rule matching >1% of benign events is unusable in practice


def extract_rule(text):
    # Fall back to the raw text minus stray fences (some models omit the opening ```).
    blocks = YAML_BLOCK.findall(text) or [re.sub(r"(?m)^```.*$", "", text)]
    for b in blocks:
        try:
            docs = [d for d in yaml.safe_load_all(b) if isinstance(d, dict)]
        except yaml.YAMLError:
            continue
        for d in docs:
            if "detection" in d:
                return d
    return None


def techniques(rule):
    tags = rule.get("tags") or [] if isinstance(rule, dict) else []
    return {str(t).lower().removeprefix("attack.") for t in tags
            if re.fullmatch(r"attack\.t\d{4}(\.\d{3})?", str(t).lower())}


def tactics(rule):
    tags = rule.get("tags") or [] if isinstance(rule, dict) else []
    # Normalize defense_evasion -> defense-evasion; ATT&CK v18 renamed defense-evasion to stealth.
    alias = {"attack.defense-evasion": "attack.stealth"}
    out = {str(t).lower().replace("_", "-") for t in tags
           if re.fullmatch(r"attack\.[a-z][a-z_-]+", str(t).lower())}
    return {alias.get(t, t) for t in out}


def load_benign():
    by_cat = defaultdict(list)
    for line in (ROOT / "data" / "baseline" / "benign.jsonl").open():
        ev = json.loads(line)
        by_cat[ev.pop("category")].append(ev)
    return by_cat


def evaluate(rule, case, benign):
    out = {"valid": False, "detects": False, "benign_hits": None, "benign_rate": None, "error": None}
    if rule is None:
        out["error"] = "no YAML rule found"
        return out
    try:
        pred = compile_rule(rule)
    except (SigmaError, re.error, TypeError, AttributeError) as e:
        kind = "invented modifier" if isinstance(e, UnknownModifier) else "invalid"
        out["error"] = f"{kind}: {e}"[:120]
        return out
    out["valid"] = True
    try:
        out["detects"] = any(pred(e) for e in case["events"])
        events = benign[case["category"]]
        hits = sum(pred(e) for e in events)
    except (re.error, TypeError) as e:
        out.update(valid=False, error=f"runtime: {e}"[:120])
        return out
    out["benign_hits"] = hits
    out["benign_rate"] = hits / max(1, len(events))
    return out


def miss_reason(rule, case):
    """Heuristic label for a valid rule that does not fire on its attack event."""
    det = {k: v for k, v in rule["detection"].items() if k != "condition"}
    fields = set()
    for item in det.values():
        for d in (item if isinstance(item, list) else [item]):
            if isinstance(d, dict):
                fields.update(str(k).split("|")[0].lower() for k in d)
    seen = {k.lower() for e in case["events"] for k in e}
    if fields - seen:
        return "field not present in this log source"
    return "wrong detection logic"


def main():
    cases = {c["id"]: c for c in sample_cases()}
    benign = load_benign()
    print({k: len(v) for k, v in benign.items()})

    rows = []
    for c in cases.values():  # human-written SigmaHQ rule as the reference
        r = evaluate(c["rule"], c, benign)
        rows.append({"model": "SigmaHQ (human)", "id": c["id"], "category": c["category"], **r,
                     "tech_exact": 1.0, "tech_parent": 1.0, "tactic": 1.0})

    latest = {}
    for g in map(json.loads, (RES / "generations.jsonl").open()):
        if not g["error"] and g["response"] and g["id"] in cases:
            latest[(g["model"], g["id"])] = g
    per_model = Counter(m for m, _ in latest)
    excluded = {m: n for m, n in per_model.items() if n < 0.75 * len(cases)}
    print("excluded for low coverage (<75% of rules):", excluded)
    for (model, cid), g in latest.items():
        if model in excluded:
            continue
        c = cases[cid]
        rule = extract_rule(g["response"])
        r = evaluate(rule, c, benign)
        gold_t, gold_tac = techniques(c["rule"]), tactics(c["rule"])
        pred_t, pred_tac = techniques(rule), tactics(rule)
        parent = lambda s: {t.split(".")[0] for t in s}  # noqa: E731
        r["miss_reason"] = miss_reason(rule, c) if r["valid"] and not r["detects"] else None
        rows.append({"model": model, "id": cid, "category": c["category"], **r,
                     "tech_exact": float(bool(gold_t & pred_t)) if gold_t else None,
                     "tech_parent": float(bool(parent(gold_t) & parent(pred_t))) if gold_t else None,
                     "tactic": float(bool(gold_tac & pred_tac)) if gold_tac else None,
                     "rule_yaml": yaml.safe_dump(rule, sort_keys=False) if rule else None})

    df = pd.DataFrame(rows)
    df["noisy"] = df.benign_rate > NOISY
    df["usable"] = df.valid & df.detects & ~df.noisy.fillna(True)
    df.to_json(RES / "scores.jsonl", orient="records", lines=True)

    summ = df.groupby("model").agg(
        rules=("id", "size"),
        valid_pct=("valid", "mean"),
        detects_pct=("detects", "mean"),
        noisy_pct=("noisy", "mean"),
        usable_pct=("usable", "mean"),
        median_benign_hits=("benign_hits", "median"),
        attack_technique_pct=("tech_exact", "mean"),
        attack_technique_parent_pct=("tech_parent", "mean"),
        attack_tactic_pct=("tactic", "mean"),
    )
    pct = [c for c in summ.columns if c.endswith("_pct")]
    summ[pct] = (summ[pct] * 100).round(1)
    summ = summ.sort_values("usable_pct", ascending=False)
    summ.to_csv(RES / "summary_by_model.csv")
    by_cat = (df[df.model != "SigmaHQ (human)"].groupby("category")[["valid", "detects", "usable"]]
              .mean().mul(100).round(1))
    by_cat.to_csv(RES / "summary_by_category.csv")
    errors = df[~df.valid].groupby("model").error.apply(lambda s: s.str.split(":").str[0].value_counts().to_dict())
    misses = df.miss_reason.value_counts()
    misses.to_csv(RES / "miss_reasons.csv")
    print("\nWhy valid rules missed the attack:\n", misses.to_string())

    print(summ.to_string())
    print("\nBy log source (all models):\n", by_cat.to_string())
    print("\nFailure reasons:\n", errors.to_string())

    plot = summ.drop(index="SigmaHQ (human)", errors="ignore")
    fig, ax = plt.subplots(figsize=(9, 4.8))
    names = [m.split("/")[-1] for m in plot.index]
    x = range(len(names))
    w = 0.27
    ax.bar([i - w for i in x], plot.valid_pct, w, label="valid Sigma", color="#95a5a6")
    ax.bar(list(x), plot.detects_pct, w, label="detects real attack", color="#2980b9")
    ax.bar([i + w for i in x], plot.usable_pct, w, label="usable (detects & <1% benign FP)", color="#27ae60")
    ax.set_xticks(list(x), names, rotation=20, ha="right")
    ax.set_ylabel("% of 60 rules")
    ax.set_ylim(0, 100)
    ax.set_title("Can LLMs write working Sigma rules?")
    ax.legend(fontsize=8, loc="upper right")
    fig.tight_layout()
    fig.savefig(RES / "sigma_by_model.png", dpi=150)


if __name__ == "__main__":
    main()

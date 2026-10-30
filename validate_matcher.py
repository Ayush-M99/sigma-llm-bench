"""Sanity check: SigmaHQ's own rules must fire on their own regression events."""
from collections import Counter
from sigbench.data import load_cases
from sigbench.matcher import compile_rule, SigmaError

cases = load_cases()
print("cases", len(cases), dict(Counter(c["category"] for c in cases)))
tp, misses, errs, preds = 0, [], [], {}
for c in cases:
    try:
        preds[c["id"]] = f = compile_rule(c["rule"])
    except SigmaError as e:
        errs.append((c["rule_path"], str(e)))
        continue
    if any(f(e) for e in c["events"]):
        tp += 1
    else:
        misses.append(c["rule_path"])
print(f"true positives: {tp}/{len(preds)}  unsupported: {len(errs)}")
for m in misses: print("  miss", m)
for e in errs: print("  err ", *e)
fires = sum(any(preds[c["id"]](e) for d in cases if d["id"] != c["id"] and d["category"] == c["category"]
                for e in d["events"]) for c in cases if c["id"] in preds)
print(f"original rules that also fire on another case's event: {fires}/{len(preds)}")

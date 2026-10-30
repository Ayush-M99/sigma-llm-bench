"""Extract a de-duplicated benign event corpus from Nextron's evtx-baseline.

Baseline source: https://github.com/NextronSystems/evtx-baseline (clean
Windows installs with normal activity). Rules firing here are false positives.
"""
import json
import random
from collections import defaultdict
from pathlib import Path

from evtx import PyEvtxParser

from sigbench.data import flatten_event

ROOT = Path(__file__).parent / "data" / "baseline"
OUT = ROOT / "benign.jsonl"
CAP = 15000  # max unique events per category

# Sysmon EventID -> Sigma category, plus PowerShell script block logging.
SYSMON = {1: "process_creation", 11: "file_event", 13: "registry_set"}
DEDUP_KEYS = {
    "process_creation": ("Image", "CommandLine", "ParentImage", "ParentCommandLine"),
    "file_event": ("Image", "TargetFilename"),
    "registry_set": ("Image", "TargetObject", "Details"),
    "ps_script": ("ScriptBlockText",),
}


def main():
    seen = defaultdict(dict)
    files = sorted(ROOT.rglob("*Sysmon*Operational.evtx")) + sorted(ROOT.rglob("*PowerShell*Operational.evtx"))
    for f in files:
        print("parsing", f.name, flush=True)
        for rec in PyEvtxParser(str(f)).records_json():
            ev = flatten_event(json.loads(rec["data"]))
            eid = int(ev.get("EventID") or 0)
            if "Sysmon" in f.name:
                cat = SYSMON.get(eid)
            else:
                cat = "ps_script" if eid == 4104 else None
            if not cat:
                continue
            key = tuple(str(ev.get(k, "")) for k in DEDUP_KEYS[cat])
            seen[cat].setdefault(key, ev)

    random.seed(0)
    with OUT.open("w") as out:
        for cat, events in seen.items():
            vals = list(events.values())
            sample = random.sample(vals, min(CAP, len(vals)))
            print(cat, "unique:", len(vals), "kept:", len(sample))
            for ev in sample:
                out.write(json.dumps({"category": cat, **ev}) + "\n")


if __name__ == "__main__":
    main()

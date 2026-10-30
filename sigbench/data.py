"""Load SigmaHQ rules that ship with regression (true-positive) events."""
import json
from pathlib import Path

import yaml

SIGMA = Path(__file__).resolve().parent.parent / "data" / "sigma"
CATEGORIES = {"process_creation", "registry_set", "file_event", "ps_script"}


def flatten_event(raw):
    """Sysmon/WinEvent JSON -> flat {field: value} dict using Sigma field names."""
    ev = raw.get("Event", raw)
    flat = {}
    data = ev.get("EventData") or {}
    if isinstance(data, dict):
        flat.update({k: v for k, v in data.items() if not k.startswith("#")})
    system = ev.get("System") or {}
    if "EventID" in system:
        eid = system["EventID"]
        flat["EventID"] = eid.get("#text") if isinstance(eid, dict) else eid
    if isinstance(system.get("Provider"), dict):
        flat["Provider_Name"] = system["Provider"].get("#attributes", {}).get("Name")
    if "Channel" in system:
        flat["Channel"] = system["Channel"]
    return flat


def _iter_json(text):
    """Yield each top-level JSON value from a file that may hold several back to back."""
    dec, pos = json.JSONDecoder(), 0
    while True:
        while pos < len(text) and text[pos].isspace():
            pos += 1
        if pos >= len(text):
            return
        obj, pos = dec.raw_decode(text, pos)
        yield obj


def load_cases():
    """Return a list of {rule, rule_path, events} for supported rules."""
    rule_by_id = {}
    for p in (SIGMA / "rules").rglob("*.yml"):
        try:
            r = yaml.safe_load(p.read_text())
        except yaml.YAMLError:
            continue
        if isinstance(r, dict) and "id" in r:
            rule_by_id[r["id"]] = (r, p)

    cases = []
    for info in sorted((SIGMA / "regression_data" / "rules").rglob("info.yml")):
        meta = yaml.safe_load(info.read_text())
        rid = meta["rule_metadata"][0]["id"]
        if rid not in rule_by_id:
            continue
        rule, path = rule_by_id[rid]
        if rule.get("logsource", {}).get("category") not in CATEGORIES:
            continue
        # info.yml often lists only the .evtx test; a JSON export sits beside it.
        events = []
        for jp in sorted(info.parent.glob("*.json")):
            for raw in _iter_json(jp.read_text()):
                for r in (raw if isinstance(raw, list) else [raw]):
                    events.append(flatten_event(r))
        if events:
            cases.append({"id": rid, "rule": rule, "rule_path": str(path.relative_to(SIGMA)),
                          "category": rule["logsource"]["category"], "events": events})
    return cases

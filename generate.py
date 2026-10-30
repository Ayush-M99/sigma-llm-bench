"""Step 1: ask each model to write a Sigma rule from a detection description (resumable)."""
import argparse
import concurrent.futures as cf
import json
import random
import threading
from collections import defaultdict
from pathlib import Path

from sigbench.data import load_cases
from sigbench.llm import chat

MODELS = [
    "openai/gpt-oss-20b",
    "mistralai/mistral-large-4-1t-a52b",
    "nvidia/nemotron-3-ultra-550b-a55b",
    "nvidia/nemotron-3.5-lightning-30b-a3b",
    "meta/muse-glimmer-30b",
]

# How many rules to sample per log source (stratified, fixed seed).
SAMPLE = {"process_creation": 34, "ps_script": 11, "registry_set": 9, "file_event": 6}

FIELDS = {
    "process_creation": "Image, OriginalFileName, CommandLine, ParentImage, ParentCommandLine, "
                        "CurrentDirectory, User, IntegrityLevel, Hashes, Product, Company, Description",
    "file_event": "Image, TargetFilename, User",
    "registry_set": "Image, TargetObject, Details, EventType",
    "ps_script": "ScriptBlockText, Path",
}
LOGSOURCE = {
    "process_creation": "category: process_creation, product: windows (Sysmon Event ID 1)",
    "file_event": "category: file_event, product: windows (Sysmon Event ID 11)",
    "registry_set": "category: registry_set, product: windows (Sysmon Event ID 13)",
    "ps_script": "category: ps_script, product: windows (PowerShell Script Block Logging, Event ID 4104)",
}

SYSTEM = "You are an expert detection engineer who writes high-quality Sigma rules."
PROMPT = """Write a Sigma detection rule for the following behaviour.

Title: {title}
What to detect: {description}
Log source: {logsource}
Available fields: {fields}

Requirements:
- Output a single complete Sigma rule in YAML inside one ```yaml code block.
- Include title, logsource, detection (with condition), level, and tags with the
  relevant MITRE ATT&CK tactic and technique tags (e.g. attack.execution, attack.t1059.001).
- The rule should catch this behaviour while keeping false positives on normal
  Windows activity low."""

OUT = Path(__file__).parent / "results" / "generations.jsonl"
_lock = threading.Lock()


def sample_cases(seed=7):
    by_cat = defaultdict(list)
    for c in load_cases():
        by_cat[c["category"]].append(c)
    rng = random.Random(seed)
    picked = []
    for cat, n in SAMPLE.items():
        picked += rng.sample(sorted(by_cat[cat], key=lambda c: c["id"]), n)
    return picked


def build_prompt(case):
    r = case["rule"]
    return PROMPT.format(title=r["title"], description=" ".join(str(r.get("description", "")).split()),
                         logsource=LOGSOURCE[case["category"]], fields=FIELDS[case["category"]])


def run_one(model, case):
    try:
        text, err = chat(model, [{"role": "system", "content": SYSTEM},
                                 {"role": "user", "content": build_prompt(case)}]), None
    except Exception as e:  # noqa: BLE001
        text, err = "", str(e)[:200]
    rec = {"model": model, "id": case["id"], "category": case["category"],
           "rule_path": case["rule_path"], "response": text, "error": err}
    with _lock, OUT.open("a") as f:
        f.write(json.dumps(rec) + "\n")
    return rec


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--models", nargs="*", default=MODELS)
    ap.add_argument("--workers-per-model", type=int, default=3)
    args = ap.parse_args()
    OUT.parent.mkdir(exist_ok=True)
    done = set()
    if OUT.exists():
        done = {(r["model"], r["id"]) for r in map(json.loads, OUT.open()) if not r["error"] and r["response"]}
    cases = sample_cases()
    jobs = [(m, c) for m in args.models for c in cases if (m, c["id"]) not in done]
    print(f"{len(jobs)} jobs ({len(done)} done)", flush=True)
    pools = {m: cf.ThreadPoolExecutor(args.workers_per_model) for m in args.models}
    futs = [pools[m].submit(run_one, m, c) for m, c in jobs]
    for i, f in enumerate(cf.as_completed(futs), 1):
        r = f.result()
        if i % 20 == 0 or r["error"]:
            print(f"[{i}/{len(jobs)}] {r['model']} {r['rule_path'].split('/')[-1]} "
                  f"{'ERR ' + r['error'] if r['error'] else 'ok'}", flush=True)


if __name__ == "__main__":
    main()

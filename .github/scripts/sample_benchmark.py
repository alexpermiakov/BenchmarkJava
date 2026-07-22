#!/usr/bin/env python3
"""Draw a fixed-seed, proportional sample of scoreable BenchmarkJava findings.

    python3 .github/scripts/sample_benchmark.py findings.sarif expectedresults-1.2.csv 100

Writes sample.sarif (the sampled findings) and sample.csv (the ground-truth
rows for just those test cases), which are what sast-triage and score_triage.py
consume.

Only findings that map to a BenchmarkTest with a ground-truth row are eligible —
anything else can't be scored, so sampling it wastes budget. Strata = ruleId.
Each rule keeps its share of the total, rounded, minimum 1 for any rule that
appears. Same seed + same input = same sample every run, so results are
comparable across runs.
"""
import json
import random
import re
import sys
from collections import defaultdict

SEED = 1337
TESTCASE_RE = re.compile(r"(BenchmarkTest\d+)\.java")


def testcase_of(result):
    for loc in result.get("locations", []):
        uri = (
            loc.get("physicalLocation", {})
            .get("artifactLocation", {})
            .get("uri", "")
        )
        m = TESTCASE_RE.search(uri)
        if m:
            return m.group(1)
    return None


def load_truth(path):
    """Test case -> its raw CSV line. Kept verbatim so sample.csv round-trips."""
    truth = {}
    with open(path) as f:
        for line in f:
            s = line.strip()
            if not s or s.startswith("#"):
                continue
            p = [x.strip() for x in s.split(",")]
            if len(p) < 4:
                continue
            truth[p[0]] = s
    return truth


def main(sarif_path, csv_path, n):
    truth = load_truth(csv_path)
    doc = json.load(open(sarif_path))
    run = doc["runs"][0]
    all_results = run["results"]

    eligible = [r for r in all_results if testcase_of(r) in truth]
    total = len(eligible)
    if total == 0:
        sys.exit(
            f"no findings in {sarif_path} map to a test case in {csv_path} — "
            "check that the scan ran against the BenchmarkJava sources"
        )

    by_rule = defaultdict(list)
    for r in eligible:
        by_rule[r.get("ruleId", "<none>")].append(r)

    rng = random.Random(SEED)
    picked = []
    for rule in sorted(by_rule):
        group = by_rule[rule]
        k = max(1, round(len(group) / total * n))
        k = min(k, len(group))
        picked.extend(rng.sample(group, k))

    # trim/pad to exactly n, deterministically
    rng.shuffle(picked)
    picked = picked[:n]

    run["results"] = picked
    with open("sample.sarif", "w") as f:
        json.dump(doc, f)

    tests = sorted({testcase_of(r) for r in picked})
    with open("sample.csv", "w") as f:
        f.write("# test name, category, real vulnerability, cwe\n")
        for t in tests:
            f.write(truth[t] + "\n")

    print(
        f"sampled {len(picked)} of {total} scoreable findings "
        f"({len(all_results)} total) across {len(by_rule)} rules, "
        f"{len(tests)} test cases",
        file=sys.stderr,
    )


if __name__ == "__main__":
    main(sys.argv[1], sys.argv[2], int(sys.argv[3]))

#!/usr/bin/env python3
"""Draw a fixed-seed, proportional sample of scoreable BenchmarkJava findings.

    python3 .github/scripts/sample_benchmark.py findings.sarif expectedresults-1.2.csv 100

Writes sample.sarif (the sampled findings) and sample.csv (the ground-truth
rows for just those test cases), which are what sast-triage and score_triage.py
consume.

Only findings that map to a BenchmarkTest with a ground-truth row are eligible —
anything else can't be scored, so sampling it wastes budget. Candidates are
collapsed to one finding per test case first, so n findings == n test cases.
Strata = ruleId. Each rule keeps its share of the candidates, rounded, minimum 1
for any rule that appears. Same seed + same input = same sample every run, so
results are comparable across runs.
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

    rng = random.Random(SEED)

    by_test = defaultdict(list)
    for r in all_results:
        tc = testcase_of(r)
        if tc in truth:
            by_test[tc].append(r)
    if not by_test:
        sys.exit(
            f"no findings in {sarif_path} map to a test case in {csv_path} — "
            "check that the scan ran against the BenchmarkJava sources"
        )

    # One finding per test case. Several rules can fire on the same test case,
    # and the scorecard reports per test case — so without this, duplicates
    # spend two of the n slots on one row and n findings < n test cases.
    scoreable = sum(len(g) for g in by_test.values())
    eligible = [rng.choice(by_test[tc]) for tc in sorted(by_test)]
    total = len(eligible)

    by_rule = defaultdict(list)
    for r in eligible:
        by_rule[r.get("ruleId", "<none>")].append(r)

    picked = []
    for rule in sorted(by_rule):
        group = by_rule[rule]
        k = max(1, round(len(group) / total * n))
        k = min(k, len(group))
        picked.extend(rng.sample(group, k))

    # trim/pad to exactly n, deterministically
    rng.shuffle(picked)
    picked = picked[:n]
    if len(picked) < n:
        chosen = {id(r) for r in picked}
        rest = [r for r in eligible if id(r) not in chosen]
        rng.shuffle(rest)
        picked.extend(rest[: n - len(picked)])

    run["results"] = picked
    with open("sample.sarif", "w") as f:
        json.dump(doc, f)

    tests = sorted({testcase_of(r) for r in picked})
    with open("sample.csv", "w") as f:
        f.write("# test name, category, real vulnerability, cwe\n")
        for t in tests:
            f.write(truth[t] + "\n")

    print(
        f"sampled {len(picked)} findings over {len(tests)} test cases "
        f"from {total} candidates ({scoreable} scoreable findings, "
        f"{len(all_results)} total) across {len(by_rule)} rules",
        file=sys.stderr,
    )
    if len(tests) != len(picked):
        sys.exit(f"expected {len(picked)} distinct test cases, got {len(tests)}")


if __name__ == "__main__":
    main(sys.argv[1], sys.argv[2], int(sys.argv[3]))

#!/usr/bin/env python3
"""Draw a fixed-seed, proportional sample of scoreable BenchmarkJava test cases.

    python3 .github/scripts/sample_benchmark.py findings.sarif expectedresults-1.2.csv 100

Writes sample.sarif (every finding on the sampled test cases) and sample.csv
(the ground-truth rows for those test cases), which are what sast-triage and
score_triage.py consume.

n is a number of TEST CASES, not findings — the sampled SARIF will normally
carry more findings than that. The reason is in "Why files, not findings" below.
sample.sarif's finding count is printed to stdout and, under Actions, written to
$GITHUB_OUTPUT as `findings=` so the triage budget can follow it.

Only test cases with a ground-truth row are eligible — anything else can't be
scored, so sampling it wastes budget. Strata = the test case's dominant ruleId;
each stratum keeps its share of the candidates, rounded, minimum 1. Same seed +
same input = same sample every run, so results are comparable across runs.

--------------------------------------------------------------------------
WHY FILES, NOT FINDINGS
The metric that matters — a real vulnerability suppressed so nobody looks at it
again — is a property of the test case, not of one finding. A file is only
missed when *every* finding on it was called benign; one sibling called
exploitable still fails the build and rescues the file.

Sampling findings broke that in two ways:

  1. Truncation. Keeping one finding per test case threw the siblings away, so a
     file could never be rescued and every finding-level miss was scored as a
     file-level miss. Absolute miss count at finding level is always >= file
     level (195 vs 42 on the full run) — the truncated sample reported the
     larger, wrong number.

  2. Size bias. Findings-as-units means a file with 10 findings is 10x more
     likely to enter the sample than a file with 1. Files with many findings are
     exactly the ones most likely to hold a rescuing sibling, so the sample
     over-weighted the misses that don't survive file-level scoring, then
     counted every one of them.

Drawing test cases uniformly within each stratum and carrying all their findings
fixes both: each file gets one vote regardless of size, and the triage sees the
siblings it needs to rescue one.
--------------------------------------------------------------------------
"""
import json
import os
import random
import re
import sys
from collections import Counter, defaultdict

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


def dominant_rule(results):
    """The stratum key for a test case: its most-fired rule, ties by name.

    A test case can fire several rules, so it has no single ruleId to stratify
    on. Taking the most frequent one (lexicographic tiebreak, so it's stable
    across runs) keeps one stratum per rule — the same shape the finding-level
    sampler had — instead of one per rule *combination*, which would fragment
    into dozens of singleton strata that each claim their minimum of 1 and
    swamp the target sample size.
    """
    counts = Counter(r.get("ruleId", "<none>") for r in results)
    return min(counts, key=lambda rule: (-counts[rule], rule))


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

    # Original SARIF index, so the sample can be emitted in scan order below.
    order = {id(r): i for i, r in enumerate(all_results)}
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

    eligible = sorted(by_test)
    total = len(eligible)
    scoreable = sum(len(g) for g in by_test.values())

    by_rule = defaultdict(list)
    for tc in eligible:
        by_rule[dominant_rule(by_test[tc])].append(tc)

    picked = []
    for rule in sorted(by_rule):
        group = by_rule[rule]
        k = max(1, round(len(group) / total * n))
        k = min(k, len(group))
        picked.extend(rng.sample(group, k))

    # trim/pad to exactly n test cases, deterministically
    rng.shuffle(picked)
    picked = picked[:n]
    if len(picked) < n:
        chosen = set(picked)
        rest = [tc for tc in eligible if tc not in chosen]
        rng.shuffle(rest)
        picked.extend(rest[: n - len(picked)])

    tests = sorted(picked)
    # Every finding on a sampled test case, in scan order. The siblings are the
    # point: file-level scoring can't tell a rescued file from a missed one
    # without them.
    sampled = sorted(
        (r for tc in tests for r in by_test[tc]), key=lambda r: order[id(r)]
    )

    run["results"] = sampled
    with open("sample.sarif", "w") as f:
        json.dump(doc, f)

    with open("sample.csv", "w") as f:
        f.write("# test name, category, real vulnerability, cwe\n")
        for t in tests:
            f.write(truth[t] + "\n")

    multi = sum(1 for t in tests if len(by_test[t]) > 1)
    widest = max(tests, key=lambda t: len(by_test[t]))
    print(
        f"sampled {len(tests)} test cases carrying {len(sampled)} findings "
        f"from {total} candidate test cases ({scoreable} scoreable findings, "
        f"{len(all_results)} total) across {len(by_rule)} rule strata; "
        f"{multi} sampled test cases have siblings "
        f"(widest: {widest} with {len(by_test[widest])})",
        file=sys.stderr,
    )
    if len(tests) != n and total >= n:
        sys.exit(f"expected {n} distinct test cases, got {len(tests)}")

    # The triage budget is counted in findings, so the workflow has to read the
    # sampled finding count back rather than reuse the test-case count.
    print(len(sampled))
    gh_out = os.environ.get("GITHUB_OUTPUT")
    if gh_out:
        with open(gh_out, "a") as f:
            f.write(f"findings={len(sampled)}\ntestcases={len(tests)}\n")


if __name__ == "__main__":
    main(sys.argv[1], sys.argv[2], int(sys.argv[3]))

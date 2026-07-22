#!/usr/bin/env python3
"""Draw a fixed-seed, proportional sample of findings from a SARIF file.

    python3 .github/scripts/sample_sarif.py findings.sarif 100 > sample.sarif

Strata = ruleId. Each rule keeps its share of the total, rounded, minimum 1 for
any rule that appears. Same seed + same input = same sample every run, so
results are comparable across runs.
"""
import json
import random
import sys
from collections import defaultdict

SEED = 1337

def main(path, n):
    doc = json.load(open(path))
    run = doc["runs"][0]
    results = run["results"]
    total = len(results)

    by_rule = defaultdict(list)
    for r in results:
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
    json.dump(doc, sys.stdout)
    print(
        f"sampled {len(picked)} of {total} findings across {len(by_rule)} rules",
        file=sys.stderr,
    )


if __name__ == "__main__":
    main(sys.argv[1], int(sys.argv[2]))
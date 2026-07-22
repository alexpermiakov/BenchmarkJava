#!/usr/bin/env python3
"""Score sast-triage verdicts against BenchmarkJava ground truth.

    python3 score_triage.py triaged.sarif sample.csv > report.md

Prints a markdown report: confusion matrix, gate precision, retention,
noise removal, per-category breakdown, and the list of silently suppressed
real vulnerabilities (the number that matters most).

--------------------------------------------------------------------------
ADAPT THIS ONE FUNCTION: verdict_of()
It has to read a verdict out of a SARIF result. Right now it tries, in order:
  1. properties.triage.verdict  (what sast-triage@v1 actually writes)
  2. properties.verdict / properties["sast-triage"].verdict
  3. a tag that looks like "sast-triage:<verdict>"
  4. suppressions[] -> benign, as a last-resort fallback
If your triaged.sarif encodes verdicts differently, fix it here — everything
else keys off this. Any result it can't classify is reported as "unlabelled"
rather than silently miscounted.
--------------------------------------------------------------------------
"""
import argparse
import json
import re
import sys
from collections import defaultdict

VERDICTS = ("benign", "exploitable", "uncertain")
TESTCASE_RE = re.compile(r"(BenchmarkTest\d+)\.java")


def verdict_of(result):
    # The action writes the verdict to properties.triage.verdict, and adds a
    # suppressions[] entry only for benign. Read the explicit verdict first:
    # suppressions is a projection of it, so trusting it first would flatten a
    # suppressed non-benign verdict to "benign".
    props = result.get("properties") or {}
    sources = [props]
    for key in ("triage", "sast-triage", "sast_triage"):
        nested = props.get(key)
        if isinstance(nested, dict):
            sources.append(nested)

    for src in sources:
        for key in ("verdict", "triage_verdict", "sast_triage_verdict"):
            val = src.get(key)
            if isinstance(val, str) and val.lower() in VERDICTS:
                return val.lower()

    for tag in props.get("tags") or []:
        if not isinstance(tag, str):
            continue
        low = tag.lower()
        for v in VERDICTS:
            if low == v or low.endswith(":" + v):
                return v

    if result.get("suppressions"):
        return "benign"
    return None


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


def location_of(result):
    for loc in result.get("locations", []):
        phys = loc.get("physicalLocation", {})
        uri = phys.get("artifactLocation", {}).get("uri", "?")
        line = phys.get("region", {}).get("startLine", "?")
        return f"{uri}:{line}"
    return "?"


def load_truth(path):
    truth = {}
    with open(path) as f:
        for line in f:
            s = line.strip()
            if not s or s.startswith("#"):
                continue
            p = [x.strip() for x in s.split(",")]
            if len(p) < 4:
                continue
            truth[p[0]] = {
                "category": p[1],
                "real": p[2].lower() == "true",
                "cwe": p[3],
            }
    return truth


def pct(num, den):
    return f"{num / den * 100:.1f}%" if den else "n/a"


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("triaged_sarif")
    ap.add_argument("csv")
    ap.add_argument("--model", default="", help="shown in the report header")
    args = ap.parse_args()

    truth = load_truth(args.csv)
    doc = json.load(open(args.triaged_sarif))
    results = [r for run in doc.get("runs", []) for r in run.get("results", [])]

    cell = defaultdict(int)          # (verdict, is_real) -> count
    per_test = defaultdict(set)      # test -> {verdicts}
    unlabelled, unmapped = [], 0
    per_cat = defaultdict(lambda: defaultdict(int))

    for r in results:
        tc = testcase_of(r)
        if tc is None or tc not in truth:
            unmapped += 1
            continue
        v = verdict_of(r)
        if v is None:
            unlabelled.append(location_of(r))
            continue
        real = truth[tc]["real"]
        cell[(v, real)] += 1
        per_test[tc].add(v)
        per_cat[truth[tc]["category"]][(v, real)] += 1

    scored = sum(cell.values())
    if scored == 0:
        sys.exit(
            "no findings scored. Either the paths don't match the CSV, or "
            "verdict_of() can't read your verdict encoding — see the note at "
            "the top of this script."
        )

    n_benign = cell[("benign", True)] + cell[("benign", False)]
    n_expl = cell[("exploitable", True)] + cell[("exploitable", False)]
    n_unc = cell[("uncertain", True)] + cell[("uncertain", False)]

    # end-to-end per test case
    real_tests = [t for t in per_test if truth[t]["real"]]
    gated = [t for t in real_tests if "exploitable" in per_test[t]]
    parked = [
        t for t in real_tests
        if "exploitable" not in per_test[t] and "uncertain" in per_test[t]
    ]
    suppressed = sorted(
        t for t in real_tests if per_test[t] == {"benign"}
    )
    fp_tests = [t for t in per_test if not truth[t]["real"]]
    fp_gated = [t for t in fp_tests if "exploitable" in per_test[t]]

    out = print
    hdr = "# sast-triage — BenchmarkJava scorecard"
    if args.model:
        hdr += f" ({args.model})"
    out(hdr)
    out("")
    out(
        f"Scored **{scored} findings** over **{len(per_test)} test cases** — "
        f"{n_expl} exploitable, {n_benign} benign, {n_unc} uncertain."
    )
    if unmapped:
        out(f"_{unmapped} findings had no ground-truth row and were skipped._")
    if unlabelled:
        out(
            f"_⚠ {len(unlabelled)} findings carried no readable verdict "
            f"(e.g. {unlabelled[0]}) — fix `verdict_of()`._"
        )
    out("")

    out("## Verdict vs ground truth")
    out("")
    out("| verdict | real vuln | designed FP |")
    out("|---|---|---|")
    for v in VERDICTS:
        out(f"| {v} | {cell[(v, True)]} | {cell[(v, False)]} |")
    out("")

    out("## Headline numbers")
    out("")
    out("| metric | value | what it means |")
    out("|---|---|---|")
    out(
        f"| Gate precision | **{pct(cell[('exploitable', True)], n_expl)}** "
        f"({cell[('exploitable', True)]}/{n_expl}) | of blocked findings, "
        "how many were real |"
    )
    out(
        f"| False suppression rate | **{pct(cell[('benign', True)], n_benign)}** "
        f"({cell[('benign', True)]}/{n_benign}) | of benign verdicts, "
        "how many sat on a real vuln |"
    )
    out(
        f"| Noise removed | {pct(cell[('benign', False)], sum(cell[(v, False)] for v in VERDICTS))} "
        "| of the scanner's false positives, how many were cleared |"
    )
    out("")

    out("## End-to-end, per vulnerability")
    out("")
    out(
        f"Of **{len(real_tests)} real vulnerabilities the scanner surfaced**:"
    )
    out("")
    out(f"- **{len(gated)}** gated ({pct(len(gated), len(real_tests))}) — the build fails")
    out(f"- **{len(parked)}** parked as uncertain — surfaced, not blocking")
    out(
        f"- **{len(suppressed)}** silently suppressed "
        f"({pct(len(suppressed), len(real_tests))}) — **the failure mode that matters**"
    )
    out("")
    out(
        f"False alarms at the gate: **{len(fp_gated)}** of {len(fp_tests)} "
        "designed-FP test cases would block a build."
    )
    out("")

    if suppressed:
        out("### Silently suppressed real vulnerabilities")
        out("")
        out("| test case | category | CWE |")
        out("|---|---|---|")
        for t in suppressed:
            out(f"| {t} | {truth[t]['category']} | CWE-{truth[t]['cwe']} |")
        out("")

    out("## By category")
    out("")
    out("| category | findings | gate precision | false suppressions |")
    out("|---|---|---|---|")
    for cat in sorted(per_cat, key=lambda c: -sum(per_cat[c].values())):
        c = per_cat[cat]
        e = c[("exploitable", True)] + c[("exploitable", False)]
        b = c[("benign", True)] + c[("benign", False)]
        out(
            f"| {cat} | {sum(c.values())} | "
            f"{pct(c[('exploitable', True)], e)} | "
            f"{c[('benign', True)]}/{b} |"
        )
    out("")
    out(
        "<sub>Ground truth: OWASP BenchmarkJava `expectedresults-1.2.csv`. "
        "Findings are matched to test cases by file name; a finding whose rule "
        "targets a different weakness than the test case is scored against that "
        "test case anyway, which can overstate false suppressions.</sub>"
    )


if __name__ == "__main__":
    main()
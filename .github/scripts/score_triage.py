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
AND THIS TABLE: RULE_CATEGORY
A ground-truth row asserts exactly one thing: whether *this test case's
designated weakness* is real. It says nothing about any other weakness in the
same file. The scanner doesn't respect that boundary — an XSS rule fires on a
file whose row asserts SQLi — so matching findings to rows by file name alone
scores the XSS call against CWE-89. Call it benign and you're booked for a
missed SQL injection you never missed.

So each finding gets a category from its ruleId, and only findings whose
category matches the test case's are scored. The rest are reported as
off-category: real calls the triage had to make, that this corpus cannot
adjudicate either way. A scanner whose rules aren't in the table below scores
nothing, loudly, instead of scoring everything against the wrong rows.
--------------------------------------------------------------------------
"""
import argparse
import json
import re
import sys
from collections import Counter, defaultdict

VERDICTS = ("benign", "exploitable", "uncertain")
TESTCASE_RE = re.compile(r"(BenchmarkTest\d+)\.java")

# ruleId substring -> BenchmarkJava category, first match wins. Covers every
# opengrep java rule that fires on the corpus. Note BenchmarkJava splits weak
# crypto in two: `hash` is CWE-328 (SHA-1, MD5), `crypto` is CWE-327 (DES).
RULE_CATEGORY = (
    ("no-direct-response-writer", "xss"),
    ("tainted-sql-from-http-request", "sqli"),
    ("jdbc-sqli", "sqli"),
    ("httpservlet-path-traversal", "pathtraver"),
    ("weak-random", "weakrand"),
    ("tainted-cmd-from-http-request", "cmdi"),
    ("command-injection-process-builder", "cmdi"),
    ("desede-is-deprecated", "crypto"),
    ("des-is-deprecated", "crypto"),
    ("use-of-sha1", "hash"),
    ("use-of-md5", "hash"),
    ("tainted-session-from-http-request", "trustbound"),
    ("tainted-ldapi-from-http-request", "ldapi"),
    ("cookie-missing-secure-flag", "securecookie"),
    ("tainted-xpath-from-http-request", "xpathi"),
)

# Confusion-matrix rows, in the order they read best: the verdict that acts on
# a finding first, the one that buries it second. Labels are plural-neutral so
# they read the same at 0, 1 or 50.
ROWS = (
    ("exploitable", "fails the build", "✅ caught", "❌ blocked in error"),
    ("benign", "suppressed, unseen", "❌ missed", "✅ cleared"),
    ("uncertain", "left for a human", "— parked", "— parked"),
)


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


def rule_category(result):
    """The weakness class a finding's rule targets, or None if unmapped."""
    rule = (result.get("ruleId") or "").lower()
    for needle, cat in RULE_CATEGORY:
        if needle in rule:
            return cat
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


def line_of(result):
    for loc in result.get("locations", []):
        return loc.get("physicalLocation", {}).get("region", {}).get("startLine")
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


def n_of(count, word, plural=None):
    return f"{count} {word if count == 1 else plural or word + 's'}"


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("triaged_sarif")
    ap.add_argument("csv")
    ap.add_argument("--model", default="", help="shown in the report header")
    args = ap.parse_args()

    truth = load_truth(args.csv)
    doc = json.load(open(args.triaged_sarif))
    results = [r for run in doc.get("runs", []) for r in run.get("results", [])]

    cell = defaultdict(int)          # (verdict, is_real) -> count, on-category
    sink = defaultdict(set)          # (test, line) -> {verdicts}, on-category
    per_test = defaultdict(list)     # test -> [(verdict, on_category)], all
    off = defaultdict(lambda: defaultdict(int))  # (rule cat, row cat) -> verdicts
    unmapped_rules = Counter()
    unlabelled, unmapped, n_off = [], 0, 0
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
        row_cat = truth[tc]["category"]
        cat = rule_category(r)
        # Only a finding whose rule targets the weakness the row is about can be
        # scored against that row; see the note at the top of this script.
        on_category = cat == row_cat
        per_test[tc].append((v, on_category))
        if on_category:
            cell[(v, real)] += 1
            sink[(tc, line_of(r))].add(v)
            per_cat[row_cat][(v, real)] += 1
        else:
            n_off += 1
            off[(cat or "unmapped rule", row_cat)][v] += 1
            if cat is None:
                unmapped_rules[r.get("ruleId") or "<none>"] += 1

    scored = sum(cell.values())
    if scored == 0:
        sys.exit(
            "no findings scored. Either the paths don't match the CSV, "
            "verdict_of() can't read your verdict encoding, or no rule in "
            "RULE_CATEGORY matches your scanner — see the notes at the top of "
            "this script."
        )

    n_benign = cell[("benign", True)] + cell[("benign", False)]
    n_expl = cell[("exploitable", True)] + cell[("exploitable", False)]
    n_unc = cell[("uncertain", True)] + cell[("uncertain", False)]

    # Same gate precision counted over distinct sink locations. Two rules firing
    # on one line (des + desede, say) are two findings but one vulnerability, so
    # the per-finding number quietly counts the same catch twice.
    sink_expl = [k for k, vs in sink.items() if "exploitable" in vs]
    sink_expl_real = [k for k in sink_expl if truth[k[0]]["real"]]

    # end-to-end per test case. Gating is category-blind on purpose: a build
    # fails, and a human looks at the file, whatever rule raised the alarm.
    verdicts_of = {t: {v for v, _ in fs} for t, fs in per_test.items()}
    real_tests = [t for t in per_test if truth[t]["real"]]
    gated = [t for t in real_tests if "exploitable" in verdicts_of[t]]
    on_cat_gated = [
        t for t in gated if any(v == "exploitable" and on for v, on in per_test[t])
    ]
    lucky = [t for t in gated if t not in on_cat_gated]
    parked = [
        t for t in real_tests
        if "exploitable" not in verdicts_of[t] and "uncertain" in verdicts_of[t]
    ]
    suppressed = sorted(t for t in real_tests if verdicts_of[t] == {"benign"})
    # Real test cases the scanner only ever flagged for some other weakness: the
    # row's own vulnerability was never surfaced, so the triage was never asked
    # about it. They still count as gated/buried — that is a property of the
    # file, not of the rule — but they can't be credited as a catch, and when
    # they land in `suppressed` what the triage buried was unrelated noise.
    never_surfaced = {t for t in real_tests if not any(on for _, on in per_test[t])}
    blind_suppressed = [t for t in suppressed if t in never_surfaced]
    # Real test cases where some on-category finding was called benign but a
    # sibling wasn't: the file is still gated or parked, so those benign calls
    # buried nothing. These are the gap between the finding-level and file-level
    # miss numbers, and the reason the sample has to be drawn over test cases —
    # see sample_benchmark.py.
    part_benign = [
        t for t in real_tests
        if any(v == "benign" and on for v, on in per_test[t])
    ]
    rescued = [t for t in part_benign if verdicts_of[t] != {"benign"}]
    fp_tests = [t for t in per_test if not truth[t]["real"]]
    fp_gated = [t for t in fp_tests if "exploitable" in verdicts_of[t]]

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
    if n_off:
        out(
            f"_{n_off} further findings fired a rule for a weakness their test "
            "case's row says nothing about and cannot be scored either way — "
            "see [Off-category findings](#off-category-findings-not-scored)._"
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
    out(
        "Rows are what the triage said; columns are what BenchmarkJava says is "
        "true. Every test case is either a genuine flaw or a decoy built to look "
        "vulnerable to a scanner — the scanner flags both, and telling them "
        "apart is the whole job."
    )
    out("")
    out("| triage verdict | actually vulnerable | safe by design |")
    out("|---|---|---|")
    for v, note, real_lbl, fp_lbl in ROWS:
        out(
            f"| **{v}** — {note} | {cell[(v, True)]} {real_lbl} "
            f"| {cell[(v, False)]} {fp_lbl} |"
        )
    out("")
    out(
        "<sub>✅ marks the correct call, ❌ the two ways to be wrong. **Missed** "
        "is the expensive one: a real vulnerability called safe and suppressed, "
        "so nobody ever looks at it again. A false alarm only costs a build. "
        "Only findings whose rule targets the weakness the test case is built "
        "around appear here — the row can't adjudicate any other rule. These are "
        "per finding — a miss here is only a real miss if every other finding on "
        "the same file was suppressed too, which is what the per-vulnerability "
        "section below counts.</sub>"
    )
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
        f"| — per sink location | {pct(len(sink_expl_real), len(sink_expl))} "
        f"({len(sink_expl_real)}/{len(sink_expl)}) | same, counting one "
        "flagged line once however many rules fired on it |"
    )
    out(
        f"| False suppression rate | **{pct(cell[('benign', True)], n_benign)}** "
        f"({cell[('benign', True)]}/{n_benign}) | of benign verdicts, "
        "how many sat on a real vuln |"
    )
    out(
        f"| Vulnerabilities buried | **{pct(len(suppressed), len(real_tests))}** "
        f"({len(suppressed)}/{len(real_tests)}) | of real vulns, how many had "
        "*every* finding suppressed |"
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
    if lucky:
        out(
            f"{len(lucky)} of the gated test cases were gated only by a finding "
            "for a *different* weakness than the row asserts. The build still "
            "fails and a human still reads the file, but the triage was not "
            "credited with catching the vulnerability itself."
        )
        out("")
    if never_surfaced:
        one = len(never_surfaced) == 1
        para = (
            f"⚠ {n_of(len(never_surfaced), 'real test case')} "
            f"{'was' if one else 'were'} never flagged for "
            f"{'its' if one else 'their'} own weakness at all — the scanner only "
            f"fired rules for other things on {'it' if one else 'them'}, so the "
            "triage was never asked the question the row is about. "
            f"{'It is' if one else 'They are'} counted above because gating and "
            "burying are properties of the file, not of the rule that raised the "
            "alarm."
        )
        if blind_suppressed:
            para += (
                f" {len(blind_suppressed)} of those "
                f"{'sits' if len(blind_suppressed) == 1 else 'sit'} in the "
                "suppressed count: what the triage buried there was unrelated "
                "noise on a file whose real vulnerability the scanner never "
                "surfaced."
            )
        out(para)
        out("")
    if part_benign:
        n = cell[("benign", True)]
        buried = len(part_benign) - len(rescued)
        para = (
            f"Counted per finding instead, {n_of(n, 'finding')} on real "
            f"vulnerabilities {'was' if n == 1 else 'were'} called benign — "
            "findings for the weakness the row is actually about — falling on "
            f"{n_of(len(part_benign), 'test case')}. "
        )
        if rescued:
            para += (
                f"{len(rescued)} of those kept a sibling finding the triage did "
                "not suppress, so the vulnerability still reaches a human, "
                f"leaving {n_of(buried, 'file')} buried by a call on the row's "
                "own weakness. "
            )
        else:
            para += (
                "None kept a sibling the triage left standing, so "
                f"{'it' if buried == 1 else f'all {buried}'} stayed buried. "
            )
        para += (
            "Quote the file-level number, not the finding-level one: a file can "
            "carry several findings and only needs one survivor to reach a human."
        )
        out(para)
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

    if n_off:
        out("## Off-category findings (not scored)")
        out("")
        out(
            f"{n_off} findings fired a rule for a weakness their test case's "
            "ground-truth row says nothing about — an XSS rule on a file whose "
            "row asserts SQLi, say. The row can neither confirm nor refute them, "
            "so scoring them against it would invent both catches and misses. "
            "They are listed here instead."
        )
        out("")
        out("| rule targets | row asserts | findings | exploitable | benign | uncertain |")
        out("|---|---|---|---|---|---|")
        for key in sorted(off, key=lambda k: (-sum(off[k].values()), k)):
            rule_cat, row_cat = key
            c = off[key]
            out(
                f"| {rule_cat} | {row_cat} | {sum(c.values())} | "
                f"{c['exploitable']} | {c['benign']} | {c['uncertain']} |"
            )
        out("")
        if unmapped_rules:
            top = ", ".join(f"`{r}` ({n})" for r, n in unmapped_rules.most_common(5))
            out(
                f"<sub>⚠ {sum(unmapped_rules.values())} of those came from rules "
                f"with no entry in `RULE_CATEGORY` ({top}) — add them there to "
                "bring those findings into the scored set.</sub>"
            )
            out("")

    out(
        "<sub>Ground truth: OWASP BenchmarkJava `expectedresults-1.2.csv`. Each "
        "row asserts one weakness for one file, so a finding is scored only when "
        "its rule targets that same weakness; everything else is reported "
        "separately rather than scored against the wrong row. On a sampled run, "
        "test cases are drawn uniformly within each rule stratum and every "
        "finding on a drawn test case is included, so the per-vulnerability "
        "numbers above are unbiased for the full corpus.</sub>"
    )


if __name__ == "__main__":
    main()

from __future__ import annotations

import argparse
import json
import os
import sys

from . import __version__
from .core import SEVERITY_ORDER, analyze


def render_text(path, findings, meta):
    out = [f"{path}: {meta.get('stages', 0)} stage(s), final={meta.get('final')}, "
           f"{len(findings)} finding(s)"]
    for f in findings:
        out.append(f"  [{f.severity.upper():6}] {f.rule} line {f.line} stage {f.stage}  {f.path}")
        out.append(f"           {f.message}")
        out.append(f"           fix: {f.fix}")
    return "\n".join(out)


def render_md(path, findings, meta):
    out = [f"### layerghost report for `{path}`", "",
           f"{meta.get('stages', 0)} stage(s), final stage `{meta.get('final')}`, {len(findings)} finding(s).", ""]
    if findings:
        out += ["| Severity | Rule | Line | Stage | Target | Problem |", "|---|---|---|---|---|---|"]
        for f in findings:
            out.append(f"| {f.severity} | {f.rule} | {f.line} | {f.stage} | `{f.path}` | {f.message} |")
    return "\n".join(out)


def main(argv=None):
    ap = argparse.ArgumentParser(prog="layerghost",
                                 description="Find secrets a Dockerfile deletes but the image still ships.")
    ap.add_argument("dockerfile", nargs="+")
    ap.add_argument("--context", help="build context dir (enables COPY . and .dockerignore checks)")
    ap.add_argument("--target", help="stage that is built (default: last stage)")
    ap.add_argument("--bloat", action="store_true", help="also report non-secret files deleted in later layers")
    ap.add_argument("--format", choices=["text", "json", "md"], default="text")
    ap.add_argument("--fail-on", choices=list(SEVERITY_ORDER), default=None)
    ap.add_argument("--version", action="version", version=__version__)
    a = ap.parse_args(argv)

    worst = -1
    reports = []
    for p in a.dockerfile:
        text = open(p, encoding="utf-8", errors="replace").read()
        ctx = a.context or os.path.dirname(os.path.abspath(p))
        findings, meta = analyze(text, context=ctx, target=a.target, include_bloat=a.bloat)
        for f in findings:
            worst = max(worst, SEVERITY_ORDER[f.severity])
        reports.append((p, findings, meta))
    if a.format == "json":
        print(json.dumps([{"file": p, "meta": m, "findings": [f.to_dict() for f in fs]}
                          for p, fs, m in reports], indent=2))
    else:
        r = render_md if a.format == "md" else render_text
        print("\n\n".join(r(p, fs, m) for p, fs, m in reports))
    if a.fail_on and worst >= SEVERITY_ORDER[a.fail_on]:
        return 1
    return 0

"""Static model of Dockerfile layers, stages, and the files each layer leaves behind."""
from __future__ import annotations

import fnmatch
import json
import os
import posixpath
import re
import shlex
from dataclasses import dataclass, field, asdict
from typing import Dict, List, Optional, Tuple

SEVERITY_ORDER = {"info": 0, "low": 1, "medium": 2, "high": 3}

SECRET_PATH_RE = re.compile(
    r"(id_(rsa|dsa|ecdsa|ed25519)(\.pub)?$|\.pem$|\.key$|\.p12$|\.pfx$|\.jks$|\.keystore$"
    r"|(^|/)\.env(\.[\w.-]+)?$|credentials(\.json)?$|(^|/)\.npmrc$|(^|/)\.netrc$|(^|/)\.pypirc$"
    r"|(^|/)\.git-credentials$|(^|/)\.docker/config\.json$|kubeconfig|(^|/)\.kube/config$"
    r"|(^|/)\.aws/|(^|/)\.ssh/|service[-_]?account[\w.-]*\.json$|secret|token|\.htpasswd$)",
    re.I,
)
SECRET_NAME_RE = re.compile(
    r"(TOKEN|SECRET|PASSW(OR)?D|PASSWD|API_?KEY|PRIVATE_?KEY|ACCESS_?KEY|CREDENTIAL|AUTH|PAT$|_KEY$|^KEY$)",
    re.I,
)
PUBLIC_NAME_RE = re.compile(r"(PUBLIC|_URL$|_PATH$|_FILE$|_DIR$|_ID$|_HOST$)", re.I)


def is_secret_path(p: str) -> bool:
    return bool(SECRET_PATH_RE.search(p)) and not p.endswith(".pub")


def is_secret_name(n: str) -> bool:
    return bool(SECRET_NAME_RE.search(n)) and not PUBLIC_NAME_RE.search(n)


@dataclass
class Instr:
    cmd: str
    args: str
    line: int
    flags: Dict[str, str] = field(default_factory=dict)


@dataclass
class Finding:
    rule: str
    severity: str
    line: int
    stage: str
    path: str
    message: str
    fix: str

    def to_dict(self):
        return asdict(self)


# ---------------------------------------------------------------- parsing

def parse_dockerfile(text: str) -> List[Instr]:
    out: List[Instr] = []
    buf, start = "", 0
    lines = text.splitlines()
    i = 0
    while i < len(lines):
        raw = lines[i]
        s = raw.strip()
        if not buf and (not s or s.startswith("#")):
            i += 1
            continue
        if buf and s.startswith("#"):
            i += 1
            continue
        if not buf:
            start = i + 1
        if s.endswith("\\"):
            buf += s[:-1] + " "
            i += 1
            continue
        buf += s
        # heredoc: RUN <<EOF ... EOF
        m = re.search(r"<<-?\s*['\"]?(\w+)['\"]?", buf)
        if m and buf.split(None, 1)[0].upper() in ("RUN", "COPY"):
            tag = m.group(1)
            body = []
            i += 1
            while i < len(lines) and lines[i].strip() != tag:
                body.append(lines[i])
                i += 1
            buf = buf[: m.start()] + " ; ".join(body)
        out.append(_mk(buf, start))
        buf = ""
        i += 1
    if buf:
        out.append(_mk(buf, start))
    return out


def _mk(s: str, line: int) -> Instr:
    parts = s.split(None, 1)
    cmd = parts[0].upper()
    rest = parts[1] if len(parts) > 1 else ""
    flags = {}
    while True:
        m = re.match(r"--([\w-]+)(?:=(\S+))?\s*", rest)
        if not m:
            break
        flags.setdefault(m.group(1), "")
        flags[m.group(1)] = (flags[m.group(1)] + "," if flags[m.group(1)] else "") + (m.group(2) or "")
        rest = rest[m.end():]
    return Instr(cmd, rest.strip(), line, flags)


def _words(args: str) -> List[str]:
    a = args.strip()
    if a.startswith("["):
        try:
            return [str(x) for x in json.loads(a)]
        except ValueError:
            pass
    try:
        return shlex.split(a, posix=True)
    except ValueError:
        return a.split()


# ---------------------------------------------------------------- dockerignore

def _rel(p: str) -> str:
    while p.startswith("./"):
        p = p[2:]
    p = p.lstrip("/")
    return p or "."


def load_dockerignore(ctx: str) -> List[Tuple[bool, str]]:
    pats = []
    p = os.path.join(ctx, ".dockerignore")
    if os.path.exists(p):
        for ln in open(p, encoding="utf-8", errors="replace"):
            ln = ln.strip()
            if not ln or ln.startswith("#"):
                continue
            neg = ln.startswith("!")
            ln = ln[1:] if neg else ln
            pats.append((neg, _rel(ln).strip("/")))
    return pats


def ignored(rel: str, pats) -> bool:
    res = False
    for neg, pat in pats:
        hit = (fnmatch.fnmatch(rel, pat) or fnmatch.fnmatch(rel, pat + "/*")
               or fnmatch.fnmatch(rel, "**/" + pat) or rel.startswith(pat.rstrip("*") + "/")
               or ("/" not in pat and fnmatch.fnmatch(posixpath.basename(rel), pat) and pat.startswith("*")))
        if pat == "**" or pat.startswith("**/"):
            hit = hit or fnmatch.fnmatch(rel, pat[3:]) or fnmatch.fnmatch(posixpath.basename(rel), pat[3:])
        if hit:
            res = not neg
    return res


def context_files(ctx: Optional[str]) -> List[str]:
    if not ctx or not os.path.isdir(ctx):
        return []
    pats = load_dockerignore(ctx)
    out = []
    for root, dirs, files in os.walk(ctx):
        dirs[:] = [d for d in dirs if d != ".git" or not ignored(".git", pats)]
        for f in files:
            rel = os.path.relpath(os.path.join(root, f), ctx).replace(os.sep, "/")
            if rel == ".dockerignore":
                continue
            if not ignored(rel, pats):
                out.append(rel)
    return sorted(out)


# ---------------------------------------------------------------- stage model

@dataclass
class FileRec:
    path: str
    line: int
    how: str
    removed_line: Optional[int] = None
    stage: str = ""
    src: str = ""

    def secret(self) -> bool:
        return is_secret_path(self.path) or (bool(self.src) and is_secret_path(self.src))


@dataclass
class Stage:
    name: str
    index: int
    base: str
    files: Dict[str, FileRec] = field(default_factory=dict)
    history: List[FileRec] = field(default_factory=list)  # every file ever added
    args: Dict[str, Tuple[int, Optional[str]]] = field(default_factory=dict)
    envs: Dict[str, int] = field(default_factory=dict)
    arg_uses: List[Tuple[str, int]] = field(default_factory=list)
    workdir: str = "/"
    inherited_from: Optional[str] = None


CREATE_RES = [
    re.compile(r"(?<![<0-9&])>>?\s*([^\s;&|>]+)"),
    re.compile(r"\s(?:-o|--output|-O|--output-document)[ =]([^\s;&|]+)"),
    re.compile(r"\btee\s+(?:-a\s+)?([^\s;&|]+)"),
    re.compile(r"\bssh-keygen\b[^;&|]*?-f\s+([^\s;&|]+)"),
    re.compile(r"\b(?:cp|mv|install)\s+(?:-\S+\s+)*\S+\s+([^\s;&|]+)"),
]
RM_RE = re.compile(r"\b(?:rm|shred|unlink)\s+((?:-\S+\s+)*)([^;&|]+)")


def _abs(p: str, wd: str) -> str:
    p = p.strip("'\"")
    if p.startswith("~"):
        p = "/root" + p[1:]
    if not p.startswith("/"):
        p = posixpath.join(wd, p)
    return posixpath.normpath(p)


def _run_creates(cmd: str, wd: str) -> List[str]:
    out = []
    for rx in CREATE_RES:
        for m in rx.finditer(cmd):
            t = m.group(1)
            if t.startswith("/dev/") or t.startswith("&") or "$(" in t:
                continue
            out.append(_abs(t, wd))
    return out


def _run_removes(cmd: str, wd: str) -> List[str]:
    out = []
    for m in RM_RE.finditer(cmd):
        for t in m.group(2).split():
            if t.startswith("-"):
                continue
            out.append(_abs(t, wd))
    return out


def _matches(path: str, pattern: str) -> bool:
    return path == pattern or path.startswith(pattern.rstrip("/") + "/") or fnmatch.fnmatch(path, pattern)


def _var_used(name: str, text: str) -> bool:
    return bool(re.search(r"\$\{?" + re.escape(name) + r"\b", text))


def analyze(text: str, context: Optional[str] = None, target: Optional[str] = None,
            include_bloat: bool = False) -> Tuple[List[Finding], Dict]:
    instrs = parse_dockerfile(text)
    ctx_files = context_files(context)
    stages: List[Stage] = []
    by_name: Dict[str, Stage] = {}
    global_args: Dict[str, Tuple[int, Optional[str]]] = {}
    findings: List[Finding] = []
    cur: Optional[Stage] = None

    for ins in instrs:
        if ins.cmd == "FROM":
            w = ins.args.split()
            base = w[0] if w else ""
            name = w[2] if len(w) >= 3 and w[1].lower() == "as" else str(len(stages))
            cur = Stage(name=name, index=len(stages), base=base)
            if base in by_name:  # FROM another stage: inherits every layer, deleted files included
                parent = by_name[base]
                cur.inherited_from = parent.name
                ident = {}
                for v in parent.history:
                    ident[id(v)] = FileRec(**asdict(v))
                cur.history = list(ident.values())
                cur.files = {k: ident.get(id(v), FileRec(**asdict(v))) for k, v in parent.files.items()}
                cur.args = {}
                cur.envs = dict(parent.envs)
                cur.workdir = parent.workdir
            stages.append(cur)
            by_name[name] = cur
            by_name[str(cur.index)] = cur
            continue
        if cur is None:
            if ins.cmd == "ARG":
                n, _, v = ins.args.partition("=")
                global_args[n.strip()] = (ins.line, v or None)
            continue
        if ins.cmd == "WORKDIR":
            cur.workdir = _abs(ins.args.strip(), cur.workdir)
        elif ins.cmd == "ARG":
            for tok in _words(ins.args):
                n, eq, v = tok.partition("=")
                default = v if eq else (global_args.get(n, (0, None))[1])
                cur.args[n] = (ins.line, default or None)
        elif ins.cmd == "ENV":
            toks = _words(ins.args)
            if toks and "=" not in toks[0]:
                pairs = [(toks[0], " ".join(toks[1:]))]
            else:
                pairs = [tuple(t.split("=", 1)) if "=" in t else (t, "") for t in toks]
            for n, v in pairs:
                if is_secret_name(n) and v.strip() and not re.fullmatch(r"\$\{?\w+\}?", v.strip()):
                    cur.envs[n] = ins.line
                elif is_secret_name(n) and v.strip():
                    # ENV TOKEN=$TOKEN promotes a build arg into image config
                    cur.envs[n] = ins.line
        elif ins.cmd in ("COPY", "ADD"):
            w = _words(ins.args)
            if len(w) < 2:
                continue
            srcs, dest = w[:-1], w[-1]
            dest_abs = _abs(dest, cur.workdir)
            src_stage = ins.flags.get("from")
            if src_stage:
                st = by_name.get(src_stage)
                if st:
                    for s in srcs:
                        spath = _abs(s, st.workdir)
                        for p, rec in list(st.files.items()):
                            if not _matches(p, spath):
                                continue
                            rel = p[len(spath.rstrip("/")) + 1:] if p != spath else posixpath.basename(p)
                            tgt = posixpath.join(dest_abs, rel)
                            nrec = FileRec(tgt, ins.line,
                                           f"COPY --from={st.name} (it was added to {p} at line {rec.line})",
                                           stage=cur.name, src=rec.src or p)
                            cur.files[tgt] = nrec
                            cur.history.append(nrec)
                continue
            for s in srcs:
                s_norm = _rel(s)
                matched = []
                if ctx_files:
                    for rel in ctx_files:
                        if s_norm == "." or rel == s_norm or rel.startswith(s_norm.rstrip("/") + "/") \
                                or fnmatch.fnmatch(rel, s_norm):
                            matched.append(rel)
                if not matched and s_norm != "." and not s.startswith("http"):
                    matched = [s_norm]
                for rel in matched:
                    if s_norm == "." or rel.startswith(s_norm.rstrip("/") + "/"):
                        sub = rel if s_norm == "." else rel[len(s_norm.rstrip("/")) + 1:]
                        tgt = posixpath.join(dest_abs, sub)
                    elif dest.endswith("/") or len(srcs) > 1 or s_norm == ".":
                        tgt = posixpath.join(dest_abs, posixpath.basename(rel))
                    else:
                        tgt = dest_abs
                    rec = FileRec(tgt, ins.line, f"{ins.cmd} {rel}", stage=cur.name, src=rel)
                    cur.files[tgt] = rec
                    cur.history.append(rec)
        elif ins.cmd == "RUN":
            body = ins.args
            mounts = ins.flags.get("mount", "")
            for n in list(cur.args) + list(global_args):
                if _var_used(n, body):
                    cur.arg_uses.append((n, ins.line))
            created = _run_creates(body, cur.workdir)
            removed = _run_removes(body, cur.workdir)
            for p in created:
                same = any(_matches(p, r) for r in removed)
                if same:
                    continue  # created and removed inside one layer: never committed
                rec = FileRec(p, ins.line, "RUN writes", stage=cur.name)
                cur.files[p] = rec
                cur.history.append(rec)
            for r in removed:
                for p in list(cur.files):
                    if _matches(p, r):
                        f = cur.files.pop(p)
                        if f.line != ins.line:
                            f.removed_line = ins.line
            _ = mounts

    if not stages:
        return [], {"stages": 0}
    final = by_name.get(target) if target else stages[-1]
    if final is None:
        raise ValueError(f"target stage {target!r} not found")

    # which stages ship? final plus its FROM-ancestors
    shipping = set()
    s = final
    while s:
        shipping.add(s.name)
        s = by_name.get(s.inherited_from) if s.inherited_from else None

    for st in stages:
        ships = st.name in shipping
        where = "final image" if ships else "intermediate stage"
        # LG001 deleted in a later layer
        for rec in st.history:
            if rec.removed_line is None:
                continue
            secret = rec.secret()
            if not secret and not include_bloat:
                continue
            if st is not final and ships:
                continue  # reported once on the final stage that inherits it
            sev = ("high" if ships else "low") if secret else "info"
            findings.append(Finding(
                "LG001", sev, rec.line, st.name, rec.path,
                f"{rec.how} puts {rec.path} in a layer at line {rec.line}; the RUN rm at line "
                f"{rec.removed_line} only hides it, the bytes stay in the {where}"
                + (f" (inherited from stage {rec.stage})" if rec.stage != st.name else ""),
                "use RUN --mount=type=secret (or --mount=type=ssh) so the file never lands in a layer, "
                "or create, use, and delete it inside a single RUN"))
        # LG002 secret ARG consumed by RUN
        seen = set()
        for n, ln in st.arg_uses:
            if not is_secret_name(n) or (n, ln) in seen:
                continue
            seen.add((n, ln))
            default = st.args.get(n, global_args.get(n, (0, None)))[1]
            sev = "high" if ships else "low"
            findings.append(Finding(
                "LG002", sev, ln, st.name, f"ARG {n}",
                f"build arg {n} is expanded in RUN at line {ln}; its value is recorded in the {where}'s "
                f"build history (docker history shows it)" + (" and it has a literal default" if default else ""),
                "pass it with RUN --mount=type=secret,id=" + n.lower() + " and read /run/secrets/" + n.lower()))
        for n, (ln, default) in st.args.items():
            if is_secret_name(n) and default and not re.fullmatch(r"\$\{?\w+\}?", default):
                findings.append(Finding(
                    "LG002", "high", ln, st.name, f"ARG {n}",
                    f"build arg {n} has a hardcoded default value in the Dockerfile",
                    "remove the default; supply secrets at build time with --secret"))
        # LG003 ENV secrets
        for n, ln in st.envs.items():
            if st.inherited_from and n in by_name[st.inherited_from].envs and st is not final:
                continue
            findings.append(Finding(
                "LG003", "high" if ships else "low", ln, st.name, f"ENV {n}",
                f"ENV {n} bakes a credential into the {where} config; a later ENV {n}= or unset does not "
                f"remove it from earlier layers' config history",
                "inject at runtime (docker run -e / orchestrator secret) or use a build secret mount"))
        # LG004 live secret files still present in a shipping stage
        if ships and st is final:
            for p, rec in st.files.items():
                if not rec.secret():
                    continue
                if rec.how.startswith("COPY --from="):
                    findings.append(Finding(
                        "LG005", "high", rec.line, st.name, p,
                        f"{rec.how}; it ships in the final image even though the builder stage was meant "
                        f"to stay behind",
                        "copy only the build artifacts you need, or delete the secret inside the builder's RUN"))
                else:
                    findings.append(Finding(
                        "LG004", "medium", rec.line, st.name, p,
                        f"{rec.how} leaves {p} in the final image filesystem",
                        "exclude it via .dockerignore or narrow the COPY source"))

    findings.sort(key=lambda f: (-SEVERITY_ORDER[f.severity], f.line, f.rule))
    meta = {"stages": len(stages), "final": final.name, "shipping": sorted(shipping),
            "context_files": len(ctx_files)}
    return findings, meta

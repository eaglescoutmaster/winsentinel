"""winsentinel command line."""
from __future__ import annotations

import argparse
import platform
import sys
from datetime import datetime
from pathlib import Path

from . import __version__
from .config import load_config
from .findings import SEVERITIES, apply_baseline
from .pshelper import is_admin
from .report import new_report_dir, sort_findings, write_json, write_markdown, write_sarif
from .runner import Context, run_modules
from .toolchain import TOOLS, ToolError, Toolchain
from .verify import verify_findings


def _parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="winsentinel", description="Read-only Windows security scanner.")
    p.add_argument("--version", action="version", version=__version__)
    sub = p.add_subparsers(dest="cmd", required=True)

    s = sub.add_parser("scan", help="run a scan and write a report")
    g = s.add_mutually_exclusive_group()
    g.add_argument("--quick", action="store_true", help="fast triage (default)")
    g.add_argument("--full", action="store_true", help="all fixed drives, git history, code analysis")
    s.add_argument("--module", action="append", metavar="X", help="run only this module (repeatable)")
    s.add_argument("--path", action="append", metavar="P", type=Path,
                   help="scan this path instead of the default roots (files/secrets/code/ai-tooling)")
    s.add_argument("--config", type=Path, help="path to winsentinel.toml")
    s.add_argument("--update-baseline", action="store_true", help="accept current findings as the baseline")
    s.add_argument("--vt", action="store_true",
                   help="opt in: look up SHA256 hashes of flagged files on VirusTotal (needs VT_API_KEY; hashes only)")
    s.add_argument("--defender-scan", action="store_true",
                   help="also trigger a Defender quick scan in --quick mode (always on in --full)")

    t = sub.add_parser("tools", help="show or install pinned external tools")
    t.add_argument("action", choices=["status", "install"])
    t.add_argument("names", nargs="*", help="tool names (default: all)")
    t.add_argument("--config", type=Path)

    a = sub.add_parser("analyze", help="deep static analysis of one file (never executes it)")
    a.add_argument("file", type=Path)
    a.add_argument("--llm", action="store_true",
                   help="opt in: send the evidence dossier (not the file) to the Claude API for a verdict on intent")
    a.add_argument("--model", default=None, help="Claude model id for --llm")
    a.add_argument("--backend", choices=["auto", "api", "claude-code"], default="auto",
                   help="auto: API key if one is set, else the signed-in Claude Code account")
    a.add_argument("--config", type=Path)

    k = sub.add_parser("keys", help="store, check or remove API keys (Windows Credential Manager)")
    k.add_argument("action", choices=["status", "set", "remove"])
    k.add_argument("name", nargs="?", choices=["anthropic", "virustotal"])

    lg = sub.add_parser("login", help="sign in to Claude in the browser (Google works) for analyze --llm")
    lg.add_argument("--console", action="store_true", help="sign in to the API Console instead of a subscription")

    sub.add_parser("modules", help="list modules")
    return p


def _cmd_keys(args) -> int:
    import getpass

    from . import keys

    if args.action == "status":
        for name, (env, purpose, _) in keys.KEYS.items():
            _, source = keys.get(name)
            print(f"{name:11} {'set (' + source + ')' if source else 'not set':26} {purpose}")
        cc = keys.claude_status()
        state = ("signed in (" + cc["method"] + ")" if cc["logged_in"] else "not signed in: winsentinel login") \
            if cc["installed"] else "Claude Code not installed"
        print(f"{'claude':11} {state:26} analyze --llm through your Claude account")
        return 0
    if not args.name:
        print("name required: anthropic or virustotal", file=sys.stderr)
        return 2
    env, purpose, url = keys.KEYS[args.name]
    if args.action == "remove":
        print("removed" if keys.remove(args.name) else "nothing stored")
        return 0
    print(f"{args.name} key for {purpose}. Get one at {url}")
    try:
        value = getpass.getpass("Paste the key (input is hidden) and press Enter: ").strip()
    except (EOFError, KeyboardInterrupt):
        print("\ncancelled", file=sys.stderr)
        return 1
    if not value:
        print("nothing entered; nothing stored", file=sys.stderr)
        return 1
    try:
        keys.store(args.name, value)
    except Exception as e:
        print(f"could not store the key: {e}", file=sys.stderr)
        return 1
    print("stored in Windows Credential Manager for this user. Not written to any file or environment variable.")
    return 0


def _cmd_login(args) -> int:
    from . import keys

    if not keys.claude_cli():
        print("Claude Code is not installed. Install it (https://claude.com/claude-code), then run this again.\n"
              "Or use an API key instead: winsentinel keys set anthropic", file=sys.stderr)
        return 1
    print("Opening the Claude sign-in page. Choose 'Continue with Google' there if that is how you sign in.")
    rc = keys.claude_login(console=args.console)
    st = keys.claude_status()
    print("signed in: analyze --llm will use this account" if st["logged_in"] else "not signed in")
    return rc if not st["logged_in"] else 0


def _cmd_analyze(args) -> int:
    import json

    from . import analyze

    cfg = load_config(args.config)
    if not args.file.is_file():
        print(f"not a file: {args.file}", file=sys.stderr)
        return 2
    try:
        dossier = analyze.build_dossier(args.file, cfg, Toolchain(cfg.tools_dir))
    except (OSError, ValueError) as e:
        print(f"cannot analyse {args.file}: {e}", file=sys.stderr)
        return 1
    verdict = None
    if args.llm:
        backend, reason = analyze.choose_backend(args.backend)
        if not backend:
            verdict = {"error": reason}
        elif backend == "claude-code":
            print("--llm: sending the evidence dossier (strings, imports, script text; not the file) to Claude "
                  "through your signed-in Claude Code account")
            verdict = analyze.llm_verdict_claude_code(dossier, args.model)
        else:
            print("--llm: sending the evidence dossier (strings, imports, script text; not the file) to the Claude API")
            verdict = analyze.llm_verdict(dossier, args.model or analyze.DEFAULT_MODEL)
    out_dir = cfg.reports_dir / f"analyze-{datetime.now():%Y%m%d-%H%M%S}-{dossier['file']['sha256'][:8]}"
    out_dir.mkdir(parents=True, exist_ok=True)
    (out_dir / "dossier.json").write_text(json.dumps(dossier, indent=1, ensure_ascii=False), "utf-8")
    if verdict is not None:
        (out_dir / "verdict.json").write_text(json.dumps(verdict, indent=1, ensure_ascii=False), "utf-8")
    (out_dir / "analysis.md").write_text(analyze.render_markdown(dossier, verdict), "utf-8")
    f = dossier["file"]
    print(f"{f['name']}: {f['kind']}, sha256 {f['sha256']}")
    print(f"yara matches: {len(dossier['yara'])}, signature: {dossier['authenticode'].get('status')}")
    if verdict is not None:
        if "verdict" in verdict:
            print(f"llm verdict: {verdict['verdict']} (confidence {verdict['confidence']:.2f})")
        else:
            print(f"llm verdict not available: {verdict.get('error') or verdict.get('refused')}")
    else:
        print("no data left this machine (pass --llm for a Claude API verdict, or have Claude Code read analysis.md)")
    print(f"analysis: {out_dir / 'analysis.md'}")
    return 0


def _cmd_tools(args) -> int:
    cfg = load_config(args.config)
    tc = Toolchain(cfg.tools_dir)
    if args.action == "status":
        for name, where in tc.status().items():
            print(f"{name:24} {TOOLS[name].version:14} {where}")
        return 0
    rc = 0
    for name in args.names or list(TOOLS):
        if name not in TOOLS:
            print(f"unknown tool {name}", file=sys.stderr)
            rc = 2
            continue
        try:
            tc.install(name)
        except (ToolError, OSError) as e:
            print(f"FAILED {name}: {e}", file=sys.stderr)
            rc = 1
    return rc


def _cmd_scan(args) -> int:
    from .modules import REGISTRY

    cfg = load_config(args.config)
    names = args.module or list(REGISTRY)
    bad = [n for n in names if n not in REGISTRY]
    if bad:
        print(f"unknown module(s): {', '.join(bad)}. Available: {', '.join(REGISTRY)}", file=sys.stderr)
        return 2
    mode = "full" if args.full else "quick"
    report_dir = new_report_dir(cfg.reports_dir)
    ctx = Context(
        cfg=cfg, mode=mode, admin=is_admin(), tools=Toolchain(cfg.tools_dir), report_dir=report_dir,
        paths=[p.resolve() for p in (args.path or [])], vt=args.vt,
        defender_scan=args.defender_scan or mode == "full", explicit=set(args.module or []),
    )
    meta = {
        "started": datetime.now().isoformat(timespec="seconds"),
        "mode": mode,
        "admin": ctx.admin,
        "host": platform.node(),
        "os": platform.platform(),
        "modules": names,
        "not_run": [n for n in REGISTRY if n not in names],
        "paths": [str(p) for p in ctx.paths],
    }
    if not ctx.admin:
        ctx.log("not elevated: checks that need admin are skipped and listed in the report")
    results = run_modules(ctx, names)
    findings = [f for r in results for f in r.findings]

    defender_paths = set()
    d = ctx.results.get("defender")
    if d:
        defender_paths = set(d.coverage.get("_detected_paths", []))
        d.coverage.pop("_detected_paths", None)
    ctx.log("[verify] second pass on high/critical findings")
    meta["verify_downgraded"] = verify_findings(findings, cfg.trusted_signers, defender_paths)

    # A partial run must not rewrite the baseline for modules that did not run.
    partial_run = bool(args.module or args.path)
    base_path = cfg.state_dir / ("baseline.json" if not partial_run else "baseline-partial.json")
    baseline = apply_baseline(findings, base_path, update=args.update_baseline)
    meta["finished"] = datetime.now().isoformat(timespec="seconds")

    write_json(report_dir / "findings.json", meta, results, findings)
    write_sarif(report_dir / "findings.sarif", findings)
    write_markdown(report_dir / "report.md", meta, results, findings, baseline)

    counts = {s: sum(f.severity == s for f in findings) for s in SEVERITIES}
    print("findings: " + ", ".join(f"{s}={counts[s]}" for s in SEVERITIES))
    for f in sort_findings(findings)[:10]:
        print(f"  [{f.severity:8}] {f.module}: {f.title} -> {f.evidence}")
    print(f"report: {report_dir / 'report.md'}")
    return 0


def main(argv: list[str] | None = None) -> int:
    for stream in (sys.stdout, sys.stderr):
        try:
            stream.reconfigure(encoding="utf-8", errors="replace")
        except (AttributeError, ValueError):
            pass
    args = _parser().parse_args(argv)
    if args.cmd == "tools":
        return _cmd_tools(args)
    if args.cmd == "analyze":
        return _cmd_analyze(args)
    if args.cmd == "keys":
        return _cmd_keys(args)
    if args.cmd == "login":
        return _cmd_login(args)
    if args.cmd == "modules":
        from .modules import REGISTRY

        for name, mod in REGISTRY.items():
            print(f"{name:12} {mod.DESCRIPTION}")
        return 0
    return _cmd_scan(args)

"""autosbom — command-line interface for all stages.

Subcommands:
  benchmark   Stage 0: compare tool SBOM outputs against a ground-truth SPDX
  generate    Stage 1: firmware/rootfs -> CycloneDX 1.6 SBOM
  vex         Stage 2: propose / review / export VEX statements
  baseline    Stage 3: create a drift baseline inventory (sign it afterwards!)
  drift       Stage 3: run a drift sweep (one-shot or daemon)
  report      Dashboard: render the self-contained HTML report
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from . import __version__
from .common.io_utils import load_json


def _cmd_benchmark(args: argparse.Namespace) -> int:
    from .common.spdx import load_spdx_json
    from .stage0_benchmark import tool_adapters as ta
    from .stage0_benchmark.compare import compare_components
    from .stage0_benchmark.report import render_markdown

    truth = load_spdx_json(args.ground_truth)
    comparisons = []
    parsers = {
        "syft": ta.parse_syft_json,
        "trivy": ta.parse_trivy_json,
        "emba": ta.parse_emba_cyclonedx,
        "cyclonedx": ta.parse_cyclonedx_json,
    }
    for spec in args.tool_output:
        try:
            tool, path = spec.split("=", 1)
        except ValueError:
            print(f"error: --tool-output must be TOOL=PATH, got {spec!r}", file=sys.stderr)
            return 2
        if tool not in parsers:
            print(f"error: unknown tool {tool!r} (choose from {sorted(parsers)})",
                  file=sys.stderr)
            return 2
        reported = parsers[tool](path)
        comparisons.append(compare_components(reported, truth, target=args.target_name))

    md = render_markdown(comparisons, title=args.title,
                         notes=f"Ground truth: `{args.ground_truth}`")
    if args.output:
        Path(args.output).write_text(md, encoding="utf-8")
        print(f"wrote {args.output}")
    else:
        print(md)
    if args.json_output:
        Path(args.json_output).write_text(
            json.dumps([c.to_dict() for c in comparisons], indent=2), encoding="utf-8")
        print(f"wrote {args.json_output}")
    return 0


def _cmd_generate(args: argparse.Namespace) -> int:
    from .stage1_generator.generate import generate, save_result

    result = generate(args.target, args.workdir, args.yocto_metadata)
    paths = save_result(result, args.output_dir)
    for note in result.notes:
        print(f"note: {note}")
    for kind, p in paths.items():
        print(f"wrote {kind}: {p}")
    return 0


def _cmd_vex(args: argparse.Namespace) -> int:
    from .common.models import Vulnerability
    from .stage0_benchmark import tool_adapters as ta
    from .stage2_vex.context import DeviceContext
    from .stage2_vex.openvex import export_openvex
    from .stage2_vex.review import ReviewError, ReviewStore
    from .stage2_vex.rules import RuleEngine

    store = ReviewStore.load(args.review_store)

    if args.vex_command == "propose":
        context = DeviceContext.load(args.context)
        annotations = {}
        if args.annotations:
            annotations = load_json(args.annotations)
            if not isinstance(annotations, dict):
                print(f"error: {args.annotations}: expected a JSON object "
                      f"of CVE annotations", file=sys.stderr)
                return 2
        if args.findings.endswith(".grype.json") or args.findings_format == "grype":
            findings_sbom = ta.parse_grype_json(args.findings)
        elif args.findings_format == "trivy":
            findings_sbom = ta.parse_trivy_json(args.findings)
        else:
            data = load_json(args.findings)
            if not isinstance(data, list):
                print(f"error: {args.findings}: raw findings format expects "
                      f"a JSON list", file=sys.stderr)
                return 2
            findings_sbom = type("S", (), {})()
            findings_sbom.vulnerabilities = [Vulnerability.from_dict(d) for d in data]
        engine = RuleEngine(context=context, backport_annotations=annotations)
        proposals = engine.evaluate_all(findings_sbom.vulnerabilities)
        added = store.add_proposals(proposals)
        store.save()
        print(f"{len(proposals)} proposals generated, {added} new, "
              f"{len(store.pending())} now pending human review")
        print("NOTE: nothing is suppressed until a human approves each proposal "
              "(autosbom vex approve ...).")
        return 0

    if args.vex_command == "list":
        for p in store.proposals:
            print(f"[{p.state:8}] {p.cve_id:18} {p.component:20} "
                  f"-> {p.proposed_status} ({p.rule})")
        return 0

    if args.vex_command in ("approve", "reject"):
        try:
            fn = store.approve if args.vex_command == "approve" else store.reject
            fn(args.cve, args.component, args.reviewer, args.note)
        except ReviewError as exc:
            print(f"error: {exc}", file=sys.stderr)
            return 1
        store.save()
        print(f"{args.vex_command}d {args.cve} / {args.component} "
              f"(reviewer: {args.reviewer})")
        return 0

    if args.vex_command == "export":
        approved = store.approved()
        if not approved:
            print("no approved proposals to export — nothing suppressed.",
                  file=sys.stderr)
            return 1
        doc = export_openvex(approved, author=args.author,
                             product_purl=args.product_purl)
        Path(args.output).write_text(json.dumps(doc, indent=2), encoding="utf-8")
        print(f"wrote {args.output} ({len(approved)} approved statements)")
        return 0

    print("error: unknown vex subcommand", file=sys.stderr)
    return 2


def _cmd_baseline(args: argparse.Namespace) -> int:
    from .stage3_drift.daemon import create_baseline

    inv = create_baseline(args.output, args.lib_dirs)
    print(f"baseline written: {args.output}")
    print(f"  {len(inv.shared_libraries)} shared libraries hashed")
    print(f"  {len(inv.packages)} packages")
    print(f"  {len(inv.kernel_modules)} kernel modules")
    print("NEXT STEP: sign this baseline (signing/sign_baseline.sh) — the drift "
          "daemon rejects unsigned baselines by default.")
    return 0


def _cmd_drift(args: argparse.Namespace) -> int:
    from .stage3_drift.daemon import DaemonConfig, run_forever, run_once
    from .stage3_drift.verify import VerificationPolicy

    policy = VerificationPolicy(
        require_signature=not args.allow_unverified_baseline,
        certificate_identity=args.certificate_identity or "",
        public_key_path=args.public_key or "",
    )
    cfg = DaemonConfig(
        baseline_path=Path(args.baseline),
        signature_path=Path(args.signature) if args.signature else None,
        event_log_path=Path(args.event_log),
        poll_interval_seconds=args.interval,
        lib_dirs=args.lib_dirs,
        policy=policy,
    )
    if args.allow_unverified_baseline:
        print("WARNING: running with an UNVERIFIED baseline (development mode). "
              "Drift results must not be used for integrity claims.",
              file=sys.stderr)
    if args.once:
        records = run_once(cfg)
        drift = [r for r in records if r.get("kind") != "sweep-complete"]
        print(f"sweep complete: {len(drift)} drift events "
              f"(log: {args.event_log})")
        for r in drift[:20]:
            print(f"  [{r.get('severity')}] {r.get('kind')}: {r.get('subject')}")
        return 0 if not drift else 3
    run_forever(cfg)
    return 0


def _cmd_report(args: argparse.Namespace) -> int:
    from .stage0_benchmark import tool_adapters as ta
    from .dashboard.html_report import load_drift_log, render_report

    sbom = ta.parse_cyclonedx_json(args.sbom, tool_name="autosbom-sentinel")
    sbom.target = args.target_name or sbom.target
    vulns = []
    if args.findings:
        if args.findings_format == "trivy":
            vulns = ta.parse_trivy_json(args.findings).vulnerabilities
        else:
            vulns = ta.parse_grype_json(args.findings).vulnerabilities
    suppressed: set[str] = set()
    if args.review_store:
        from .stage2_vex.review import ReviewStore
        suppressed = ReviewStore.load(args.review_store).suppressed_cves()
    drift_events = load_drift_log(args.drift_log) if args.drift_log else []
    baseline_verified = None
    if drift_events:
        baseline_verified = all(
            e.get("baseline_verified", False)
            for e in drift_events if "baseline_verified" in e
        ) or False
    html_text = render_report(
        sbom, vulns, suppressed, drift_events,
        baseline_verified=baseline_verified, title=args.title,
    )
    Path(args.output).write_text(html_text, encoding="utf-8")
    print(f"wrote {args.output}")
    return 0


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="autosbom",
                                description="AutoSBOM Sentinel (portfolio project)")
    p.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    sub = p.add_subparsers(dest="command", required=True)

    b = sub.add_parser("benchmark", help="Stage 0: score tool outputs vs ground truth")
    b.add_argument("--ground-truth", required=True, help="SPDX JSON ground-truth SBOM")
    b.add_argument("--tool-output", action="append", required=True,
                   metavar="TOOL=PATH", help="e.g. syft=out.json (repeatable)")
    b.add_argument("--target-name", default="", help="label for the target image")
    b.add_argument("--title", default="Stage 0 Benchmark Results")
    b.add_argument("--output", help="write markdown report here (default: stdout)")
    b.add_argument("--json-output", help="also write raw comparison JSON here")
    b.set_defaults(func=_cmd_benchmark)

    g = sub.add_parser("generate", help="Stage 1: firmware/rootfs -> CycloneDX SBOM")
    g.add_argument("target", help="firmware image file or extracted rootfs directory")
    g.add_argument("--workdir", default="./autosbom-work")
    g.add_argument("--output-dir", default="./autosbom-out")
    g.add_argument("--yocto-metadata",
                   help="Yocto layer/build dir to scan for CVE_STATUS annotations")
    g.set_defaults(func=_cmd_generate)

    v = sub.add_parser("vex", help="Stage 2: propose/review/export VEX")
    v.add_argument("--review-store", default="./vex-review.json")
    vsub = v.add_subparsers(dest="vex_command", required=True)
    vp = vsub.add_parser("propose", help="run rules engine -> pending proposals")
    vp.add_argument("--findings", required=True,
                    help="grype/trivy JSON, or a JSON list of findings")
    vp.add_argument("--findings-format", choices=["grype", "trivy", "raw"],
                    default="grype")
    vp.add_argument("--context", required=True, help="device-context JSON/YAML")
    vp.add_argument("--annotations",
                    help="backport-annotations.json from Stage 1")
    vsub.add_parser("list", help="list proposals and their review state")
    for action in ("approve", "reject"):
        va = vsub.add_parser(action, help=f"{action} one proposal")
        va.add_argument("--cve", required=True)
        va.add_argument("--component", required=True)
        va.add_argument("--reviewer", required=True,
                        help="your name — recorded in the review store")
        va.add_argument("--note", default="")
    ve = vsub.add_parser("export", help="export APPROVED proposals as OpenVEX")
    ve.add_argument("--output", required=True)
    ve.add_argument("--author", required=True)
    ve.add_argument("--product-purl", required=True,
                    help="purl of the product the VEX applies to")
    v.set_defaults(func=_cmd_vex)

    bl = sub.add_parser("baseline", help="Stage 3: create drift baseline inventory")
    bl.add_argument("--output", required=True)
    bl.add_argument("--lib-dirs", nargs="*", default=None)
    bl.set_defaults(func=_cmd_baseline)

    d = sub.add_parser("drift", help="Stage 3: drift sweep (one-shot or daemon)")
    d.add_argument("--baseline", required=True)
    d.add_argument("--signature", help="cosign signature file for the baseline")
    d.add_argument("--certificate-identity",
                   help="expected keyless cert identity for verification")
    d.add_argument("--public-key", help="cosign public key (key-based verification)")
    d.add_argument("--allow-unverified-baseline", action="store_true",
                   help="DEVELOPMENT ONLY: skip signature verification")
    d.add_argument("--event-log", default="./drift-events.jsonl")
    d.add_argument("--interval", type=int, default=300)
    d.add_argument("--lib-dirs", nargs="*", default=None)
    d.add_argument("--once", action="store_true", help="single sweep, then exit")
    d.set_defaults(func=_cmd_drift)

    r = sub.add_parser("report", help="render the self-contained HTML report")
    r.add_argument("--sbom", required=True, help="CycloneDX JSON from Stage 1")
    r.add_argument("--findings", help="grype/trivy findings JSON")
    r.add_argument("--findings-format", choices=["grype", "trivy"], default="grype")
    r.add_argument("--review-store", help="VEX review store (approved = suppressed)")
    r.add_argument("--drift-log", help="drift-events.jsonl from Stage 3")
    r.add_argument("--target-name", default="")
    r.add_argument("--title", default="AutoSBOM Sentinel — Build Report")
    r.add_argument("--output", required=True)
    r.set_defaults(func=_cmd_report)

    return p


# Exceptions the CLI treats as expected operational failures (a bad file, a
# missing tool, a permissions problem) — reported as a clean one-line error
# instead of a Python traceback. Anything else is a real bug and is left to
# surface with its full traceback so it doesn't get silently swallowed.
_OPERATIONAL_ERRORS = (
    FileNotFoundError, NotADirectoryError, IsADirectoryError, PermissionError,
    ValueError, RuntimeError,
)


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        return args.func(args)
    except _OPERATIONAL_ERRORS as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())

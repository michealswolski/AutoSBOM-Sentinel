"""Render Stage 0 benchmark results as a markdown report."""
from __future__ import annotations

from .compare import ComponentComparison, CveComparison


def render_markdown(
    comparisons: list[ComponentComparison],
    cve_comparisons: list[CveComparison] | None = None,
    title: str = "Stage 0 Benchmark Results",
    notes: str = "",
) -> str:
    lines = [f"# {title}", ""]
    if notes:
        lines += [notes, ""]

    lines += [
        "## Component identification (vs. ground-truth SBOM)",
        "",
        "| Tool | Target | Precision | Recall | F1 | FP | FN | Version mismatches | Unknown-version reports |",
        "|---|---|---|---|---|---|---|---|---|",
    ]
    for c in comparisons:
        lines.append(
            f"| {c.tool} | {c.target} | {c.precision:.1%} | {c.recall:.1%} | "
            f"{c.f1:.2f} | {len(c.false_positives)} | {len(c.false_negatives)} | "
            f"{len(c.version_mismatches)} | {len(c.unknown_version_reports)} |"
        )
    lines.append("")

    for c in comparisons:
        examples = []
        if c.false_positives:
            examples.append(
                f"- **False positives** (reported, not in ground truth): "
                f"`{'`, `'.join(c.false_positives[:5])}`"
                + (" …" if len(c.false_positives) > 5 else "")
            )
        if c.false_negatives:
            examples.append(
                f"- **False negatives** (in ground truth, missed): "
                f"`{'`, `'.join(c.false_negatives[:5])}`"
                + (" …" if len(c.false_negatives) > 5 else "")
            )
        if c.version_mismatches:
            vm = c.version_mismatches[0]
            examples.append(
                f"- **Version mismatch example**: `{vm[0]}` reported as "
                f"`{vm[1]}`, ground truth `{vm[2]}` — this is the mechanism "
                f"behind backport-driven CVE false positives."
            )
        if c.unknown_version_reports:
            examples.append(
                f"- **Unknown-version reports** (stripped-binary failure mode): "
                f"`{'`, `'.join(c.unknown_version_reports[:5])}`"
            )
        if examples:
            lines += [f"### {c.tool} — worked examples ({c.target})", ""] + examples + [""]

    if cve_comparisons:
        lines += [
            "## CVE accuracy (vs. manually-verified sample)",
            "",
            "Only CVEs that were manually verified are scored; unverified",
            "reports are excluded rather than guessed at.",
            "",
            "| Tool | Precision | Recall | FP (with reason) | FN |",
            "|---|---|---|---|---|",
        ]
        for c in cve_comparisons:
            fp_str = "; ".join(f"{cve} ({reason})" for cve, reason in c.false_positives[:4])
            lines.append(
                f"| {c.tool} | {c.precision:.1%} | {c.recall:.1%} | "
                f"{fp_str or '—'} | {', '.join(c.false_negatives) or '—'} |"
            )
        lines.append("")

    return "\n".join(lines)

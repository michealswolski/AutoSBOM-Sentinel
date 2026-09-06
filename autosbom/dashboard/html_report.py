"""Self-contained HTML report: heatmap, VEX before/after, drift timeline.

One file, no external assets, openable anywhere — the per-build shareable
artifact (the live Dependency-Track instance is separate; see dashboard/README
in the repo root for wiring CycloneDX + VEX output into it).

Charts follow a validated palette: two-series comparisons use categorical
slots 1-2 (blue/orange), magnitude uses the one-hue blue sequential ramp,
drift severity uses reserved status colors always paired with an icon+label.
Each chart ships a data-table fallback for accessibility.
"""
from __future__ import annotations

import html
import json
from datetime import datetime, timezone

from ..common.models import Sbom, Vulnerability
from .heatmap import HeatmapCell, build_heatmap

# Sequential blue ramp (light mode steps 100->700) for magnitude encoding.
_SEQ_LIGHT = ["#cde2fb", "#9ec5f4", "#6da7ec", "#3987e5", "#256abf", "#184f95", "#0d366b"]
_SEQ_DARK = ["#104281", "#184f95", "#1c5cab", "#256abf", "#2a78d6", "#3987e5", "#5598e7"]


def _seq_color(value: int, max_value: int, steps: list[str]) -> str:
    if max_value <= 0 or value <= 0:
        return "var(--cell-zero)"
    idx = min(len(steps) - 1, int((value / max_value) * (len(steps) - 1) + 0.5))
    return steps[idx]


_CSS = """
:root {
  color-scheme: light;
  --surface-1: #fcfcfb; --page: #f9f9f7;
  --ink-1: #0b0b0b; --ink-2: #52514e; --ink-muted: #898781;
  --grid: #e1e0d9; --baseline: #c3c2b7;
  --series-1: #2a78d6; --series-2: #eb6834;
  --status-critical: #d03b3b; --status-warning: #fab219; --status-good: #0ca30c;
  --cell-zero: #f0efec; --border: rgba(11,11,11,0.10);
}
@media (prefers-color-scheme: dark) {
  :root:where(:not([data-theme="light"])) {
    color-scheme: dark;
    --surface-1: #1a1a19; --page: #0d0d0d;
    --ink-1: #ffffff; --ink-2: #c3c2b7; --ink-muted: #898781;
    --grid: #2c2c2a; --baseline: #383835;
    --series-1: #3987e5; --series-2: #d95926;
    --cell-zero: #232322; --border: rgba(255,255,255,0.10);
  }
}
:root[data-theme="dark"] {
  color-scheme: dark;
  --surface-1: #1a1a19; --page: #0d0d0d;
  --ink-1: #ffffff; --ink-2: #c3c2b7; --ink-muted: #898781;
  --grid: #2c2c2a; --baseline: #383835;
  --series-1: #3987e5; --series-2: #d95926;
  --cell-zero: #232322; --border: rgba(255,255,255,0.10);
}
* { box-sizing: border-box; }
body {
  margin: 0; padding: 24px; background: var(--page); color: var(--ink-1);
  font: 14px/1.5 system-ui, -apple-system, "Segoe UI", sans-serif;
}
main { max-width: 960px; margin: 0 auto; }
h1 { font-size: 22px; margin: 0 0 4px; }
h2 { font-size: 16px; margin: 32px 0 8px; }
.sub { color: var(--ink-2); margin: 0 0 20px; }
.card {
  background: var(--surface-1); border: 1px solid var(--border);
  border-radius: 8px; padding: 20px; margin: 12px 0;
}
.legend { display: flex; gap: 16px; margin: 8px 0 12px; color: var(--ink-2); font-size: 13px; }
.legend .chip { display: inline-block; width: 10px; height: 10px; border-radius: 3px; margin-right: 6px; }
.bar-row { display: grid; grid-template-columns: 140px 1fr; align-items: center; gap: 10px; margin: 6px 0; }
.bar-label { color: var(--ink-2); font-size: 13px; text-align: right; }
.bar-track { position: relative; height: 34px; }
.bar {
  position: absolute; left: 0; height: 14px; border-radius: 0 4px 4px 0;
  min-width: 2px;
}
.bar.raw { top: 2px; background: var(--series-1); }
.bar.post { top: 18px; background: var(--series-2); }
.bar-val {
  position: absolute; font-size: 11px; color: var(--ink-2);
  transform: translateY(-1px); padding-left: 6px; white-space: nowrap;
}
.heat-grid { display: grid; grid-template-columns: repeat(7, 1fr); gap: 2px; }
.heat-cell {
  border-radius: 4px; padding: 10px 8px; min-height: 92px;
  display: flex; flex-direction: column; justify-content: space-between;
  background: var(--cell-zero); border: 1px solid var(--border);
}
.heat-cat { font-size: 11px; color: var(--ink-2); word-break: break-word; }
.heat-num { font-size: 20px; font-weight: 600; }
.heat-meta { font-size: 10px; color: var(--ink-muted); }
.heat-cell.hot .heat-cat, .heat-cell.hot .heat-num, .heat-cell.hot .heat-meta { color: #ffffff; }
.evt { display: grid; grid-template-columns: 170px 110px 1fr; gap: 10px; padding: 7px 0; border-bottom: 1px solid var(--grid); font-size: 13px; }
.evt:last-child { border-bottom: 0; }
.evt time { color: var(--ink-muted); font-variant-numeric: tabular-nums; }
.badge { font-weight: 600; }
.badge.critical { color: var(--status-critical); }
.badge.warning { color: var(--status-warning); }
.badge.ok { color: var(--status-good); }
details { margin-top: 12px; }
summary { cursor: pointer; color: var(--ink-2); font-size: 13px; }
table { border-collapse: collapse; margin-top: 8px; width: 100%; font-size: 13px; }
th, td { text-align: left; padding: 4px 10px 4px 0; border-bottom: 1px solid var(--grid); }
th { color: var(--ink-2); font-weight: 600; }
td.num, th.num { text-align: right; font-variant-numeric: tabular-nums; }
.verified { display: inline-flex; align-items: center; gap: 6px; font-size: 13px; }
.footnote { color: var(--ink-muted); font-size: 12px; margin-top: 24px; }
[hidden] { display: none !important; }
"""


def _esc(s: str) -> str:
    return html.escape(str(s), quote=True)


def _vex_chart(cells: list[HeatmapCell]) -> str:
    max_val = max((c.cve_count for c in cells), default=0) or 1
    rows = []
    for c in cells:
        raw_w = 100.0 * c.cve_count / max_val
        post_w = 100.0 * c.actionable_cve_count / max_val
        rows.append(
            f'<div class="bar-row">'
            f'<div class="bar-label">{_esc(c.category)}</div>'
            f'<div class="bar-track" title="{_esc(c.category)}: '
            f'{c.cve_count} raw, {c.actionable_cve_count} after approved VEX">'
            f'<div class="bar raw" style="width:{raw_w:.1f}%"></div>'
            f'<div class="bar-val" style="top:2px;left:{raw_w:.1f}%">{c.cve_count}</div>'
            f'<div class="bar post" style="width:{post_w:.1f}%"></div>'
            f'<div class="bar-val" style="top:18px;left:{post_w:.1f}%">{c.actionable_cve_count}</div>'
            f"</div></div>"
        )
    table = ["<details><summary>Data table</summary><table>",
             "<tr><th>Category</th><th class=num>Raw CVEs</th>"
             "<th class=num>Suppressed (approved VEX)</th><th class=num>Actionable</th></tr>"]
    for c in cells:
        table.append(
            f"<tr><td>{_esc(c.category)}</td><td class=num>{c.cve_count}</td>"
            f"<td class=num>{c.suppressed_cve_count}</td>"
            f"<td class=num>{c.actionable_cve_count}</td></tr>"
        )
    table.append("</table></details>")
    return (
        '<div class="legend">'
        '<span><span class="chip" style="background:var(--series-1)"></span>Raw CVE count</span>'
        '<span><span class="chip" style="background:var(--series-2)"></span>Actionable after approved VEX</span>'
        "</div>" + "".join(rows) + "".join(table)
    )


def _heatmap_html(cells: list[HeatmapCell]) -> str:
    max_val = max((c.actionable_cve_count for c in cells), default=0)
    out = ['<div class="heat-grid">']
    for c in cells:
        light = _seq_color(c.actionable_cve_count, max_val, _SEQ_LIGHT)
        # "hot" (white ink) when the fill is in the darker half of the ramp
        hot = (
            light in _SEQ_LIGHT[3:]
        )
        style = f"background:{light}" if light != "var(--cell-zero)" else ""
        out.append(
            f'<div class="heat-cell{" hot" if hot else ""}" style="{style}" '
            f'title="{_esc(c.category)}: {c.component_count} components, '
            f'{c.actionable_cve_count} actionable CVEs (max CVSS {c.max_cvss:.1f})">'
            f'<div class="heat-cat">{_esc(c.category)}</div>'
            f'<div class="heat-num">{c.actionable_cve_count}</div>'
            f'<div class="heat-meta">{c.component_count} comp · max CVSS {c.max_cvss:.1f}</div>'
            f"</div>"
        )
    out.append("</div>")
    out.append("<details><summary>Data table</summary><table>"
               "<tr><th>Category</th><th class=num>Components</th>"
               "<th class=num>Actionable CVEs</th><th class=num>Max CVSS</th></tr>")
    for c in cells:
        out.append(
            f"<tr><td>{_esc(c.category)}</td><td class=num>{c.component_count}</td>"
            f"<td class=num>{c.actionable_cve_count}</td>"
            f"<td class=num>{c.max_cvss:.1f}</td></tr>"
        )
    out.append("</table></details>")
    return "".join(out)


def _timeline_html(drift_events: list[dict]) -> str:
    if not drift_events:
        return '<p class="sub">No drift events recorded.</p>'
    rows = []
    shown = drift_events[-200:]
    for e in shown:
        kind = e.get("kind", "")
        sev = e.get("severity", "")
        if kind == "sweep-complete":
            badge = '<span class="badge ok">✓ clean sweep</span>'
            detail = (f"{e.get('libraries_checked', 0)} libs, "
                      f"{e.get('packages_checked', 0)} pkgs, "
                      f"{e.get('kernel_modules_checked', 0)} kmods checked")
            if e.get("drift_events", 0):
                badge = '<span class="badge warning">⚠ sweep w/ drift</span>'
                detail = f"{e['drift_events']} drift events this sweep"
        elif sev == "critical":
            badge = '<span class="badge critical">✖ critical</span>'
            detail = f"{_esc(kind)}: {_esc(e.get('subject', ''))} {_esc(e.get('detail', ''))}"
        else:
            badge = '<span class="badge warning">⚠ warning</span>'
            detail = f"{_esc(kind)}: {_esc(e.get('subject', ''))} {_esc(e.get('detail', ''))}"
        rows.append(
            f'<div class="evt"><time>{_esc(e.get("timestamp", ""))}</time>'
            f"{badge}<span>{detail}</span></div>"
        )
    note = ""
    if len(drift_events) > len(shown):
        note = (f'<p class="sub">Showing last {len(shown)} of '
                f"{len(drift_events)} events.</p>")
    return note + "".join(rows)


def render_report(
    sbom: Sbom,
    vulnerabilities: list[Vulnerability] | None = None,
    suppressed_cves: set[str] | None = None,
    drift_events: list[dict] | None = None,
    baseline_verified: bool | None = None,
    title: str = "AutoSBOM Sentinel — Build Report",
) -> str:
    """Render the full self-contained HTML report and return it as a string."""
    cells = build_heatmap(sbom, vulnerabilities, suppressed_cves)
    generated = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    n_comp = len(sbom.components)
    vulns = vulnerabilities if vulnerabilities is not None else sbom.vulnerabilities
    n_cve = len({v.cve_id for v in vulns})
    n_sup = len(suppressed_cves or set())
    flagged = sum(1 for c in sbom.components if "needs-manual-review" in c.flags)

    if baseline_verified is True:
        verify_html = ('<span class="verified"><span class="badge ok">✓</span> '
                       "drift baseline signature verified (cosign)</span>")
    elif baseline_verified is False:
        verify_html = ('<span class="verified"><span class="badge critical">✖</span> '
                       "drift baseline UNVERIFIED — development mode</span>")
    else:
        verify_html = ""

    return f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>{_esc(title)}</title><style>{_CSS}</style></head><body><main>
<h1>{_esc(title)}</h1>
<p class="sub">Target: <strong>{_esc(sbom.target or "unknown")}</strong> ·
{n_comp} components ({flagged} flagged for manual review) ·
{n_cve} unique CVEs reported · {n_sup} suppressed by <em>approved</em> VEX ·
generated {generated}</p>
{verify_html}

<div class="card">
<h2 style="margin-top:0">Attack-surface heatmap</h2>
<p class="sub">Actionable CVEs (post-approved-VEX) grouped by exposure
category — the automotive view, not the package-name view.</p>
{_heatmap_html(cells)}
</div>

<div class="card">
<h2 style="margin-top:0">CVE noise reduction — raw vs. post-VEX</h2>
<p class="sub">Only human-approved VEX statements count as suppression;
pending proposals still show as raw findings.</p>
{_vex_chart(cells)}
</div>

<div class="card">
<h2 style="margin-top:0">Runtime drift timeline</h2>
{_timeline_html(drift_events or [])}
</div>

<p class="footnote">Personal portfolio project — generated by autosbom-sentinel
{_esc(sbom.tool_version)}. Not a production compliance system.</p>
</main></body></html>
"""


def load_drift_log(path: str) -> list[dict]:
    events = []
    try:
        with open(path, encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if line:
                    events.append(json.loads(line))
    except FileNotFoundError:
        pass
    return events

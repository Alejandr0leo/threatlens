"""
report.py — Genera reportes de Threat Intelligence en Markdown y JSON.
"""

from __future__ import annotations

import json
from dataclasses import asdict

from .engine import IOCResult

_EMOJI = {
    "MALICIOSO": "🔴", "SOSPECHOSO": "🟠", "BAJO": "🟡",
    "LIMPIO": "🟢", "INFORMATIVO": "🔵", "DESCONOCIDO": "⚪", "INVÁLIDO": "⚫",
}


def to_markdown(results: list[IOCResult]) -> str:
    lines = ["# Reporte de Threat Intelligence — ThreatLens", ""]
    total = len(results)
    mal = sum(1 for r in results if r.verdict == "MALICIOSO")
    susp = sum(1 for r in results if r.verdict == "SOSPECHOSO")
    lines += [
        f"- IOCs analizados: **{total}**",
        f"- Maliciosos: **{mal}**  ·  Sospechosos: **{susp}**",
        "",
        "| IOC | Tipo | Veredicto | Puntaje |",
        "|---|---|---|---|",
    ]
    for r in results:
        emoji = _EMOJI.get(r.verdict, "")
        lines.append(f"| `{r.ioc}` | {r.kind} | {emoji} {r.verdict} | {r.score} |")

    lines += ["", "---", "", "## Detalle por IOC", ""]
    for r in results:
        lines.append(f"### {_EMOJI.get(r.verdict, '')} `{r.ioc}`  ({r.kind} · {r.verdict} · {r.score})")
        for s in r.results:
            if s.status == "skipped":
                continue
            link = f" — [{s.link}]({s.link})" if s.link else ""
            lines.append(f"- **{s.source}** · `{s.status}` · {s.detail}{link}")
        lines.append("")
    return "\n".join(lines)


def to_json(results: list[IOCResult]) -> str:
    return json.dumps([asdict(r) for r in results], ensure_ascii=False, indent=2)

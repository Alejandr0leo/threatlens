"""
cli.py — Enriquece IOCs desde la terminal.

Uso:
    python cli.py --file data/sample_iocs.txt
    python cli.py 8.8.8.8 evil-domain.com --json out.json
    python cli.py --file iocs.txt --markdown reporte.md
"""

import argparse
import os

from threatlens import enrich_many, parse_iocs
from threatlens.report import to_markdown, to_json, _EMOJI

_COLOR = {"MALICIOSO": "\033[91m", "SOSPECHOSO": "\033[93m", "BAJO": "\033[33m",
          "LIMPIO": "\033[92m", "INFORMATIVO": "\033[94m",
          "DESCONOCIDO": "\033[90m", "INVÁLIDO": "\033[90m"}
_RESET = "\033[0m"


def main():
    ap = argparse.ArgumentParser(description="ThreatLens — enriquecimiento de IOCs")
    ap.add_argument("iocs", nargs="*", help="IOCs sueltos (IP, dominio o hash)")
    ap.add_argument("--file", help="archivo con IOCs (uno por línea)")
    ap.add_argument("--json", help="guardar reporte JSON")
    ap.add_argument("--markdown", help="guardar reporte Markdown")
    ap.add_argument("--no-color", action="store_true")
    args = ap.parse_args()

    raws = list(args.iocs)
    if args.file:
        with open(args.file) as fh:
            raws += parse_iocs(fh.read())
    if not raws:
        ap.error("Indica IOCs como argumentos o con --file")

    print(f"Analizando {len(raws)} IOC(s)...\n")
    results = enrich_many(raws)

    for r in results:
        c = "" if args.no_color else _COLOR.get(r.verdict, "")
        reset = "" if args.no_color else _RESET
        emoji = _EMOJI.get(r.verdict, "")
        print(f"{c}{emoji} {r.verdict:11}{reset} [{r.score:3}] {r.ioc}  ({r.kind})")
        for s in r.results:
            if s.status in ("skipped", "not_found"):
                continue
            print(f"      └ {s.source}: {s.detail}")
        print()

    mal = sum(1 for r in results if r.verdict == "MALICIOSO")
    susp = sum(1 for r in results if r.verdict == "SOSPECHOSO")
    print(f"Resumen: {mal} malicioso(s), {susp} sospechoso(s) de {len(results)} IOC(s).")

    if args.json:
        os.makedirs(os.path.dirname(args.json) or ".", exist_ok=True)
        with open(args.json, "w") as f:
            f.write(to_json(results))
        print(f"Reporte JSON: {args.json}")
    if args.markdown:
        os.makedirs(os.path.dirname(args.markdown) or ".", exist_ok=True)
        with open(args.markdown, "w") as f:
            f.write(to_markdown(results))
        print(f"Reporte Markdown: {args.markdown}")


if __name__ == "__main__":
    main()

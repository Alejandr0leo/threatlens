"""
engine.py — Orquesta el enriquecimiento de IOCs y agrega un veredicto por indicador.

Flujo: lista de IOCs crudos -> detectar tipo -> consultar todas las fuentes en
paralelo -> agregar puntaje y veredicto final.
"""

from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field

from .ioc import detect_type
from .sources import ALL_SOURCES, SourceResult

# Bandas de veredicto según el puntaje agregado (0-100)
def _verdict(score: int, has_data: bool, informational: bool) -> str:
    if informational:
        return "INFORMATIVO"
    if not has_data:
        return "DESCONOCIDO"
    if score >= 70:
        return "MALICIOSO"
    if score >= 40:
        return "SOSPECHOSO"
    if score >= 1:
        return "BAJO"
    return "LIMPIO"


@dataclass
class IOCResult:
    raw: str
    ioc: str
    kind: str
    score: int
    verdict: str
    results: list[SourceResult] = field(default_factory=list)


def enrich_one(raw: str) -> IOCResult:
    kind, normalized = detect_type(raw)

    if kind == "unknown":
        return IOCResult(raw, normalized, kind, 0, "INVÁLIDO",
                         [SourceResult("local", "error", 0, "No se reconoce como IP, dominio o hash.")])

    results = [src(normalized, kind) for src in ALL_SOURCES]

    informational = any(r.source == "local" and r.status == "info" for r in results)
    # Si la IP es privada/reservada, no tiene sentido el puntaje de amenaza externa
    scored = [r for r in results if r.status in ("malicious", "suspicious")]
    score = max((r.score for r in scored), default=0)
    has_data = any(r.status in ("malicious", "suspicious", "clean", "not_found") and r.source != "local"
                   for r in results) or any(r.status in ("malicious", "suspicious") for r in results)

    verdict = _verdict(score, has_data, informational)
    return IOCResult(raw, normalized, kind, score, verdict, results)


def enrich_many(raws: list[str], max_workers: int = 8) -> list[IOCResult]:
    """Enriquece varios IOCs en paralelo (preserva el orden de entrada)."""
    with ThreadPoolExecutor(max_workers=max_workers) as ex:
        return list(ex.map(enrich_one, raws))

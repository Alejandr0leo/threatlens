"""
sources.py — Fuentes de enriquecimiento de Threat Intelligence.

Cada fuente recibe (ioc, tipo) y devuelve un SourceResult. El diseño degrada con
elegancia: las fuentes que requieren API key se marcan como 'skipped' si la key no
está configurada, y cualquier error de red se captura como 'error' sin romper el flujo.

Fuentes:
  - local       : clasificación offline (siempre activa, sin red).
  - tor         : nodos de salida Tor (sin API key).
  - feodo       : abuse.ch Feodo Tracker, IPs de C2 de botnets (Auth-Key de abuse.ch).
  - urlhaus     : abuse.ch URLhaus, hosts/dominios maliciosos (Auth-Key de abuse.ch).
  - threatfox   : abuse.ch ThreatFox, IOCs de malware (Auth-Key de abuse.ch).
  - virustotal  : VirusTotal v3 (VT_API_KEY).
  - abuseipdb   : AbuseIPDB (ABUSEIPDB_API_KEY).

Variables de entorno: ABUSE_CH_API_KEY, VT_API_KEY, ABUSEIPDB_API_KEY.
La Auth-Key de abuse.ch es gratuita y cubre Feodo, URLhaus y ThreatFox.
"""

from __future__ import annotations

import os
import time
from dataclasses import dataclass, field

import requests

from .ioc import ip_classification, hash_kind

TIMEOUT = 12
_CACHE: dict = {}
_CACHE_TTL = 1800  # 30 min


@dataclass
class SourceResult:
    source: str
    status: str          # malicious | suspicious | clean | not_found | skipped | error | info
    score: int = 0       # contribución de riesgo 0-100
    detail: str = ""
    link: str | None = None
    meta: dict = field(default_factory=dict)


def _cached(key: str):
    item = _CACHE.get(key)
    if item and (time.time() - item[0]) < _CACHE_TTL:
        return item[1]
    return None


def _store(key: str, value):
    _CACHE[key] = (time.time(), value)
    return value


def _abuse_key() -> str | None:
    return os.environ.get("ABUSE_CH_API_KEY")


# ---------------------------------------------------------------------------
# Local (siempre activa, sin red)
# ---------------------------------------------------------------------------
def src_local(ioc: str, kind: str) -> SourceResult:
    if kind == "ip":
        cls = ip_classification(ioc)
        if cls:
            return SourceResult("local", "info", 0,
                                f"IP {cls}: no es una amenaza enrutable en Internet.")
        return SourceResult("local", "clean", 0, "IP pública válida.")
    if kind == "hash":
        return SourceResult("local", "clean", 0, f"Hash {hash_kind(ioc)} válido.")
    if kind == "domain":
        return SourceResult("local", "clean", 0, "Dominio con formato válido.")
    return SourceResult("local", "error", 0, "Tipo de IOC no reconocido.")


# ---------------------------------------------------------------------------
# Tor exit nodes (sin API key)
# ---------------------------------------------------------------------------
def _tor_exits() -> set[str]:
    cached = _cached("tor")
    if cached is not None:
        return cached
    try:
        r = requests.get("https://check.torproject.org/torbulkexitlist", timeout=TIMEOUT)
        r.raise_for_status()
        ips = {ln.strip() for ln in r.text.splitlines() if ln.strip() and not ln.startswith("#")}
        return _store("tor", ips)
    except Exception:
        return _store("tor", set())


def src_tor(ioc: str, kind: str) -> SourceResult:
    if kind != "ip":
        return SourceResult("tor", "skipped", 0, "Solo aplica a IPs.")
    exits = _tor_exits()
    if not exits:
        return SourceResult("tor", "error", 0, "No se pudo consultar la lista de salidas Tor.")
    if ioc in exits:
        return SourceResult("tor", "suspicious", 30,
                            "La IP es un nodo de salida de Tor (tráfico anonimizado).",
                            "https://metrics.torproject.org/")
    return SourceResult("tor", "not_found", 0, "No es un nodo de salida Tor.")


# ---------------------------------------------------------------------------
# abuse.ch Feodo Tracker — IPs de C2 (Auth-Key abuse.ch)
# ---------------------------------------------------------------------------
def _feodo_list(key: str) -> dict:
    cached = _cached("feodo")
    if cached is not None:
        return cached
    try:
        r = requests.get("https://feodotracker.abuse.ch/downloads/ipblocklist.json",
                         headers={"Auth-Key": key}, timeout=TIMEOUT)
        r.raise_for_status()
        return _store("feodo", {row["ip_address"]: row for row in r.json()})
    except Exception:
        return _store("feodo", {})


def src_feodo(ioc: str, kind: str) -> SourceResult:
    if kind != "ip":
        return SourceResult("feodo", "skipped", 0, "Solo aplica a IPs.")
    key = _abuse_key()
    if not key:
        return SourceResult("feodo", "skipped", 0, "Requiere ABUSE_CH_API_KEY (gratuita).")
    data = _feodo_list(key)
    if not data:
        return SourceResult("feodo", "error", 0, "No se pudo consultar Feodo Tracker.")
    if ioc in data:
        fam = data[ioc].get("malware", "desconocido")
        return SourceResult("feodo", "malicious", 90,
                            f"IP de C2 listada (familia: {fam}).",
                            "https://feodotracker.abuse.ch/", data[ioc])
    return SourceResult("feodo", "not_found", 0, "No aparece en Feodo Tracker.")


# ---------------------------------------------------------------------------
# abuse.ch URLhaus — hosts/dominios (Auth-Key abuse.ch)
# ---------------------------------------------------------------------------
def src_urlhaus(ioc: str, kind: str) -> SourceResult:
    if kind not in ("domain", "ip"):
        return SourceResult("urlhaus", "skipped", 0, "Aplica a dominios/IPs.")
    key = _abuse_key()
    if not key:
        return SourceResult("urlhaus", "skipped", 0, "Requiere ABUSE_CH_API_KEY (gratuita).")
    try:
        r = requests.post("https://urlhaus-api.abuse.ch/v1/host/",
                          data={"host": ioc}, headers={"Auth-Key": key}, timeout=TIMEOUT)
        r.raise_for_status()
        d = r.json()
        if d.get("query_status") == "no_results":
            return SourceResult("urlhaus", "not_found", 0, "Sin resultados en URLhaus.")
        count = int(d.get("url_count") or 0)
        score = 70 if count else 30
        return SourceResult("urlhaus", "malicious" if count else "suspicious", score,
                            f"{count} URL(s) maliciosa(s) asociadas a este host.",
                            d.get("urlhaus_reference"), d)
    except Exception as e:
        return SourceResult("urlhaus", "error", 0, f"Error consultando URLhaus: {e}")


# ---------------------------------------------------------------------------
# abuse.ch ThreatFox — IOCs de malware (Auth-Key abuse.ch)
# ---------------------------------------------------------------------------
def src_threatfox(ioc: str, kind: str) -> SourceResult:
    key = _abuse_key()
    if not key:
        return SourceResult("threatfox", "skipped", 0, "Requiere ABUSE_CH_API_KEY (gratuita).")
    try:
        r = requests.post("https://threatfox-api.abuse.ch/api/v1/",
                          json={"query": "search_ioc", "search_term": ioc},
                          headers={"Auth-Key": key}, timeout=TIMEOUT)
        r.raise_for_status()
        d = r.json()
        if d.get("query_status") != "ok" or not d.get("data"):
            return SourceResult("threatfox", "not_found", 0, "Sin coincidencias en ThreatFox.")
        fam = d["data"][0].get("malware_printable", "desconocido")
        return SourceResult("threatfox", "malicious", 85,
                            f"IOC asociado a {fam} (ThreatFox).",
                            "https://threatfox.abuse.ch/", d["data"][0])
    except Exception as e:
        return SourceResult("threatfox", "error", 0, f"Error ThreatFox: {e}")


# ---------------------------------------------------------------------------
# VirusTotal v3 (VT_API_KEY)
# ---------------------------------------------------------------------------
def src_virustotal(ioc: str, kind: str) -> SourceResult:
    key = os.environ.get("VT_API_KEY")
    if not key:
        return SourceResult("virustotal", "skipped", 0, "Sin VT_API_KEY configurada.")
    endpoint = {"ip": "ip_addresses", "domain": "domains", "hash": "files"}.get(kind)
    if not endpoint:
        return SourceResult("virustotal", "skipped", 0, "Tipo no soportado.")
    try:
        r = requests.get(f"https://www.virustotal.com/api/v3/{endpoint}/{ioc}",
                         headers={"x-apikey": key}, timeout=TIMEOUT)
        if r.status_code == 404:
            return SourceResult("virustotal", "not_found", 0, "No conocido por VirusTotal.")
        r.raise_for_status()
        stats = r.json()["data"]["attributes"]["last_analysis_stats"]
        mal, susp = stats.get("malicious", 0), stats.get("suspicious", 0)
        total = sum(stats.values()) or 1
        score = min(100, int((mal * 100 + susp * 50) / total))
        status = "malicious" if mal else ("suspicious" if susp else "clean")
        return SourceResult("virustotal", status, score,
                            f"{mal} motores lo marcan como malicioso, {susp} sospechoso (de {total}).",
                            f"https://www.virustotal.com/gui/search/{ioc}", stats)
    except Exception as e:
        return SourceResult("virustotal", "error", 0, f"Error VT: {e}")


# ---------------------------------------------------------------------------
# AbuseIPDB (ABUSEIPDB_API_KEY)
# ---------------------------------------------------------------------------
def src_abuseipdb(ioc: str, kind: str) -> SourceResult:
    key = os.environ.get("ABUSEIPDB_API_KEY")
    if not key:
        return SourceResult("abuseipdb", "skipped", 0, "Sin ABUSEIPDB_API_KEY configurada.")
    if kind != "ip":
        return SourceResult("abuseipdb", "skipped", 0, "Solo aplica a IPs.")
    try:
        r = requests.get("https://api.abuseipdb.com/api/v2/check",
                         headers={"Key": key, "Accept": "application/json"},
                         params={"ipAddress": ioc, "maxAgeInDays": 90}, timeout=TIMEOUT)
        r.raise_for_status()
        d = r.json()["data"]
        score = int(d.get("abuseConfidenceScore", 0))
        status = "malicious" if score >= 70 else ("suspicious" if score >= 25 else "clean")
        return SourceResult("abuseipdb", status, score,
                            f"Confianza de abuso {score}% · {d.get('totalReports', 0)} reportes.",
                            f"https://www.abuseipdb.com/check/{ioc}", d)
    except Exception as e:
        return SourceResult("abuseipdb", "error", 0, f"Error AbuseIPDB: {e}")


ALL_SOURCES = [
    src_local, src_tor, src_feodo, src_urlhaus, src_threatfox,
    src_virustotal, src_abuseipdb,
]

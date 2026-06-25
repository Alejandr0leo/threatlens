"""
ioc.py — Detección, validación y normalización de indicadores de compromiso (IOCs).

Soporta: IPv4, dominios, URLs (de las que extrae el host) y hashes (MD5/SHA1/SHA256).
Incluye "refang" para indicadores ofuscados (ej. 1[.]2[.]3[.]4, hxxp://...).
"""

import ipaddress
import re

HASH_LENGTHS = {32: "md5", 40: "sha1", 64: "sha256"}
_HEX = re.compile(r"^[a-fA-F0-9]+$")
_DOMAIN = re.compile(
    r"^(?=.{1,253}$)(?!-)[A-Za-z0-9-]{1,63}(?<!-)"
    r"(\.(?!-)[A-Za-z0-9-]{1,63}(?<!-))+$"
)


def refang(value: str) -> str:
    """Convierte un IOC ofuscado a su forma normal."""
    v = value.strip()
    replacements = {
        "[.]": ".", "(.)": ".", "{.}": ".", "[dot]": ".", " dot ": ".",
        "[:]": ":", "hxxps": "https", "hxxp": "http", "[//]": "//",
    }
    for bad, good in replacements.items():
        v = v.replace(bad, good)
    return v.strip()


def _host_from_url(value: str) -> str | None:
    m = re.match(r"^[a-zA-Z][a-zA-Z0-9+.-]*://([^/:?#]+)", value)
    return m.group(1) if m else None


def detect_type(value: str) -> tuple[str, str]:
    """Devuelve (tipo, valor_normalizado).

    tipo ∈ {'ip', 'domain', 'hash', 'unknown'}.
    Para URLs devuelve el host como 'domain' (o 'ip' si el host es una IP).
    """
    v = refang(value)

    # URL -> extraer host
    if "://" in v:
        host = _host_from_url(v)
        if host:
            v = host

    # IP
    try:
        ipaddress.ip_address(v)
        return "ip", v
    except ValueError:
        pass

    # Hash
    if _HEX.match(v) and len(v) in HASH_LENGTHS:
        return "hash", v.lower()

    # Dominio
    if _DOMAIN.match(v):
        return "domain", v.lower()

    return "unknown", v


def hash_kind(value: str) -> str | None:
    """Devuelve 'md5' / 'sha1' / 'sha256' para un hash, o None."""
    return HASH_LENGTHS.get(len(value)) if _HEX.match(value) else None


def ip_classification(value: str) -> str | None:
    """Para una IP, indica si es privada/reservada/loopback/etc. (no es una amenaza
    de Internet). Devuelve None si es una IP pública normal."""
    try:
        ip = ipaddress.ip_address(value)
    except ValueError:
        return None
    if ip.is_loopback:
        return "loopback"
    if ip.is_private:
        return "privada (RFC1918)"
    if ip.is_reserved:
        return "reservada"
    if ip.is_link_local:
        return "link-local"
    if ip.is_multicast:
        return "multicast"
    return None


def parse_iocs(text: str) -> list[str]:
    """Extrae IOCs de un texto libre. Ignora líneas en blanco y comentarios (#)."""
    seen, out = set(), []
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        for item in re.split(r"[\s,;]+", line):
            if item and item not in seen:
                seen.add(item)
                out.append(item)
    return out

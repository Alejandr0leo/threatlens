"""ThreatLens — enriquecimiento de IOCs y agregación de Threat Intelligence."""
from .engine import enrich_one, enrich_many, IOCResult
from .ioc import detect_type, parse_iocs

__all__ = ["enrich_one", "enrich_many", "IOCResult", "detect_type", "parse_iocs"]
__version__ = "0.1.0"

# ThreatLens — Enriquecimiento de IOCs y Threat Intelligence

ThreatLens recibe indicadores de compromiso (**IPs, dominios y hashes**), los consulta
contra varias fuentes de inteligencia de amenazas y entrega un **veredicto agregado**
por indicador, con reporte en terminal, Markdown/JSON y un dashboard visual.

> Proyecto de portafolio orientado a roles de **CTI / Threat Intelligence / SOC**.

---

##  ¿Qué hace?

- **Detecta y normaliza** el tipo de IOC automáticamente (IPv4, dominio, URL→host, hash MD5/SHA1/SHA256).
- **"Refang"** de indicadores ofuscados: `1[.]2[.]3[.]4`, `hxxp://malo[.]com` → forma real.
- **Consulta varias fuentes en paralelo** y combina sus señales en un puntaje 0–100.
- **Veredicto claro** por IOC: 🔴 MALICIOSO · 🟠 SOSPECHOSO · 🟡 BAJO · 🟢 LIMPIO · 🔵 INFORMATIVO · ⚪ DESCONOCIDO.
- **Degrada con elegancia**: las fuentes sin API key se omiten solas; los errores de red no rompen el análisis.

---

## 🛰️ Fuentes de inteligencia

| Fuente | IOC | API key |
|---|---|---|
| local | todos | — (offline, siempre activa) |
| Tor exit nodes | IP | — (sin key) |
| abuse.ch Feodo Tracker | IP | `ABUSE_CH_API_KEY` |
| abuse.ch URLhaus | dominio / IP | `ABUSE_CH_API_KEY` |
| abuse.ch ThreatFox | todos | `ABUSE_CH_API_KEY` |
| VirusTotal v3 | todos | `VT_API_KEY` |
| AbuseIPDB | IP | `ABUSEIPDB_API_KEY` |

La **Auth-Key de abuse.ch es gratuita** (https://auth.abuse.ch/) y cubre Feodo, URLhaus y ThreatFox.
VirusTotal y AbuseIPDB ofrecen *free tier*. Sin ninguna key, siguen activas `local` y `Tor`.

---

## Uso rápido

```bash
# 1. Instalar dependencias
pip install -r requirements.txt

# 2. (Opcional) Configurar keys
export ABUSE_CH_API_KEY="tu_auth_key"
export VT_API_KEY="tu_api_key"

# 3a. Analizar desde archivo
python cli.py --file data/sample_iocs.txt

# 3b. Analizar IOCs sueltos + guardar reporte
python cli.py 8.8.8.8 malicious-test.com 44d88612fea8a8f36de82e1278abb02f --markdown reporte.md

# 3c. Dashboard visual
streamlit run dashboard.py
```

### Ejemplo de salida (terminal)

```
🔴 MALICIOSO   [ 90] 45.155.205.99  (ip)
      └ feodo: IP de C2 listada (familia: Emotet).
🔵 INFORMATIVO [  0] 192.168.1.10  (ip)
      └ local: IP privada (RFC1918): no es una amenaza enrutable en Internet.
🟢 LIMPIO      [  0] 8.8.8.8  (ip)
```

---

## Arquitectura

```
threatlens/
├── threatlens/
│   ├── ioc.py          # Detección, validación y "refang" de IOCs
│   ├── sources.py      # Fuentes de inteligencia (pluggables)
│   ├── engine.py       # Orquesta consultas en paralelo + agrega veredicto
│   └── report.py       # Reportes en Markdown / JSON
├── data/
│   └── sample_iocs.txt # IOCs de muestra
├── cli.py              # Ejecución por terminal
├── dashboard.py        # Dashboard visual (Streamlit)
└── config.example.env  # Plantilla de variables de entorno
```

**Stack:** Python · requests · pandas · Streamlit · concurrencia con ThreadPoolExecutor.

### ¿Cómo se calcula el veredicto?
Cada fuente devuelve un puntaje de riesgo (0–100). El motor toma el **máximo** entre las
señales positivas y lo mapea a bandas: ≥70 MALICIOSO, 40–69 SOSPECHOSO, 1–39 BAJO,
0 con datos LIMPIO, sin datos DESCONOCIDO. Las IPs privadas/reservadas se marcan
INFORMATIVO (no son amenazas de Internet).

---

## Roadmap

- [ ] Soporte para enriquecimiento de URLs completas y direcciones de correo.
- [ ] Exportación a STIX 2.1 / MISP.
- [ ] Caché persistente en disco y modo "watch" para feeds.
- [ ] Más fuentes (GreyNoise, AlienVault OTX, Shodan).

---

## Autor

**Nikolay Alejandro León Duarte** — Estudiante de Ingeniería de Sistemas (ciberseguridad, CTI, Python)
GitHub: [github.com/Alejandr0leo](https://github.com/Alejandr0leo)

---

*Proyecto educativo / de portafolio. Úsalo de forma responsable y respeta los términos de uso de cada fuente.*

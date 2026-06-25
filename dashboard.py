"""
dashboard.py — Dashboard visual de ThreatLens (Streamlit).

Uso:
    streamlit run dashboard.py
"""

import os
import pandas as pd
import streamlit as st

from threatlens import enrich_many, parse_iocs

st.set_page_config(page_title="ThreatLens — Threat Intelligence", page_icon="🔍", layout="wide")

VERDICT_COLOR = {
    "MALICIOSO": "#e74c3c", "SOSPECHOSO": "#e67e22", "BAJO": "#f1c40f",
    "LIMPIO": "#27ae60", "INFORMATIVO": "#3498db",
    "DESCONOCIDO": "#95a5a6", "INVÁLIDO": "#7f8c8d", "INVALIDO": "#7f8c8d",
}

st.title("🔍 ThreatLens — Threat Intelligence")
st.caption("Enriquecimiento de IOCs (IP · dominio · hash) contra múltiples fuentes de inteligencia.")

with st.sidebar:
    st.header("Fuentes")
    st.markdown(
        "- **local** · offline\n- **Tor exit nodes** · sin key\n"
        "- **Feodo Tracker** · IPs C2 (abuse.ch)\n"
        "- **URLhaus** · hosts (abuse.ch)\n- **ThreatFox** · IOCs (abuse.ch)\n"
        "- **VirusTotal** · `VT_API_KEY`\n- **AbuseIPDB** · `ABUSEIPDB_API_KEY`"
    )
    keys = {
        "abuse.ch (Feodo/URLhaus/ThreatFox)": bool(os.environ.get("ABUSE_CH_API_KEY")),
        "VirusTotal": bool(os.environ.get("VT_API_KEY")),
        "AbuseIPDB": bool(os.environ.get("ABUSEIPDB_API_KEY")),
    }
    st.divider()
    st.caption("API keys detectadas:")
    for name, ok in keys.items():
        st.write(("✅ " if ok else "⬜ ") + name)

default = "8.8.8.8\nexample.com\n44d88612fea8a8f36de82e1278abb02f"
text = st.text_area("Pega IOCs (uno por línea, o separados por coma/espacio):",
                    value=default, height=140)
go = st.button("Analizar", type="primary")

if go:
    raws = parse_iocs(text)
    if not raws:
        st.warning("No se detectaron IOCs.")
        st.stop()

    with st.spinner(f"Consultando inteligencia para {len(raws)} IOC(s)..."):
        results = enrich_many(raws)

    mal = sum(1 for r in results if r.verdict == "MALICIOSO")
    susp = sum(1 for r in results if r.verdict == "SOSPECHOSO")
    c1, c2, c3 = st.columns(3)
    c1.metric("IOCs analizados", len(results))
    c2.metric("Maliciosos", mal)
    c3.metric("Sospechosos", susp)
    st.divider()

    table = pd.DataFrame([{
        "IOC": r.ioc, "Tipo": r.kind, "Veredicto": r.verdict, "Puntaje": r.score,
    } for r in results])
    st.dataframe(table, use_container_width=True, hide_index=True)

    for r in results:
        color = VERDICT_COLOR.get(r.verdict, "#888")
        with st.expander(f"{r.verdict} · {r.ioc}  (puntaje {r.score})"):
            st.markdown(
                f"<div style='border-left:5px solid {color};padding:6px 12px'>"
                f"<b style='color:{color}'>{r.verdict}</b> · {r.kind} · puntaje {r.score}</div>",
                unsafe_allow_html=True,
            )
            for s in r.results:
                if s.status == "skipped":
                    continue
                link = f" — [ref]({s.link})" if s.link else ""
                st.markdown(f"- **{s.source}** · `{s.status}` · {s.detail}{link}")

st.caption("ThreatLens v0.1 · proyecto de portafolio — github.com/Alejandr0leo")

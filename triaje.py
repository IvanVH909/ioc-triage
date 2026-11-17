#!/usr/bin/env python3
"""
ioc-triage
----------
Triaje rapido de un IOC (IP, dominio o hash) en tres pasos:

  1. ENRIQUECER  -> consulta AbuseIPDB (IPs) y VirusTotal (IPs, dominios, hashes)
  2. PUNTUAR     -> veredicto base con reglas simples y transparentes (sin IA)
  3. RESUMIR     -> un LLM redacta el resumen y propone siguientes pasos, SOLO con los datos recogidos

Solo usa la libreria estandar de Python.

Uso:
    python triaje.py 8.8.8.8
    python triaje.py 275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f
    python triaje.py 203.0.113.7 --offline --no-llm      # demo con datos simulados de ./fixtures
"""

from __future__ import annotations

import argparse
import ipaddress
import json
import os
import re
import sys
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timezone
from pathlib import Path

HERE = Path(__file__).resolve().parent
HASH_RE = re.compile(r"^(?:[a-fA-F0-9]{32}|[a-fA-F0-9]{40}|[a-fA-F0-9]{64})$")
DOMAIN_RE = re.compile(r"^(?=.{1,253}$)(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,63}$")

SYSTEM_PROMPT = (
    "Eres un analista SOC de nivel 1. Recibes datos de enriquecimiento de un indicador de compromiso (IOC) "
    "y un veredicto base calculado por reglas. Redacta un triaje breve.\n"
    "REGLAS ESTRICTAS:\n"
    "- Usa SOLO los datos proporcionados. No inventes campañas, familias de malware ni atribuciones.\n"
    "- Si faltan datos o hubo errores de consulta, dilo explicitamente y baja la confianza.\n"
    "- 'benign' significa 'sin evidencias de maldad en estas fuentes', no 'seguro'.\n"
    "Responde EXCLUSIVAMENTE con un objeto JSON valido, sin formato markdown adicional (sin ```json), con esta forma exacta:\n"
    '{"verdict": "malicious|suspicious|benign|unknown", "confidence": "low|medium|high", '
    '"summary": "2-3 frases", "next_steps": ["paso 1", "paso 2", "paso 3"]}'
)


class EnrichmentError(Exception):
    """Fallo al consultar una fuente externa."""


# --------------------------------------------------------------------------- #
# Utilidades
# --------------------------------------------------------------------------- #
def load_env(path: Path = HERE / ".env") -> None:
    """Carga variables KEY=VALUE de .env (sin dependencias). No pisa las ya definidas."""
    if not path.exists():
        return
    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if line and not line.startswith("#") and "=" in line:
            key, _, value = line.partition("=")
            os.environ.setdefault(key.strip(), value.strip().strip('"').strip("'"))


def classify(ioc: str) -> str:
    """Devuelve 'ip', 'hash' o 'domain'; lanza ValueError si no reconoce el formato."""
    ioc = ioc.strip()
    try:
        ipaddress.ip_address(ioc)
        return "ip"
    except ValueError:
        pass
    if HASH_RE.match(ioc):
        return "hash"
    if DOMAIN_RE.match(ioc):
        return "domain"
    raise ValueError(f"Formato de IOC no reconocido: {ioc!r}")


def http_json(url: str, headers: dict, body: dict | None = None, timeout: int = 25) -> dict:
    data = json.dumps(body).encode() if body is not None else None
    req = urllib.request.Request(url, data=data, headers=headers, method="POST" if body is not None else "GET")
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return json.loads(resp.read().decode("utf-8"))
    except urllib.error.HTTPError as exc:
        # Google suele devolver un JSON con el motivo real del error.
        # No mostramos la URL completa porque contiene la API key.
        try:
            detail = exc.read().decode("utf-8", errors="replace")
            payload = json.loads(detail)
            message = payload.get("error", {}).get("message", detail)
        except (ValueError, AttributeError):
            message = "sin detalle"
        host = urllib.parse.urlparse(url).netloc
        raise EnrichmentError(f"HTTP {exc.code} en {host}: {message}") from exc
    except (urllib.error.URLError, TimeoutError, json.JSONDecodeError) as exc:
        raise EnrichmentError(f"Error de red/parseo en {urllib.parse.urlparse(url).netloc}: {exc}") from exc


# --------------------------------------------------------------------------- #
# 1. Enriquecimiento
# --------------------------------------------------------------------------- #
def query_abuseipdb(ip: str) -> dict:
    key = os.environ.get("ABUSEIPDB_API_KEY")
    if not key:
        raise EnrichmentError("Falta ABUSEIPDB_API_KEY")
    url = "https://api.abuseipdb.com/api/v2/check?" + urllib.parse.urlencode({"ipAddress": ip, "maxAgeInDays": 90})
    return http_json(url, {"Key": key, "Accept": "application/json"})


def query_virustotal(ioc: str, kind: str) -> dict:
    key = os.environ.get("VT_API_KEY")
    if not key:
        raise EnrichmentError("Falta VT_API_KEY")
    path = {"ip": "ip_addresses", "domain": "domains", "hash": "files"}[kind]
    return http_json(f"https://www.virustotal.com/api/v3/{path}/{urllib.parse.quote(ioc)}", {"x-apikey": key})


def normalize_abuseipdb(raw: dict) -> dict:
    d = raw.get("data", {})
    return {
        "abuse_score": d.get("abuseConfidenceScore"),
        "total_reports": d.get("totalReports"),
        "country": d.get("countryCode"),
        "isp": d.get("isp"),
        "usage_type": d.get("usageType"),
        "last_reported": d.get("lastReportedAt"),
    }


def normalize_virustotal(raw: dict) -> dict:
    a = raw.get("data", {}).get("attributes", {})
    stats = a.get("last_analysis_stats", {})
    return {
        "malicious": stats.get("malicious", 0),
        "suspicious": stats.get("suspicious", 0),
        "harmless": stats.get("harmless", 0),
        "undetected": stats.get("undetected", 0),
        "reputation": a.get("reputation"),
        "country": a.get("country"),
        "as_owner": a.get("as_owner"),
        "file_type": a.get("type_description"),
        "file_name": a.get("meaningful_name"),
    }


def enrich(ioc: str, kind: str, offline: bool = False) -> dict:
    """Devuelve {'abuseipdb': {...}|None, 'virustotal': {...}|None, 'errors': [...]}."""
    evidence = {"abuseipdb": None, "virustotal": None, "errors": []}

    if offline:  # datos simulados guardados en ./fixtures (misma forma que las APIs reales)
        fx = HERE / "fixtures" / f"{ioc}.json"
        if not fx.exists():
            evidence["errors"].append(f"Sin fixture offline para {ioc}")
            return evidence
        raw = json.loads(fx.read_text(encoding="utf-8"))
        if "abuseipdb" in raw:
            evidence["abuseipdb"] = normalize_abuseipdb(raw["abuseipdb"])
        if "virustotal" in raw:
            evidence["virustotal"] = normalize_virustotal(raw["virustotal"])
        return evidence

    if kind == "ip":
        if ipaddress.ip_address(ioc).is_private:
            evidence["errors"].append("IP privada/reservada: no tiene reputacion publica")
            return evidence
        try:
            evidence["abuseipdb"] = normalize_abuseipdb(query_abuseipdb(ioc))
        except EnrichmentError as exc:
            evidence["errors"].append(f"AbuseIPDB: {exc}")
    try:
        evidence["virustotal"] = normalize_virustotal(query_virustotal(ioc, kind))
    except EnrichmentError as exc:
        evidence["errors"].append(f"VirusTotal: {exc}")
    return evidence


# --------------------------------------------------------------------------- #
# 2. Veredicto base (reglas transparentes, sin IA)
# --------------------------------------------------------------------------- #
def baseline_verdict(evidence: dict) -> str:
    vt, ab = evidence.get("virustotal"), evidence.get("abuseipdb")
    if not vt and not ab:
        return "unknown"
    vt_mal = (vt or {}).get("malicious", 0) or 0
    vt_sus = (vt or {}).get("suspicious", 0) or 0
    ab_score = (ab or {}).get("abuse_score") or 0
    if vt_mal >= 5 or ab_score >= 75:
        return "malicious"
    # Una detección maliciosa aislada puede ser ruido/falso positivo.
    # Exigimos al menos dos motores para elevar a suspicious.
    if vt_mal >= 2 or vt_sus >= 3 or ab_score >= 25:
        return "suspicious"
    return "benign"


# --------------------------------------------------------------------------- #
# 3. Resumen con LLM
# --------------------------------------------------------------------------- #
def build_user_prompt(ioc: str, kind: str, evidence: dict, baseline: str) -> str:
    return json.dumps(
        {"ioc": ioc, "tipo": kind, "veredicto_base": baseline, "datos": evidence},
        ensure_ascii=False, indent=2,
    )


def parse_llm_json(text: str) -> dict:
    """Extrae el JSON de la respuesta del modelo aunque venga envuelto en ```json ... ```."""
    text = text.strip()
    text = re.sub(r"^```(?:json)?\s*|\s*```$", "", text, flags=re.IGNORECASE)
    start, end = text.find("{"), text.rfind("}")
    if start == -1 or end == -1:
        raise ValueError("La respuesta del LLM no contiene JSON")
    data = json.loads(text[start:end + 1])
    verdict = str(data.get("verdict", "unknown")).lower()
    if verdict not in {"malicious", "suspicious", "benign", "unknown"}:
        verdict = "unknown"
    return {
        "verdict": verdict,
        "confidence": str(data.get("confidence", "low")).lower(),
        "summary": str(data.get("summary", "")).strip(),
        "next_steps": [str(s) for s in data.get("next_steps", [])][:5],
    }


def query_llm(ioc: str, kind: str, evidence: dict, baseline: str) -> dict:
    key = os.environ.get("GEMINI_API_KEY")
    if not key:
        raise EnrichmentError("Falta GEMINI_API_KEY en el entorno")
    
    model = os.environ.get("IOC_LLM_MODEL", "gemini-3.5-flash-lite")
    url = f"https://generativelanguage.googleapis.com/v1beta/models/{model}:generateContent?key={key}"
    
    body = {
        "system_instruction": {
            "parts": [{"text": SYSTEM_PROMPT}]
        },
        "contents": [{
            "parts": [{"text": build_user_prompt(ioc, kind, evidence, baseline)}]
        }],
        "generationConfig": {
            "responseMimeType": "application/json"
        }
    }
    
    headers = {"content-type": "application/json"}
    resp = http_json(url, headers, body)
    
    try:
        text = resp["candidates"][0]["content"]["parts"][0]["text"]
    except (KeyError, IndexError) as exc:
        raise EnrichmentError(f"Respuesta inesperada de la API de Gemini: {exc}") from exc
        
    return parse_llm_json(text)
# --------------------------------------------------------------------------- #
# Orquestacion + CLI
# --------------------------------------------------------------------------- #
def triage(ioc: str, offline: bool = False, use_llm: bool = True) -> dict:
    ioc = ioc.strip()
    kind = classify(ioc)
    evidence = enrich(ioc, kind, offline=offline)
    baseline = baseline_verdict(evidence)
    result = {
        "ioc": ioc,
        "type": kind,
        "timestamp": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "evidence": evidence,
        "baseline_verdict": baseline,
        "llm": None,
    }
    if use_llm:
        try:
            result["llm"] = query_llm(ioc, kind, evidence, baseline)
        except (EnrichmentError, ValueError) as exc:
            result["llm"] = {"error": str(exc)}
    return result


def print_result(r: dict) -> None:
    ev = r["evidence"]
    print(f"\n=== {r['ioc']}  ({r['type']}) ===")
    if ev["abuseipdb"]:
        a = ev["abuseipdb"]
        print(f"AbuseIPDB : score {a['abuse_score']}/100 · {a['total_reports']} reportes · {a['country']} · {a['isp']}")
    if ev["virustotal"]:
        v = ev["virustotal"]
        print(f"VirusTotal: {v['malicious']} malicious / {v['suspicious']} suspicious / {v['harmless']} harmless")
    for err in ev["errors"]:
        print(f"[!] {err}")
    print(f"Veredicto base (reglas): {r['baseline_verdict'].upper()}")
    llm = r["llm"]
    if llm and "error" not in llm:
        print(f"Veredicto LLM: {llm['verdict'].upper()} (confianza {llm['confidence']})\n{llm['summary']}")
        for i, step in enumerate(llm["next_steps"], 1):
            print(f"  {i}. {step}")
    elif llm:
        print(f"[!] LLM no disponible: {llm['error']}")


def main(argv=None) -> int:
    load_env()
    ap = argparse.ArgumentParser(description="Triaje de IOCs con enriquecimiento y resumen LLM.")
    ap.add_argument("iocs", nargs="+", help="IP, dominio o hash (MD5/SHA1/SHA256)")
    ap.add_argument("--offline", action="store_true", help="Usa datos simulados de ./fixtures (sin red)")
    ap.add_argument("--no-llm", action="store_true", help="No llama al LLM (solo enriquecimiento + reglas)")
    ap.add_argument("--out", type=Path, default=Path("results"), help="Carpeta de salida para los JSON")
    args = ap.parse_args(argv)

    args.out.mkdir(parents=True, exist_ok=True)
    code = 0
    for ioc in args.iocs:
        try:
            result = triage(ioc, offline=args.offline, use_llm=not args.no_llm)
        except ValueError as exc:
            print(f"[x] {exc}", file=sys.stderr)
            code = 1
            continue
        print_result(result)
        safe = re.sub(r"[^A-Za-z0-9._-]", "_", ioc)
        (args.out / f"{safe}.json").write_text(json.dumps(result, indent=2, ensure_ascii=False), encoding="utf-8")
    return code


if __name__ == "__main__":
    sys.exit(main())

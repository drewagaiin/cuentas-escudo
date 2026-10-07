#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
cuentas-escudo — ¿le robaron una cuenta a la empresa?

Lee el registro de inicios de sesión que la empresa exporta de Microsoft 365
(Entra ID) o Google Workspace y busca señales de cuenta comprometida: protocolos
viejos que se saltan el doble factor, fuerza bruta, rociado de contraseñas (spray),
viaje imposible, fatiga de MFA y accesos desde países nuevos.

No usa internet. Solo lee el archivo que le das. No modifica nada.

Uso rápido:
    ./cuentas-escudo.py registros.csv
    ./cuentas-escudo.py registros.json --formato json
    ./cuentas-escudo.py carpeta_de_logs/ --anonimizar
    cat registros.csv | ./cuentas-escudo.py -

Códigos de salida: 0 sin indicios · 1 sospechoso · 3 peligroso · 2 error.
"""
from __future__ import annotations

import argparse
import csv
import io
import json
import math
import os
import re
import sys
from collections import defaultdict
from dataclasses import dataclass, field
from datetime import datetime, timezone

VERSION = "1.0.0"
SCHEMA_VERSION = 1

# País propio por defecto (ISO 3166 alfa-2). Panamá.
HOME_COUNTRY_DEFAULT = "PA"

# ---- Umbrales (se pueden cambiar por la línea de comandos) -------------------
DEF_BRUTE_FAILS = 10          # fallos del mismo usuario para marcar fuerza bruta
DEF_BRUTE_WIN = 600           # ventana en segundos (10 min)
DEF_SPRAY_USERS = 5           # usuarios distintos desde una IP para marcar spray
DEF_SPRAY_WIN = 3600          # ventana del spray (60 min)
DEF_MFA_FATIGUE = 5           # rechazos/pedidos de MFA seguidos antes de un éxito
DEF_TRAVEL_KMH = 900          # velocidad imposible (km/h) entre dos accesos
DEF_TRAVEL_MIN_KM = 500       # distancia mínima para considerar viaje (ruido geo-IP)

# Niveles de severidad y su peso para el veredicto.
SEV_ORDER = {"info": 0, "bajo": 1, "medio": 2, "alto": 3, "critico": 4}

# Protocolos/clientes heredados que NO soportan MFA moderno (basic auth).
# Comparación en minúsculas por subcadena.
LEGACY_CLIENTS = (
    "imap", "pop", "smtp", "mapi", "activesync", "exchange activesync",
    "authenticated smtp", "autodiscover", "offline address book",
    "other clients", "older office clients",
)

# Códigos de error de Entra ID relevantes (sign-in error code).
ERR_SUCCESS = {"0", ""}
ERR_BAD_PASSWORD = {"50126"}                       # usuario o clave inválidos
ERR_LOCKED = {"50053"}                             # bloqueo inteligente / cuenta bloqueada
ERR_MFA_REQUIRED = {"50074", "50076", "50079", "50158"}  # se pidió MFA (interrupción)
ERR_MFA_DENIED = {"500121"}                        # MFA no respondido / denegado (fatiga)
ERR_CA_BLOCKED = {"53003", "530032"}               # bloqueado por acceso condicional
# Estos NO son intentos de adivinar la clave; no deben contar como fuerza bruta.
ERR_NO_CUENTA = ERR_CA_BLOCKED | ERR_LOCKED

# Eventos de Google Workspace (login audit).
G_SUCCESS = {"login_success"}
G_FAILURE = {"login_failure"}
G_SUSPICIOUS = {"login_success_suspicious", "suspicious_login",
                "suspicious_login_less_secure_app", "login_challenge"}


def eprint(*a):
    print(*a, file=sys.stderr)


class ErrorUso(Exception):
    """Error de uso: termina con código 2."""


# =============================================================================
#  Limpieza de texto hostil (los registros son entrada no confiable)
# =============================================================================
_CTRL = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f-\x9f]")
_ANSI = re.compile(r"\x1b\[[0-9;?]*[ -/]*[@-~]")


def limpiar(s, maxlen: int = 300) -> str:
    """Quita secuencias de escape ANSI, controles, saltos de línea y recorta.

    Evita que un valor del registro (usuario, IP, país) altere la terminal
    o inyecte líneas falsas en el informe.
    """
    if s is None:
        return ""
    if not isinstance(s, str):
        s = str(s)
    s = _ANSI.sub("", s)
    s = s.replace("\r", " ").replace("\n", " ").replace("\t", " ")
    s = _CTRL.sub("", s)
    s = s.strip()
    if len(s) > maxlen:
        s = s[: maxlen - 1] + "…"
    return s


# =============================================================================
#  Evento normalizado
# =============================================================================
@dataclass
class Evento:
    ts: datetime | None          # momento (UTC) o None si no se pudo leer
    raw_ts: str                  # texto original de la fecha
    user: str                    # usuario en minúsculas (UPN o correo)
    ip: str
    country: str                 # ISO alfa-2 en mayúsculas, o ""
    city: str
    lat: float | None
    lon: float | None
    status: str                  # "success" | "failure" | "interrupt" | "unknown"
    error: str                   # código de error (texto)
    client: str                  # cliente/protocolo tal como vino
    app: str                     # aplicación
    legacy: bool                 # el cliente es un protocolo heredado
    suspicious_src: bool         # el propio proveedor lo marcó sospechoso
    source: str                  # "m365" | "google" | "?"
    line: int                    # número de registro (para citar)


@dataclass
class Hallazgo:
    sev: str
    code: str
    user: str
    msg: str
    mitre: str = ""
    evidencia: list = field(default_factory=list)   # líneas o datos de apoyo


# =============================================================================
#  Lectura de fechas
# =============================================================================
_TS_FORMATS = (
    "%Y-%m-%dT%H:%M:%S.%f%z",
    "%Y-%m-%dT%H:%M:%S%z",
    "%Y-%m-%d %H:%M:%S.%f",
    "%Y-%m-%d %H:%M:%S",
    "%m/%d/%Y %H:%M:%S",
    "%m/%d/%Y, %I:%M:%S %p",
    "%m/%d/%Y %I:%M:%S %p",
    "%d/%m/%Y %H:%M:%S",
)


def parse_ts(s: str) -> datetime | None:
    """Convierte una fecha a datetime con zona UTC. Devuelve None si no puede."""
    if not s:
        return None
    s = s.strip()
    # fromisoformat cubre la mayoría de los casos ISO 8601 (incluida la Z).
    iso = s.replace("Z", "+00:00") if s.endswith("Z") else s
    try:
        dt = datetime.fromisoformat(iso)
        return dt.astimezone(timezone.utc) if dt.tzinfo else dt.replace(tzinfo=timezone.utc)
    except ValueError:
        pass
    for fmt in _TS_FORMATS:
        try:
            dt = datetime.strptime(s, fmt)
            return dt.astimezone(timezone.utc) if dt.tzinfo else dt.replace(tzinfo=timezone.utc)
        except ValueError:
            continue
    return None


def to_float(s) -> float | None:
    try:
        if s is None or s == "":
            return None
        return float(s)
    except (TypeError, ValueError):
        return None


# =============================================================================
#  Distancia entre dos puntos (haversine, en km)
# =============================================================================
def haversine_km(lat1, lon1, lat2, lon2) -> float:
    r = 6371.0
    p1, p2 = math.radians(lat1), math.radians(lat2)
    dphi = math.radians(lat2 - lat1)
    dlmb = math.radians(lon2 - lon1)
    a = (math.sin(dphi / 2) ** 2
         + math.cos(p1) * math.cos(p2) * math.sin(dlmb / 2) ** 2)
    return 2 * r * math.asin(min(1.0, math.sqrt(a)))


# =============================================================================
#  Detección del formato y mapeo de columnas
# =============================================================================
def norm_header(h: str) -> str:
    return re.sub(r"\s+", " ", (h or "").strip().lower())


# Sinónimos de encabezado -> campo canónico. Cubre M365 (inglés y español) y Google.
HEADER_MAP = {
    # fecha
    "date (utc)": "ts", "date": "ts", "fecha (utc)": "ts", "fecha": "ts",
    "createddatetime": "ts", "sign-in time": "ts", "time": "ts",
    # usuario
    "username": "user", "user principal name": "user", "userprincipalname": "user",
    "usuario": "user", "nombre principal de usuario": "user",
    "affected user": "user", "user email": "user", "email": "user",
    "user": "user_display",  # "User" en M365 CSV suele ser el nombre para mostrar
    "usuario afectado": "user",
    # ip
    "ip address": "ip", "ipaddress": "ip", "dirección ip": "ip", "direccion ip": "ip",
    "ip": "ip",
    # ubicación
    "location": "location", "ubicación": "location", "ubicacion": "location",
    "city": "city", "ciudad": "city",
    "country": "country", "country or region": "country", "país": "country",
    "pais": "country", "state": "state",
    "latitude": "lat", "latitud": "lat", "longitude": "lon", "longitud": "lon",
    # estado / error
    "status": "status", "estado": "status",
    "sign-in error code": "error", "error code": "error",
    "código de error de inicio de sesión": "error", "codigo de error": "error",
    "failure reason": "reason", "motivo del error": "reason", "reason": "reason",
    # cliente / app
    "client app": "client", "clientappused": "client",
    "aplicación cliente": "client", "aplicacion cliente": "client",
    "application": "app", "app display name": "app", "aplicación": "app",
    "aplicacion": "app",
    # google
    "event": "g_event", "event name": "g_event", "evento": "g_event",
    "event description": "g_desc",
}


def map_headers(headers: list) -> dict:
    """Devuelve {indice_columna: campo_canonico}."""
    out = {}
    for i, h in enumerate(headers):
        key = norm_header(h)
        if key in HEADER_MAP:
            out[i] = HEADER_MAP[key]
    return out


def detect_source(canon_fields: set, headers_norm: set) -> str:
    if "g_event" in canon_fields or any("google" in h for h in headers_norm):
        return "google"
    if any(h in headers_norm for h in (
            "sign-in error code", "client app", "clientappused",
            "código de error de inicio de sesión")):
        return "m365"
    return "?"


# =============================================================================
#  Construcción de un Evento desde una fila (dict de campo canónico -> valor)
# =============================================================================
def classify_status_m365(error: str) -> str:
    e = (error or "").strip()
    if e in ERR_SUCCESS:
        return "success"
    if e in ERR_MFA_REQUIRED or e in ERR_MFA_DENIED:
        return "interrupt"
    if e in ERR_NO_CUENTA:
        return "blocked"          # bloqueo/cierre: no es un intento de adivinar clave
    return "failure"


def classify_status_google(event: str) -> str:
    ev = (event or "").strip().lower()
    if ev in G_SUCCESS:
        return "success"
    if ev in G_FAILURE:
        return "failure"
    if ev in G_SUSPICIOUS:
        return "success"   # entró, pero el proveedor lo marcó sospechoso
    return "unknown"


def is_legacy(client: str) -> bool:
    c = (client or "").lower()
    return any(tok in c for tok in LEGACY_CLIENTS)


_ISO2 = re.compile(r"^[A-Za-z]{2}$")


def extract_country(row: dict) -> str:
    c = (row.get("country") or "").strip()
    if _ISO2.match(c):
        return c.upper()
    # A veces la ubicación viene como "Panama City, Panama, PA" o "US"
    loc = (row.get("location") or "").strip()
    if loc:
        parts = [p.strip() for p in loc.split(",") if p.strip()]
        if parts and _ISO2.match(parts[-1]):
            return parts[-1].upper()
    # Si country trae un nombre largo, no lo convertimos (sin tablas externas).
    # Se limpia porque es texto del registro (entrada no confiable).
    return limpiar(c, 40)


def build_event(row: dict, source: str, line: int) -> Evento:
    raw_ts = row.get("ts", "")
    ts = parse_ts(raw_ts)

    # usuario: preferir UPN/correo; si falta, usar el nombre para mostrar
    user = (row.get("user") or row.get("user_display") or "").strip().lower()

    client = (row.get("client") or "").strip()
    error = (row.get("error") or "").strip()

    if source == "google":
        status = classify_status_google(row.get("g_event", ""))
        suspicious = (row.get("g_event", "").strip().lower() in G_SUSPICIOUS)
    else:
        status = classify_status_m365(error)
        suspicious = False

    return Evento(
        ts=ts,
        raw_ts=raw_ts.strip(),
        user=user,
        ip=(row.get("ip") or "").strip(),
        country=extract_country(row),
        city=(row.get("city") or "").strip(),
        lat=to_float(row.get("lat")),
        lon=to_float(row.get("lon")),
        status=status,
        error=error,
        client=client,
        app=(row.get("app") or "").strip(),
        legacy=is_legacy(client),
        suspicious_src=suspicious,
        source=source,
        line=line,
    )


# =============================================================================
#  Lectura de archivos (CSV y JSON)
# =============================================================================
def rows_from_csv(text: str):
    """Genera dicts canónicos a partir de un CSV (maneja comillas y comas)."""
    # Sniff del delimitador entre coma, punto y coma y tabulador.
    sample = text[:4096]
    delim = ","
    try:
        dialect = csv.Sniffer().sniff(sample, delimiters=",;\t")
        delim = dialect.delimiter
    except csv.Error:
        pass
    reader = csv.reader(io.StringIO(text), delimiter=delim)
    try:
        headers = next(reader)
    except StopIteration:
        return
    headers_norm = {norm_header(h) for h in headers}
    cmap = map_headers(headers)
    canon_fields = set(cmap.values())
    source = detect_source(canon_fields, headers_norm)
    for n, rec in enumerate(reader, start=2):
        row = {}
        for i, val in enumerate(rec):
            field_name = cmap.get(i)
            # Si dos columnas mapean al mismo campo (p. ej. Email y Username),
            # nos quedamos con el primer valor NO vacío.
            if field_name and not row.get(field_name):
                row[field_name] = val
        if any(row.values()):
            yield row, source, n


def _iter_json_records(data):
    """Normaliza las formas comunes de JSON a una lista de dicts."""
    if isinstance(data, dict):
        for key in ("value", "records", "signIns", "items", "data"):
            if isinstance(data.get(key), list):
                return data[key]
        return [data]
    if isinstance(data, list):
        return data
    return []


def _flatten_json_obj(obj: dict) -> dict:
    """Aplana un registro de Entra ID (Graph) a campos canónicos."""
    row = {}
    g = obj.get

    def pick(*keys):
        for k in keys:
            v = g(k)
            if v not in (None, ""):
                return v
        return ""

    row["ts"] = pick("createdDateTime", "Date (UTC)", "date", "ts", "time")
    row["user"] = pick("userPrincipalName", "userName", "user", "email",
                       "actor_email")
    row["user_display"] = pick("userDisplayName")
    row["ip"] = pick("ipAddress", "ip", "ip_address")
    row["app"] = pick("appDisplayName", "application", "app")
    row["client"] = pick("clientAppUsed", "clientApp", "client")

    status = obj.get("status")
    if isinstance(status, dict):
        row["error"] = str(status.get("errorCode", ""))
        row["reason"] = status.get("failureReason", "") or ""
    else:
        row["error"] = str(pick("errorCode", "Sign-in error code", "error"))

    loc = obj.get("location")
    if isinstance(loc, dict):
        row["city"] = loc.get("city", "") or ""
        row["state"] = loc.get("state", "") or ""
        row["country"] = loc.get("countryOrRegion", "") or loc.get("country", "") or ""
        geo = loc.get("geoCoordinates")
        if isinstance(geo, dict):
            row["lat"] = geo.get("latitude")
            row["lon"] = geo.get("longitude")
    else:
        row["country"] = pick("country", "countryOrRegion")
        row["city"] = pick("city")
        row["location"] = pick("location")

    # Google audit API: name del evento
    if "events" in obj or "actor" in obj:
        actor = obj.get("actor")
        if isinstance(actor, dict) and not row["user"]:
            row["user"] = actor.get("email", "") or ""
        evs = obj.get("events")
        if isinstance(evs, list) and evs and isinstance(evs[0], dict):
            row["g_event"] = evs[0].get("name", "") or ""
    else:
        row["g_event"] = pick("event", "eventName")
    return row


def rows_from_json(text: str):
    data = json.loads(text)                       # puede lanzar ValueError
    records = _iter_json_records(data)
    source_hint = "?"
    for n, obj in enumerate(records, start=1):
        if not isinstance(obj, dict):
            continue
        row = _flatten_json_obj(obj)
        if source_hint == "?":
            if row.get("g_event"):
                source_hint = "google"
            elif row.get("client") or row.get("error"):
                source_hint = "m365"
        yield row, source_hint, n


def rows_from_jsonlines(text: str):
    for n, ln in enumerate(text.splitlines(), start=1):
        ln = ln.strip()
        if not ln:
            continue
        obj = json.loads(ln)
        if isinstance(obj, dict):
            row = _flatten_json_obj(obj)
            src = "google" if row.get("g_event") else "m365"
            yield row, src, n


def read_events(text: str, forced_fmt: str | None) -> list:
    """Lee el contenido y devuelve una lista de Eventos."""
    text = text.lstrip("﻿")                  # quita BOM si existe
    stripped = text.lstrip()
    fmt = forced_fmt
    if fmt is None:
        if stripped[:1] == "[":
            fmt = "json"                          # array JSON
        elif stripped[:1] == "{":
            # Un objeto JSON entero, o varias líneas de objetos (JSON Lines).
            # Probar el texto completo como un solo JSON; si falla, es JSON Lines.
            try:
                json.loads(text)
                fmt = "json"
            except ValueError:
                fmt = "jsonl"
        else:
            fmt = "csv"

    eventos = []
    if fmt == "json":
        gen = rows_from_json(text)
    elif fmt == "jsonl":
        gen = rows_from_jsonlines(text)
    else:
        gen = rows_from_csv(text)

    for row, source, line in gen:
        eventos.append(build_event(row, source, line))
    return eventos


# =============================================================================
#  Motor de detección
# =============================================================================
class Config:
    def __init__(self, args):
        self.home = (args.pais or HOME_COUNTRY_DEFAULT).upper()
        self.brute_fails = args.umbral_fallos
        self.brute_win = args.ventana_fallos
        self.spray_users = args.umbral_spray
        self.spray_win = args.ventana_spray
        self.mfa_fatigue = args.umbral_mfa
        self.travel_kmh = args.velocidad
        self.travel_min_km = DEF_TRAVEL_MIN_KM


def _sorted_by_time(evs: list) -> list:
    return sorted(evs, key=lambda e: (e.ts is None, e.ts or datetime.min.replace(tzinfo=timezone.utc)))


def detectar(eventos: list, cfg: Config) -> list:
    hallazgos: list = []
    por_usuario: dict = defaultdict(list)
    for e in eventos:
        if e.user:
            por_usuario[e.user].append(e)

    # ---- Reglas por usuario -------------------------------------------------
    for user, evs in por_usuario.items():
        evs = _sorted_by_time(evs)
        _regla_legacy(user, evs, hallazgos)
        _regla_bruteforce(user, evs, cfg, hallazgos)
        _regla_mfa_fatiga(user, evs, cfg, hallazgos)
        _regla_viaje_imposible(user, evs, cfg, hallazgos)
        _regla_pais_nuevo(user, evs, cfg, hallazgos)
        _regla_sospechoso_proveedor(user, evs, hallazgos)

    # ---- Reglas por IP (spray) ----------------------------------------------
    _regla_spray(eventos, cfg, hallazgos)

    hallazgos.sort(key=lambda h: (-SEV_ORDER.get(h.sev, 0), h.user, h.code))
    return hallazgos


def _regla_legacy(user, evs, out):
    hits = [e for e in evs if e.legacy and e.status in ("success", "failure", "interrupt")]
    exitosos = [e for e in hits if e.status == "success"]
    if exitosos:
        clientes = sorted({limpiar(e.client, 40) for e in exitosos})
        out.append(Hallazgo(
            "critico", "LEGACY-AUTH-SUCCESS", user,
            f"Inició sesión con un protocolo viejo que NO pide doble factor "
            f"({', '.join(clientes)}). Es la forma típica de usar una clave robada "
            f"saltándose el MFA.",
            "T1078.004",
            [f"línea {e.line}: {limpiar(e.ip)} {limpiar(e.client,40)}" for e in exitosos[:5]],
        ))
    elif hits:
        clientes = sorted({limpiar(e.client, 40) for e in hits})
        out.append(Hallazgo(
            "medio", "LEGACY-AUTH-ATTEMPT", user,
            f"Hubo intentos con protocolos viejos sin doble factor "
            f"({', '.join(clientes)}). Conviene bloquear la autenticación heredada.",
            "T1078.004",
            [f"línea {e.line}: {limpiar(e.ip)}" for e in hits[:5]],
        ))


def _regla_bruteforce(user, evs, cfg, out):
    fails = [e for e in evs if e.status == "failure" and e.ts]
    if len(fails) < cfg.brute_fails:
        # igual revisamos éxito tras muchos fallos sin ts fiable
        pass
    # ventana deslizante sobre los fallos ordenados por tiempo
    marcado = False
    i = 0
    worst = []
    for j in range(len(fails)):
        while fails[j].ts and fails[i].ts and (fails[j].ts - fails[i].ts).total_seconds() > cfg.brute_win:
            i += 1
        if j - i + 1 >= cfg.brute_fails:
            worst = fails[i:j + 1]
            marcado = True
    # ¿hubo un éxito poco después del último fallo de una racha?
    exito_tras_racha = None
    if marcado and worst:
        t_fin = worst[-1].ts
        for e in evs:
            if (e.status == "success" and e.ts and t_fin
                    and 0 <= (e.ts - t_fin).total_seconds() <= cfg.brute_win):
                exito_tras_racha = e
                break
    if exito_tras_racha:
        out.append(Hallazgo(
            "critico", "BRUTE-SUCCESS", user,
            f"{len(worst)} intentos fallidos seguidos y luego un inicio de sesión "
            f"correcto desde {limpiar(exito_tras_racha.ip)}. Posible cuenta adivinada "
            f"por fuerza bruta.",
            "T1110.001",
            [f"éxito en línea {exito_tras_racha.line}"],
        ))
    elif marcado:
        out.append(Hallazgo(
            "alto", "BRUTE-FORCE", user,
            f"{len(worst)} intentos fallidos en menos de {cfg.brute_win // 60} min. "
            f"Alguien está probando contraseñas contra esta cuenta.",
            "T1110.001",
            [f"líneas {worst[0].line}–{worst[-1].line}"],
        ))


def _regla_mfa_fatiga(user, evs, cfg, out):
    # Cuenta pedidos/denegaciones de MFA seguidos y luego un éxito.
    # La fatiga de MFA se basa en rechazos/no respuestas repetidos (500121),
    # no en simples solicitudes de MFA (50074), que son normales a diario.
    streak = 0
    inicio = None
    for e in evs:
        es_mfa = (e.error in ERR_MFA_DENIED
                  or (e.source == "google" and e.status == "interrupt"))
        if es_mfa:
            streak += 1
            if inicio is None:
                inicio = e
        elif e.status == "success":
            if streak >= cfg.mfa_fatigue:
                out.append(Hallazgo(
                    "alto", "MFA-FATIGUE", user,
                    f"{streak} solicitudes de doble factor seguidas y después un "
                    f"acceso correcto. Puede ser 'fatiga de MFA': bombardean al "
                    f"usuario con avisos hasta que acepta uno por error.",
                    "T1621",
                    [f"desde línea {inicio.line if inicio else '?'}"],
                ))
            streak = 0
            inicio = None
        else:
            streak = 0
            inicio = None


def _regla_viaje_imposible(user, evs, cfg, out):
    exitosos = [e for e in evs if e.status == "success" and e.ts]
    reportados = 0

    # 1) Con coordenadas: comparar accesos geolocalizados ENTRE SÍ (consecutivos),
    #    para que un acceso sin coordenadas en medio no tape un viaje imposible.
    con_coords = [e for e in exitosos if None not in (e.lat, e.lon)]
    for a, b in zip(con_coords, con_coords[1:]):
        if reportados >= 3:
            break
        dt = (b.ts - a.ts).total_seconds()
        if dt < 0:
            continue
        dist = haversine_km(a.lat, a.lon, b.lat, b.lon)
        if dist < cfg.travel_min_km:
            continue
        vel = float("inf") if dt <= 0 else dist / (dt / 3600.0)
        if vel > cfg.travel_kmh:
            out.append(Hallazgo(
                "alto", "IMPOSSIBLE-TRAVEL", user,
                f"Dos accesos correctos a {int(dist)} km de distancia en "
                f"{_fmt_dur(dt)} ({limpiar(a.city) or limpiar(a.country)} → "
                f"{limpiar(b.city) or limpiar(b.country)}). Imposible viajar tan "
                f"rápido: una de las dos sesiones no es del usuario.",
                "T1078",
                [f"líneas {a.line} y {b.line}"],
            ))
            reportados += 1

    # 2) Sin coordenadas: cambio de país en menos de 1 hora (señal más débil).
    sin_coords = [e for e in exitosos if None in (e.lat, e.lon) and e.country]
    for a, b in zip(sin_coords, sin_coords[1:]):
        if reportados >= 3:
            break
        dt = (b.ts - a.ts).total_seconds()
        if a.country != b.country and 0 <= dt < 3600:
            out.append(Hallazgo(
                "medio", "FAST-COUNTRY-CHANGE", user,
                f"Dos accesos correctos desde países distintos ({limpiar(a.country,8)} → "
                f"{limpiar(b.country,8)}) en {_fmt_dur(dt)}. Revisa si el usuario viajó "
                f"o usa VPN.",
                "T1078",
                [f"líneas {a.line} y {b.line}"],
            ))
            reportados += 1


def _regla_pais_nuevo(user, evs, cfg, out):
    exitosos = [e for e in evs if e.status == "success" and e.country]
    if len(exitosos) < 2:
        return
    vistos = set()
    for e in exitosos:
        vistos.add(e.country)
    extranjeros = sorted(c for c in vistos if c != cfg.home)
    if not extranjeros:
        return
    if cfg.home in vistos:
        # Casi todo es del país propio y aparece acceso extranjero.
        out.append(Hallazgo(
            "medio", "NEW-COUNTRY", user,
            f"Accesos correctos desde fuera de {cfg.home}: "
            f"{', '.join(limpiar(c, 8) for c in extranjeros)}. Confírmalo con la persona.",
            "T1078", []))
    else:
        # TODOS los accesos correctos son del extranjero: más sospechoso aún.
        out.append(Hallazgo(
            "alto", "ALL-FOREIGN", user,
            f"Todos los accesos correctos son desde fuera de {cfg.home} "
            f"({', '.join(limpiar(c, 8) for c in extranjeros)}). Si la persona trabaja "
            f"desde {cfg.home}, la cuenta puede estar en manos de otro.",
            "T1078", []))


def _regla_sospechoso_proveedor(user, evs, out):
    sosp = [e for e in evs if e.suspicious_src]
    if sosp:
        out.append(Hallazgo(
            "alto", "PROVIDER-FLAGGED", user,
            f"El propio Google marcó {len(sosp)} inicio(s) de sesión como "
            f"sospechosos. Trátalo como cuenta en riesgo hasta confirmar.",
            "T1078",
            [f"línea {e.line}: {limpiar(e.ip)}" for e in sosp[:5]],
        ))


def _regla_spray(eventos, cfg, out):
    por_ip = defaultdict(list)
    for e in eventos:
        if e.ip and e.status in ("failure", "success") and e.ts:
            por_ip[e.ip].append(e)
    for ip, evs in por_ip.items():
        evs = _sorted_by_time(evs)
        i = 0
        peor_usuarios = set()
        for j in range(len(evs)):
            while evs[j].ts and evs[i].ts and (evs[j].ts - evs[i].ts).total_seconds() > cfg.spray_win:
                i += 1
            ventana = evs[i:j + 1]
            usuarios = {e.user for e in ventana if e.user}
            if len(usuarios) > len(peor_usuarios):
                peor_usuarios = usuarios
        if len(peor_usuarios) >= cfg.spray_users:
            exito = next((e for e in evs if e.status == "success" and e.user in peor_usuarios), None)
            if exito:
                out.append(Hallazgo(
                    "critico", "SPRAY-SUCCESS", "(varios)",
                    f"La IP {limpiar(ip)} probó contraseñas contra "
                    f"{len(peor_usuarios)} usuarios distintos y al menos uno "
                    f"({limpiar(exito.user)}) entró. Rociado de contraseñas con éxito.",
                    "T1110.003",
                    sorted(limpiar(u) for u in list(peor_usuarios)[:8]),
                ))
            else:
                out.append(Hallazgo(
                    "alto", "PASSWORD-SPRAY", "(varios)",
                    f"La IP {limpiar(ip)} intentó entrar a {len(peor_usuarios)} "
                    f"usuarios distintos en poco tiempo. Rociado de contraseñas.",
                    "T1110.003",
                    sorted(limpiar(u) for u in list(peor_usuarios)[:8]),
                ))


def _fmt_dur(seg: float) -> str:
    seg = int(seg)
    if seg < 60:
        return f"{seg} s"
    if seg < 3600:
        return f"{seg // 60} min"
    return f"{seg // 3600} h {(seg % 3600) // 60} min"


# =============================================================================
#  Veredicto y salida
# =============================================================================
def veredicto(hallazgos: list) -> tuple:
    peor = max((SEV_ORDER.get(h.sev, 0) for h in hallazgos), default=0)
    if peor >= 4:
        return "PELIGROSO", 3
    if peor == 3:
        return "PELIGROSO", 3
    if peor >= 1:
        return "SOSPECHOSO", 1
    return "SIN INDICIOS CLAROS", 0


_SEV_TAG = {"critico": "CRÍTICO", "alto": "ALTO", "medio": "MEDIO",
            "bajo": "BAJO", "info": "INFO"}


def anonimizar_user(u: str) -> str:
    if not u:
        return ""
    if "@" in u:
        _, dom = u.split("@", 1)
        return "***@" + dom
    return "***"


def anonimizar_ip(ip: str) -> str:
    if ":" in ip:
        return ip.split(":")[0] + ":***"
    parts = ip.split(".")
    if len(parts) == 4:
        return ".".join(parts[:2]) + ".x.x"
    return "***"


def render_texto(eventos, hallazgos, cfg, anon, detalle) -> str:
    out = []
    v, _ = veredicto(hallazgos)
    usuarios = len({e.user for e in eventos if e.user})
    buenos = sum(1 for e in eventos if e.status == "success")
    malos = sum(1 for e in eventos if e.status == "failure")
    sin_ts = sum(1 for e in eventos if e.ts is None)

    out.append(f"cuentas-escudo v{VERSION} — revisión de inicios de sesión")
    out.append("")
    out.append(f"  Veredicto: {v}")
    out.append(f"  Eventos: {len(eventos)}  ·  usuarios: {usuarios}  ·  "
               f"correctos: {buenos}  ·  fallidos: {malos}")
    if sin_ts:
        out.append(f"  Aviso: {sin_ts} evento(s) sin fecha legible; "
                   f"no entran en las reglas por tiempo.")
    out.append("")

    if not hallazgos:
        out.append("No se encontraron señales claras de cuentas comprometidas.")
        out.append("Esto no garantiza que todo esté bien: un robo bien hecho")
        out.append("puede no dejar rastro en estos registros.")
        return "\n".join(out)

    out.append("Señales encontradas (de más a menos grave):")
    out.append("")
    for h in hallazgos:
        u = anonimizar_user(h.user) if anon else h.user
        u = limpiar(u, 80) if u != "(varios)" else u
        out.append(f"  [{_SEV_TAG.get(h.sev, h.sev.upper())}] {h.code}  ·  {u}")
        out.append(f"      {limpiar(h.msg, 600)}")
        if detalle:
            if h.mitre:
                out.append(f"      MITRE ATT&CK: {h.mitre}")
            for ev in h.evidencia:
                out.append(f"      · {limpiar(ev, 120)}")
        out.append("")

    out.append("Qué hacer:")
    out.append("  1. Con las cuentas marcadas CRÍTICO o ALTO: cambia la contraseña ya")
    out.append("     y cierra todas las sesiones abiertas de esa cuenta.")
    out.append("  2. Activa el doble factor (MFA) si no lo tiene.")
    out.append("  3. Bloquea la autenticación heredada (IMAP/POP/SMTP básico).")
    out.append("  4. Revisa si crearon reglas de reenvío en el buzón.")
    out.append("  5. Avisa a la persona por un medio aparte (llamada), no por correo.")
    return "\n".join(out)


def render_json(eventos, hallazgos, cfg, anon) -> str:
    v, code = veredicto(hallazgos)
    lineas = []
    for h in hallazgos:
        user = h.user
        if anon and user != "(varios)":
            user = anonimizar_user(user)
        obj = {
            "tool": "cuentas-escudo",
            "version": VERSION,
            "schema_version": SCHEMA_VERSION,
            "type": "finding",
            "severity": h.sev,
            "code": h.code,
            "user": user,
            "message": limpiar(h.msg, 600),
            "mitre": h.mitre,
            "evidence": [limpiar(e, 200) for e in h.evidencia],
        }
        lineas.append(json.dumps(obj, ensure_ascii=False))
    resumen = {
        "tool": "cuentas-escudo",
        "version": VERSION,
        "schema_version": SCHEMA_VERSION,
        "type": "summary",
        "verdict": v,
        "verdict_code": code,
        "events": len(eventos),
        "users": len({e.user for e in eventos if e.user}),
        "findings": len(hallazgos),
    }
    lineas.append(json.dumps(resumen, ensure_ascii=False))
    return "\n".join(lineas)


# =============================================================================
#  Escritura segura de informes (0600, sin seguir symlinks)
# =============================================================================
def escribir_seguro(ruta: str, contenido: str):
    flags = os.O_WRONLY | os.O_CREAT | os.O_TRUNC
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        fd = os.open(ruta, flags, 0o600)
    except OSError as e:
        raise ErrorUso(f"no se pudo escribir en {ruta}: {e}") from e
    try:
        os.write(fd, contenido.encode("utf-8"))
    finally:
        os.close(fd)
    try:
        os.chmod(ruta, 0o600)
    except OSError:
        pass


# =============================================================================
#  Entrada / archivos
# =============================================================================
MAX_BYTES = 200 * 1024 * 1024   # 200 MB por archivo


def leer_texto(ruta: str) -> str:
    if ruta == "-":
        data = sys.stdin.buffer.read(MAX_BYTES + 1)
    else:
        if os.path.isdir(ruta):
            raise ErrorUso(f"{ruta} es una carpeta; pásala sin barra o usa un archivo")
        try:
            with open(ruta, "rb") as f:
                data = f.read(MAX_BYTES + 1)
        except OSError as e:
            raise ErrorUso(f"no se pudo leer {ruta}: {e}") from e
    if len(data) > MAX_BYTES:
        raise ErrorUso(f"{ruta}: archivo demasiado grande (límite {MAX_BYTES // (1024*1024)} MB)")
    return data.decode("utf-8", errors="replace")


def juntar_archivos(entradas: list) -> list:
    archivos = []
    for t in entradas:
        if t == "-":
            archivos.append("-")
        elif os.path.isdir(t):
            for nombre in sorted(os.listdir(t)):
                p = os.path.join(t, nombre)
                if os.path.isfile(p) and nombre.lower().endswith((".csv", ".json", ".jsonl", ".log")):
                    archivos.append(p)
        else:
            archivos.append(t)
    return archivos


# =============================================================================
#  Main
# =============================================================================
def construir_parser():
    p = argparse.ArgumentParser(
        prog="cuentas-escudo",
        description="Detecta cuentas comprometidas en registros de inicio de sesión "
                    "de Microsoft 365 o Google Workspace (sin usar internet).",
        epilog="Códigos de salida: 0 sin indicios · 1 sospechoso · 3 peligroso · 2 error.",
    )
    p.add_argument("archivos", nargs="*", help="archivos CSV/JSON, carpetas, o - para la entrada estándar")
    p.add_argument("--formato", choices=("auto", "csv", "json", "jsonl"), default="auto",
                   help="formato de entrada (por defecto se detecta solo)")
    p.add_argument("--salida", choices=("texto", "json"), default="texto",
                   help="texto para leer, json (JSON Lines) para un SIEM")
    p.add_argument("-o", "--guardar", metavar="ARCHIVO", help="guarda el informe (permisos 600)")
    p.add_argument("--pais", default=HOME_COUNTRY_DEFAULT,
                   help=f"país propio en código de 2 letras (por defecto {HOME_COUNTRY_DEFAULT})")
    p.add_argument("--anonimizar", action="store_true",
                   help="oculta usuarios e IPs para compartir el informe (Ley 81)")
    p.add_argument("--detalle", action="store_true",
                   help="muestra técnicas MITRE ATT&CK y evidencia")
    p.add_argument("--umbral-fallos", type=int, default=DEF_BRUTE_FAILS)
    p.add_argument("--ventana-fallos", type=int, default=DEF_BRUTE_WIN)
    p.add_argument("--umbral-spray", type=int, default=DEF_SPRAY_USERS)
    p.add_argument("--ventana-spray", type=int, default=DEF_SPRAY_WIN)
    p.add_argument("--umbral-mfa", type=int, default=DEF_MFA_FATIGUE)
    p.add_argument("--velocidad", type=float, default=DEF_TRAVEL_KMH,
                   help="velocidad imposible en km/h para el viaje imposible")
    p.add_argument("--version", action="version", version=f"cuentas-escudo v{VERSION}")
    return p


def validar_args(args):
    for nombre, val in (("--umbral-fallos", args.umbral_fallos),
                        ("--ventana-fallos", args.ventana_fallos),
                        ("--umbral-spray", args.umbral_spray),
                        ("--ventana-spray", args.ventana_spray),
                        ("--umbral-mfa", args.umbral_mfa)):
        if val <= 0:
            raise ErrorUso(f"{nombre} debe ser mayor que 0")
    if not math.isfinite(args.velocidad) or args.velocidad <= 0:
        raise ErrorUso("--velocidad debe ser un número mayor que 0")
    if not re.match(r"^[A-Za-z]{2}$", args.pais):
        raise ErrorUso("--pais debe ser un código de 2 letras, por ejemplo PA")


def main(argv=None) -> int:
    parser = construir_parser()
    args = parser.parse_args(argv)
    try:
        validar_args(args)
        if not args.archivos:
            raise ErrorUso("falta el archivo de registros (usa - para la entrada estándar). "
                           "Prueba con -h para ver la ayuda.")
        cfg = Config(args)
        archivos = juntar_archivos(args.archivos)
        if not archivos:
            raise ErrorUso("no se encontró ningún archivo CSV/JSON que analizar")

        eventos = []
        forced = None if args.formato == "auto" else args.formato
        for ruta in archivos:
            texto = leer_texto(ruta)
            try:
                eventos.extend(read_events(texto, forced))
            except (ValueError, AttributeError, TypeError, KeyError) as e:
                raise ErrorUso(f"{ruta}: no se pudo leer como "
                               f"{args.formato} ({e})") from e

        if not eventos:
            raise ErrorUso("no se encontró ningún inicio de sesión en los datos "
                           "(¿es un export de Microsoft 365 o Google?)")

        hallazgos = detectar(eventos, cfg)

        if args.salida == "json":
            salida = render_json(eventos, hallazgos, cfg, args.anonimizar)
        else:
            salida = render_texto(eventos, hallazgos, cfg, args.anonimizar, args.detalle)

        if args.guardar:
            escribir_seguro(args.guardar, salida + "\n")
            eprint(f"Informe guardado en {args.guardar} (permisos 600)")
        else:
            print(salida)

        _, code = veredicto(hallazgos)
        return code
    except ErrorUso as e:
        eprint(f"Error: {e}")
        return 2
    except BrokenPipeError:
        try:
            sys.stdout.close()
        except Exception:
            pass
        return 0
    except KeyboardInterrupt:
        return 2


if __name__ == "__main__":
    sys.exit(main())

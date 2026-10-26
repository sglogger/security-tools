#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
2shell-detector.py - Detector fuer PHP2Shell und Node2Shell/HTTP2Shell

  PHP2Shell               CVE-2026-109618, CVE-2026-109619 (PHP-Core, pre-auth RCE)
  Node2Shell / HTTP2Shell CVE-2026-111497 (Google Brotli Decoder 1.0.3-1.2.0, OOB write)

Nur Erkennung, aendert nichts. Nur Python-Stdlib (>= 3.8), laeuft auf macOS und Linux.

Statische Analyse pro Repo/Container-Verzeichnis:
  Dockerfile*, docker-compose*/compose* (+ .env), .nvmrc, .node-version, .php-version,
  .tool-versions, package.json (+ volta), package-lock/yarn.lock/pnpm-lock,
  requirements*.txt, pyproject.toml, poetry.lock, uv.lock, pdm.lock, Pipfile.lock,
  go.mod, Cargo.lock, *.csproj, vendorte Brotli-Quellen (version.h) und libbrotli*-Binaries.

Laufzeit-Analyse (--docker): fuehrt per `docker exec` in jedem laufenden Container
`php -v` aus (Fallback: php-fpm -v / php-cgi -v) und zeigt die Ausgabe als Beleg; dazu
node -v, bun -v, Python-Brotli und Distro-libbrotli. Das ist die verlaessliche Quelle,
v.a. bei floating Tags (php:8.3-fpm, wordpress:latest, node:lts). Gestoppte Container
werden nicht geprueft. Compose-Projektverzeichnis wird pro Container mit angezeigt.

Beispiele:
  ./2shell-detector.py                                  # Default-Roots, falls vorhanden
  ./2shell-detector.py ~/SourceCode
  ./2shell-detector.py /data/docker-containers --docker
  ./2shell-detector.py ~/SourceCode/meinrepo -v         # inkl. OK-Befunde
  ./2shell-detector.py --json > report.json

Exit-Code: 2 = AFFECTED/EOL gefunden, 1 = nur UNPINNED/REVIEW, 0 = sauber.

Versionsstand der Fix-Tabellen: 26.10.2026
  PHP:    8.2.35, 8.3.36, 8.4.27, 8.5.12 (<= 8.1 EOL, kein Upstream-Fix)
  Node:   22.23.4, 24.22.1, 26.12.1 (20.x, 23.x, 25.x und aelter EOL, kein Fix)
  Bun:    1.4.4
  Brotli: 1.0.10, 1.1.1, 1.2.1 (lib, PyPI Brotli; brotlicffi 1.2.1.0)
"""

import argparse
import json
import os
import re
import subprocess
import sys
from datetime import datetime

# --------------------------------------------------------------------------- #
# Fix-Tabellen
# --------------------------------------------------------------------------- #

CVE_PHP = "CVE-2026-109618/-109619"
CVE_BROTLI = "CVE-2026-111497"

PHP_FIXED = {(8, 2): (8, 2, 35), (8, 3): (8, 3, 36), (8, 4): (8, 4, 27), (8, 5): (8, 5, 12)}
NODE_FIXED = {22: (22, 23, 4), 24: (24, 22, 1), 26: (26, 12, 1)}
BUN_FIXED = (1, 4, 4)
BROTLI_FIXED = {(1, 0): (1, 0, 10), (1, 1): (1, 1, 1), (1, 2): (1, 2, 1)}

AFFECTED, EOL, UNPINNED, REVIEW, INFO, OK = "AFFECTED", "EOL", "UNPINNED", "REVIEW", "INFO", "OK"
ORDER = {AFFECTED: 0, EOL: 1, UNPINNED: 2, REVIEW: 3, INFO: 4, OK: 5}

DEFAULT_ROOTS = ["~/SourceCode", "/data/docker-containers"]

SKIP_DIRS = {"__pycache__", ".git", "dist", "coverage", "uploads", "cache", "logs"}
DEEP_DIRS = {"node_modules", "vendor", "venv", "env", ".venv", "bower_components", "site-packages"}

UNIT_MARKERS = re.compile(
    r"^(Dockerfile.*|.*\.Dockerfile|(docker-)?compose.*\.ya?ml|package\.json|composer\.json|"
    r"requirements.*\.txt|pyproject\.toml|go\.mod|\.nvmrc|\.node-version|\.tool-versions)$",
    re.I,
)

# Images mit PHP im Bauch, deren Tag die PHP-Version nicht oder nur optional nennt
PHP_APPS = {
    "wordpress", "drupal", "joomla", "nextcloud", "matomo", "phpmyadmin", "mediawiki", "typo3",
    "prestashop", "magento", "moodle", "roundcubemail", "roundcube", "freshrss", "wallabag",
    "kimai", "bookstack", "limesurvey", "mautic", "suitecrm", "dolibarr", "glpi", "friendica",
    "invoiceninja", "grav", "snipe-it", "librenms", "leantime", "monica", "firefly-iii",
}
# Images mit Node im Bauch
NODE_APPS = {
    "ghost", "n8n", "node-red", "uptime-kuma", "strapi", "verdaccio", "etherpad", "outline",
    "nocodb", "directus", "homepage", "code-server", "rocket.chat", "mattermost-push-proxy",
    "actual-server", "hedgedoc", "wiki", "flowise", "budibase", "appsmith", "nodebb",
}

# npm-Pakete, die Brotli-Request-Bodies standardmaessig dekomprimieren (Inbound-Pfad)
INBOUND_PKGS = {
    "express": 5, "body-parser": 2, "@fastify/compress": 0,
    "koa-body": 0, "koa-bodyparser": 0, "@koa/bodyparser": 0,
}

# --------------------------------------------------------------------------- #
# Helpers
# --------------------------------------------------------------------------- #


def vt(s):
    m = re.match(r"\s*[vV]?(\d+(?:\.\d+)*)", s or "")
    return tuple(int(x) for x in m.group(1).split(".")) if m else ()


def vs(t):
    return ".".join(str(x) for x in t)


def read(path, limit=5 * 1024 * 1024):
    try:
        if os.path.getsize(path) > limit:
            return None
        with open(path, "r", encoding="utf-8", errors="replace") as fh:
            return fh.read()
    except OSError:
        return None


VAR_RE = re.compile(r"\$\{(\w+)(?::?-([^}]*))?\}|\$(\w+)")


def subst(s, env):
    def repl(m):
        name = m.group(1) or m.group(3)
        if env.get(name):
            return env[name]
        if m.group(2) is not None:
            return m.group(2)
        return m.group(0)
    return VAR_RE.sub(repl, s)


def load_dotenv(path):
    env = {}
    text = read(path, 512 * 1024)
    if not text:
        return env
    for line in text.splitlines():
        m = re.match(r"\s*(?:export\s+)?([A-Za-z_]\w*)\s*=\s*(.*)$", line)
        if m:
            env[m.group(1)] = m.group(2).strip().strip("'\"")
    return env


# --------------------------------------------------------------------------- #
# Bewertung
# --------------------------------------------------------------------------- #


def eval_php(ver):
    v = vt(ver)
    if not v:
        return UNPINNED, "keine PHP-Version erkennbar -> Laufzeit pruefen (--docker)"
    if len(v) < 2:
        return UNPINNED, "nur Major %d gepinnt -> Laufzeit pruefen (--docker)" % v[0]
    mm = v[:2]
    if mm < (8, 2):
        return EOL, "PHP %s ist EOL, kein Upstream-Fix -> Upgrade auf >= 8.2.35" % vs(mm)
    if mm > max(PHP_FIXED):
        return OK, "neuer als die gefixten Branches"
    fix = PHP_FIXED[mm]
    if len(v) < 3:
        return UNPINNED, "floating %s, gefixt ab %s -> Image neu pullen/builden und verifizieren" % (vs(mm), vs(fix))
    if v[:3] < fix:
        return AFFECTED, "Fix: %s" % vs(fix)
    return OK, "gefixt (>= %s)" % vs(fix)


def eval_node(ver):
    v = vt(ver)
    if not v:
        return UNPINNED, "keine Node-Version erkennbar (lts/latest?) -> Laufzeit pruefen (--docker)"
    major = v[0]
    if major > max(NODE_FIXED):
        return OK, "neuer als die gefixten Lines"
    if major not in NODE_FIXED:
        return EOL, "Node %d ist EOL, kein Fix -> 22.23.4 / 24.22.1 / 26.12.1" % major
    fix = NODE_FIXED[major]
    if len(v) < 3:
        return UNPINNED, "floating %d, gefixt ab %s -> neu pullen/builden und verifizieren" % (major, vs(fix))
    if v[:3] < fix:
        return AFFECTED, "Fix: %s" % vs(fix)
    return OK, "gefixt (>= %s)" % vs(fix)


def eval_bun(ver):
    v = vt(ver)
    if len(v) < 3:
        return UNPINNED, "Bun nicht exakt gepinnt, gefixt ab %s" % vs(BUN_FIXED)
    if v[:3] < BUN_FIXED:
        return AFFECTED, "Fix: %s" % vs(BUN_FIXED)
    return OK, "gefixt (>= %s)" % vs(BUN_FIXED)


def eval_brotli(ver):
    v = vt(ver)
    if len(v) < 3:
        return UNPINNED, "Brotli-Version nicht exakt (%s) -> Lockfile/Laufzeit pruefen" % (ver or "?")
    v3 = v[:3]
    if v3 < (1, 0, 3):
        return OK, "vor 1.0.3, nicht betroffen"
    br = v3[:2]
    if br > max(BROTLI_FIXED):
        return OK, "neuer als die gefixten Branches"
    fix = BROTLI_FIXED[br]
    if v3 < fix:
        return AFFECTED, "Fix: %s" % vs(fix)
    return OK, "gefixt (>= %s)" % vs(fix)


def eval_deb_brotli(pkgver):
    upstream = pkgver.split(":")[-1].split("-")[0]
    st, d = eval_brotli(upstream)
    if st == OK:
        return st, d
    if re.search(r"\+deb1[23]u\d+", pkgver):
        return OK, "Debian-Security-Fix (%s)" % pkgver
    if re.search(r"ubuntu\d", pkgver):
        return REVIEW, "Ubuntu-Security-Update %s -> Ubuntu Security Tracker pruefen" % pkgver
    if "ubuntu" in pkgver or "build" in pkgver:
        return AFFECTED, "Ubuntu-Paket %s ohne Security-Update -> Ubuntu Security Tracker pruefen" % pkgver
    return AFFECTED, "Distro-Paket %s ohne Fix (bookworm: 1.0.9-2+deb12u1, trixie: 1.1.0-2+deb13u1)" % pkgver


# --------------------------------------------------------------------------- #
# Findings
# --------------------------------------------------------------------------- #


class Unit(object):
    def __init__(self, name, path, kind="repo"):
        self.name, self.path, self.kind = name, path, kind
        self.findings = []
        self.inbound = set()
        self.has_php = False
        self.has_node = False
        self._seen = set()

    def add(self, component, version, status, detail, file=None, line=None, cve=None):
        key = (component, str(version), file)
        if key in self._seen:
            return
        self._seen.add(key)
        if cve is None:
            cve = CVE_PHP if component.startswith("PHP") else CVE_BROTLI
        rel = os.path.relpath(file, self.path) if file and self.path else (file or "")
        self.findings.append({
            "unit": self.name, "kind": self.kind, "status": status, "component": component,
            "version": str(version), "cve": cve, "file": rel, "line": line, "detail": detail,
        })

    def worst(self):
        if not self.findings:
            return OK
        return min((f["status"] for f in self.findings), key=lambda s: ORDER[s])


# --------------------------------------------------------------------------- #
# Image-Referenzen
# --------------------------------------------------------------------------- #


def parse_image(ref):
    ref = ref.split("@")[0]
    last = ref.rsplit("/", 1)[-1]
    tag = ""
    name = ref
    if ":" in last:
        tag = last.split(":", 1)[1]
        name = ref[: -(len(tag) + 1)]
    base = name.rsplit("/", 1)[-1].lower()
    return name.lower(), base, tag


def eval_image(ref):
    """-> Liste von (component, version, status, detail)"""
    if "$" in ref:
        return [("Image", ref, UNPINNED, "Variable nicht aufloesbar -> Laufzeit pruefen (--docker)")]
    name, base, tag = parse_image(ref)
    t = tag.lower()
    out = []

    if base == "bun" or name.endswith("oven/bun"):
        m = re.match(r"v?(\d+(?:\.\d+){0,2})", t)
        if m:
            st, d = eval_bun(m.group(1))
            out.append(("Bun", m.group(1), st, d))
        else:
            out.append(("Bun", tag or "latest", UNPINNED, "floating Tag -> Laufzeit pruefen (--docker)"))
    elif re.match(r"nodejs\d+$", base):
        st, d = eval_node(base[6:])
        out.append(("Node.js", base[6:], st, "%s · %s" % (base, d)))
    elif base in ("node", "nodejs"):
        m = re.match(r"v?(\d+(?:\.\d+){0,2})", t)
        if m:
            st, d = eval_node(m.group(1))
            out.append(("Node.js", m.group(1), st, d))
        else:
            out.append(("Node.js", tag or "latest", UNPINNED, "floating Tag -> Laufzeit pruefen (--docker)"))
    elif base in PHP_APPS:
        m = re.search(r"php-?(\d+(?:\.\d+){0,2})", t)
        if m:
            st, d = eval_php(m.group(1))
            out.append(("PHP (%s)" % base, m.group(1), st, d))
        else:
            out.append(("PHP (%s)" % base, tag or "latest", UNPINNED,
                        "PHP-Version nicht aus Tag ableitbar -> Laufzeit pruefen (--docker)"))
    elif "php" in base:
        m = re.match(r"(?:php-?)?(\d+(?:\.\d+){0,2})", t)
        if m:
            st, d = eval_php(m.group(1))
            out.append(("PHP", m.group(1), st, d))
        else:
            out.append(("PHP", tag or "latest", UNPINNED, "floating Tag -> Laufzeit pruefen (--docker)"))
    elif base in NODE_APPS:
        out.append(("Node.js (%s)" % base, tag or "latest", UNPINNED,
                    "Node-App-Image, Node-Version -> Laufzeit pruefen (--docker)"))

    if "envoy" in base:
        out.append(("Envoy", tag or "latest", REVIEW,
                    "Envoy buendelt Brotli (GHSA-3wvj-j6qm-62mr) -> Fixed-Version im Advisory pruefen"))
    if "dotnet" in name:
        out.append((".NET Runtime", tag or "latest", REVIEW,
                    ".NET buendelt Brotli nativ, Stand 25.10. teils ungefixt -> MS-Advisory pruefen"))
    return out


# --------------------------------------------------------------------------- #
# Parser
# --------------------------------------------------------------------------- #


def logical_lines(text):
    out, buf, start = [], "", None
    for i, raw in enumerate(text.splitlines(), 1):
        line = raw.rstrip()
        if start is None:
            start = i
        if line.lstrip().startswith("#") and buf:
            continue
        if line.endswith("\\"):
            buf += line[:-1] + " "
            continue
        buf += line
        out.append((start, buf))
        buf, start = "", None
    if buf:
        out.append((start, buf))
    return out


VERSION_VARS = {"PHP_VERSION": "PHP", "NODE_VERSION": "Node.js", "BUN_VERSION": "Bun"}
PKG_MGR = re.compile(r"\b(apt-get|apt|apk|dnf|yum|microdnf|zypper)\b")
DISTRO_PHP = re.compile(r"(?<![\w/-])php(\d(?:\.?\d+)?)?(?:-(?:fpm|cli|common|apache2))?(?![\w./-])")


def scan_dockerfile(unit, path, env):
    text = read(path)
    if text is None:
        return
    args = {}
    stages = set()
    for ln, line in logical_lines(text):
        s = line.strip()
        if not s or s.startswith("#"):
            continue
        kw, _, rest = s.partition(" ")
        kw = kw.upper()
        rest = rest.strip()

        if kw in ("ARG", "ENV"):
            pairs = re.findall(r"(\w+)=(\"[^\"]*\"|'[^']*'|\S+)", rest)
            if not pairs and kw == "ENV":
                m = re.match(r"(\w+)\s+(.+)$", rest)
                if m:
                    pairs = [(m.group(1), m.group(2))]
            for k, val in pairs:
                val = subst(val.strip("'\""), dict(args, **env))
                args[k] = env.get(k) or val
                comp = VERSION_VARS.get(k)
                if comp and re.match(r"\d", args[k]):
                    fn = {"PHP": eval_php, "Node.js": eval_node, "Bun": eval_bun}[comp]
                    st, d = fn(args[k])
                    unit.add(comp, args[k], st, "%s %s · %s" % (kw, k, d), path, ln)

        elif kw == "FROM":
            toks = [t for t in rest.split() if not t.startswith("--")]
            if not toks:
                continue
            img = subst(toks[0], dict(args, **env))
            if len(toks) >= 3 and toks[1].lower() == "as":
                stages.add(toks[2].lower())
            if img.lower() in stages or img.lower() == "scratch":
                continue
            for comp, ver, st, d in eval_image(img):
                unit.add(comp, ver, st, "FROM %s · %s" % (img, d), path, ln)

        elif kw == "RUN":
            low = rest.lower()
            if PKG_MGR.search(low):
                for m in DISTRO_PHP.finditer(low):
                    if "docker-php" in low[max(0, m.start() - 12):m.start()]:
                        continue
                    ver = m.group(1) or ""
                    if ver and "." not in ver and len(ver) == 2:
                        ver = ver[0] + "." + ver[1]
                    unit.add("PHP (Distro)", ver or "?", REVIEW,
                             "PHP aus Distro-Paketen -> Backport im Distro-Tracker pruefen bzw. --docker", path, ln)
                    break
                if re.search(r"(?<![\w-])nodejs(?![\w-])", low) and "setup_" not in low:
                    unit.add("Node.js (Distro)", "?", REVIEW,
                             "Node aus Distro-Paketen -> Version/Backport pruefen bzw. --docker", path, ln)
                if re.search(r"(?<![\w-])(libbrotli[\w-]*|brotli(-libs|-dev)?)(?![\w-])", low):
                    unit.add("libbrotli (Distro)", "?", REVIEW,
                             "native Brotli aus Distro-Paketen -> Paketversion pruefen bzw. --docker", path, ln)
            for m in re.finditer(r"setup_(\d+)\.x", low):
                st, d = eval_node(m.group(1))
                unit.add("Node.js (NodeSource)", m.group(1) + ".x", st, d, path, ln)
            for m in re.finditer(r"node-v(\d+\.\d+\.\d+)", low):
                st, d = eval_node(m.group(1))
                unit.add("Node.js", m.group(1), st, "Tarball-Download · " + d, path, ln)
            for m in re.finditer(r"bun-v(\d+\.\d+\.\d+)|bun@(\d+\.\d+\.\d+)", low):
                ver = m.group(1) or m.group(2)
                st, d = eval_bun(ver)
                unit.add("Bun", ver, st, d, path, ln)


def scan_compose(unit, path, env):
    text = read(path)
    if text is None:
        return
    for ln, line in enumerate(text.splitlines(), 1):
        m = re.match(r"\s*-?\s*image:\s*['\"]?([^'\"\s#]+)", line)
        if not m:
            continue
        img = subst(m.group(1), env)
        for comp, ver, st, d in eval_image(img):
            unit.add(comp, ver, st, "image: %s · %s" % (img, d), path, ln)


def scan_version_file(unit, path, kind):
    text = read(path, 64 * 1024) or ""
    first = next((l.strip() for l in text.splitlines() if l.strip() and not l.strip().startswith("#")), "")
    if kind == "node":
        st, d = eval_node(first)
        unit.add("Node.js", first or "?", st, d, path, 1)
    elif kind == "php":
        st, d = eval_php(first)
        unit.add("PHP", first or "?", st, d, path, 1)


def scan_tool_versions(unit, path):
    text = read(path, 64 * 1024) or ""
    for ln, line in enumerate(text.splitlines(), 1):
        parts = line.split()
        if len(parts) < 2:
            continue
        tool, ver = parts[0].lower(), parts[1]
        if tool in ("nodejs", "node"):
            st, d = eval_node(ver)
            unit.add("Node.js", ver, st, d, path, ln)
        elif tool == "php":
            st, d = eval_php(ver)
            unit.add("PHP", ver, st, d, path, ln)
        elif tool == "bun":
            st, d = eval_bun(ver)
            unit.add("Bun", ver, st, d, path, ln)


def note_inbound(unit, pkg, ver):
    min_major = INBOUND_PKGS.get(pkg)
    if min_major is None:
        return
    v = vt(ver)
    if min_major == 0 or (v and v[0] >= min_major):
        unit.inbound.add("%s@%s" % (pkg, ver))


def scan_package_json(unit, path):
    text = read(path)
    if not text:
        return
    try:
        data = json.loads(text)
    except ValueError:
        return
    if not isinstance(data, dict):
        return
    volta = data.get("volta") or {}
    if isinstance(volta, dict):
        if volta.get("node"):
            st, d = eval_node(volta["node"])
            unit.add("Node.js", volta["node"], st, "volta · " + d, path)
        if volta.get("bun"):
            st, d = eval_bun(volta["bun"])
            unit.add("Bun", volta["bun"], st, "volta · " + d, path)
    for sect in ("dependencies", "devDependencies", "optionalDependencies"):
        deps = data.get(sect) or {}
        if isinstance(deps, dict):
            for pkg, rng in deps.items():
                if pkg in INBOUND_PKGS and isinstance(rng, str):
                    m = re.search(r"(\d+(?:\.\d+)*)", rng)
                    if m and sect != "devDependencies":
                        note_inbound(unit, pkg, m.group(1))


LOCK_PATTERNS = [
    # package-lock v2/v3
    re.compile(r'"node_modules/(?:[^"]*/node_modules/)?(@?[\w./-]+)"\s*:\s*\{\s*"version"\s*:\s*"([^"]+)"'),
    # pnpm
    re.compile(r"^\s*['\"]?/?(@?[\w.-]+(?:/[\w.-]+)?)@(\d+\.\d+\.\d+)[^:\s]*['\"]?:", re.M),
    # yarn classic / berry
    re.compile(r'^"?(@?[\w.-]+(?:/[\w.-]+)?)@[^\n]*:\n\s+version:?\s+"?(\d+\.\d+\.\d+)', re.M),
]


def scan_js_lock(unit, path):
    text = read(path, 80 * 1024 * 1024)
    if not text:
        return
    for pat in LOCK_PATTERNS:
        for m in pat.finditer(text):
            if m.group(1) in INBOUND_PKGS:
                note_inbound(unit, m.group(1), m.group(2))


PY_PKGS = {"brotli": "Python Brotli", "brotlicffi": "brotlicffi"}


def py_eval(unit, pkg, spec, path, ln, src):
    comp = PY_PKGS[pkg]
    m = re.match(r"\s*===?\s*([\d.]+)", spec or "")
    if m:
        st, d = eval_brotli(m.group(1))
        unit.add(comp, m.group(1), st, "%s · %s" % (src, d), path, ln)
    else:
        unit.add(comp, (spec or "*").strip() or "*", UNPINNED,
                 "%s · nicht exakt gepinnt -> Lockfile/Laufzeit pruefen (Fix: Brotli 1.2.1 / brotlicffi 1.2.1.0)" % src,
                 path, ln)


def scan_requirements(unit, path):
    text = read(path) or ""
    for ln, line in enumerate(text.splitlines(), 1):
        line = line.split("#", 1)[0].strip()
        if not line:
            continue
        m = re.match(r"(brotli|brotlicffi)\s*((?:[=<>~!]=?|===)\s*[\w.*]+)?", line, re.I)
        if m and not re.match(r"(brotli|brotlicffi)[\w-]", line, re.I):
            py_eval(unit, m.group(1).lower(), m.group(2), path, ln, os.path.basename(path))
            continue
        e = re.match(r"([\w.-]+)\[([^\]]*)\]", line)
        if e and re.search(r"\b(brotli|speedups)\b", e.group(2), re.I):
            unit.add("Python Brotli (Extra)", line, REVIEW,
                     "%s zieht Brotli optional -> aufgeloeste Version im Lock/Laufzeit pruefen" % e.group(1),
                     path, ln)


def scan_toml_lock(unit, path):
    text = read(path, 50 * 1024 * 1024) or ""
    for m in re.finditer(r'name\s*=\s*"(brotli|brotlicffi)"\s*\n\s*version\s*=\s*"([^"]+)"', text, re.I):
        ln = text.count("\n", 0, m.start()) + 1
        comp = PY_PKGS[m.group(1).lower()]
        st, d = eval_brotli(m.group(2))
        unit.add(comp, m.group(2), st, "%s · %s" % (os.path.basename(path), d), path, ln)


def scan_pipfile_lock(unit, path):
    text = read(path, 50 * 1024 * 1024)
    try:
        data = json.loads(text or "")
    except ValueError:
        return
    for sect in ("default", "develop"):
        for pkg, info in (data.get(sect) or {}).items():
            if pkg.lower() in PY_PKGS and isinstance(info, dict):
                py_eval(unit, pkg.lower(), info.get("version", ""), path, None, "Pipfile.lock")


def scan_pyproject(unit, path):
    text = read(path) or ""
    for ln, line in enumerate(text.splitlines(), 1):
        for m in re.finditer(r"""["'](brotli|brotlicffi)\s*((?:[=<>~!]=?|===)\s*[\d.*]+)?[^"']*["']""", line, re.I):
            py_eval(unit, m.group(1).lower(), m.group(2), path, ln, os.path.basename(path))
        m = re.match(r"""\s*(brotli|brotlicffi)\s*=\s*["']([^"']*)["']""", line, re.I)
        if m:
            spec = m.group(2)
            if re.match(r"\d", spec):
                spec = "==" + spec
            py_eval(unit, m.group(1).lower(), spec, path, ln, "pyproject.toml (poetry)")


def scan_go_mod(unit, path):
    text = read(path) or ""
    for ln, line in enumerate(text.splitlines(), 1):
        m = re.search(r"(github\.com/andybalholm/brotli|github\.com/google/brotli/go/cbrotli)\s+(v[\w.\-+]+)", line)
        if m:
            what = "Go-Port" if "andybalholm" in m.group(1) else "cgo-Binding gegen System-libbrotli"
            unit.add("Go %s" % m.group(1).split("/", 1)[1], m.group(2), REVIEW,
                     "%s -> gegen Upstream-Advisory pruefen" % what, path, ln)


def scan_cargo_lock(unit, path):
    text = read(path, 50 * 1024 * 1024) or ""
    for m in re.finditer(r'name\s*=\s*"(brotli-sys|brotlic-sys)"\s*\n\s*version\s*=\s*"([^"]+)"', text):
        ln = text.count("\n", 0, m.start()) + 1
        unit.add("Rust %s" % m.group(1), m.group(2), REVIEW,
                 "Crate kompiliert C-Brotli mit -> gebuendelte Brotli-Version pruefen", path, ln)


def scan_brotli_version_h(unit, path):
    text = read(path, 256 * 1024) or ""
    if "BROTLI" not in text:
        return
    maj = re.search(r"#define\s+BROTLI_VERSION_MAJOR\s+(\d+)", text)
    mi = re.search(r"#define\s+BROTLI_VERSION_MINOR\s+(\d+)", text)
    pa = re.search(r"#define\s+BROTLI_VERSION_PATCH\s+(\d+)", text)
    if maj and mi and pa:
        ver = "%s.%s.%s" % (maj.group(1), mi.group(1), pa.group(1))
    else:
        hx = re.search(r"#define\s+BROTLI_VERSION\s+0x([0-9A-Fa-f]+)", text)
        if not hx:
            return
        n = int(hx.group(1), 16)
        ver = "%d.%d.%d" % (n >> 24, (n >> 12) & 0xFFF, n & 0xFFF)
    st, d = eval_brotli(ver)
    unit.add("Brotli (vendored C)", ver, st, "vendorte Quelle · " + d, path)


def scan_brotli_binary(unit, path, fname):
    m = re.match(r"libbrotli(?:dec|common|enc)?[.-](?:so\.)?(\d+\.\d+\.\d+)", fname)
    if m:
        st, d = eval_brotli(m.group(1))
        unit.add("libbrotli (Binary)", m.group(1), st, "gebuendelte Library · " + d, path)


# --------------------------------------------------------------------------- #
# Walk
# --------------------------------------------------------------------------- #


def walk(root, deep, max_depth):
    base = root.rstrip(os.sep).count(os.sep)
    for dirpath, dirnames, filenames in os.walk(root):
        depth = dirpath.rstrip(os.sep).count(os.sep) - base
        keep = []
        for d in dirnames:
            if d in SKIP_DIRS or (d.startswith(".") and d not in DEEP_DIRS):
                continue
            if d in DEEP_DIRS and not deep:
                continue
            keep.append(d)
        dirnames[:] = keep if depth < max_depth else []
        yield dirpath, filenames


def scan_unit(unit, deep, max_depth):
    for dirpath, files in walk(unit.path, deep, max_depth):
        env = load_dotenv(os.path.join(dirpath, ".env")) if ".env" in files else {}
        for f in files:
            p = os.path.join(dirpath, f)
            fl = f.lower()
            if fl.endswith(".php"):
                unit.has_php = True
            if fl == "composer.json":
                unit.has_php = True
            elif fl.startswith("dockerfile") or fl.endswith(".dockerfile") or fl == "containerfile":
                scan_dockerfile(unit, p, env)
            elif re.match(r"(docker-)?compose.*\.ya?ml$", fl):
                scan_compose(unit, p, env)
            elif fl in (".nvmrc", ".node-version"):
                unit.has_node = True
                scan_version_file(unit, p, "node")
            elif fl == ".php-version":
                unit.has_php = True
                scan_version_file(unit, p, "php")
            elif fl == ".tool-versions":
                scan_tool_versions(unit, p)
            elif fl == "package.json":
                unit.has_node = True
                scan_package_json(unit, p)
            elif fl in ("package-lock.json", "npm-shrinkwrap.json", "yarn.lock", "pnpm-lock.yaml"):
                scan_js_lock(unit, p)
            elif re.match(r"(requirements|constraints).*\.(txt|in)$", fl):
                scan_requirements(unit, p)
            elif fl in ("poetry.lock", "uv.lock", "pdm.lock"):
                scan_toml_lock(unit, p)
            elif fl == "pipfile.lock":
                scan_pipfile_lock(unit, p)
            elif fl == "pyproject.toml":
                scan_pyproject(unit, p)
            elif fl == "go.mod":
                scan_go_mod(unit, p)
            elif fl == "cargo.lock":
                scan_cargo_lock(unit, p)
            elif fl.endswith(".csproj"):
                unit.add(".NET Runtime", "?", REVIEW,
                         ".NET buendelt Brotli nativ, Stand 25.10. teils ungefixt -> Runtime-Version und MS-Advisory pruefen",
                         p, cve=CVE_BROTLI)
            elif fl == "version.h" and "brotli" in dirpath.lower():
                scan_brotli_version_h(unit, p)
            elif fl.startswith("libbrotli"):
                scan_brotli_binary(unit, p, f)

    comps = [f["component"] for f in unit.findings]
    if unit.has_php and not any(c.startswith("PHP") for c in comps):
        unit.add("PHP", "?", INFO, "PHP-Code ohne Runtime-Pin im Repo -> Version dort pruefen, wo es laeuft",
                 cve=CVE_PHP)
    if unit.has_node and not any(c.startswith(("Node", "Bun")) for c in comps):
        unit.add("Node.js", "?", INFO, "Node-Projekt ohne Runtime-Pin im Repo -> Version dort pruefen, wo es laeuft")
    if unit.inbound:
        tag = "Brotli-Inbound-Pfad: " + ", ".join(sorted(unit.inbound))
        for f in unit.findings:
            if f["component"].startswith(("Node", "Bun")) and f["status"] in (AFFECTED, EOL, UNPINNED, INFO):
                f["detail"] += "  [!] " + tag
                f["exposed"] = True


def units_for_root(root):
    root = os.path.abspath(os.path.expanduser(root))
    if not os.path.isdir(root):
        return []
    try:
        entries = sorted(os.listdir(root))
    except OSError:
        return []
    if any(UNIT_MARKERS.match(e) for e in entries):
        return [Unit(os.path.basename(root) or root, root)]
    out = []
    for e in entries:
        p = os.path.join(root, e)
        if e.startswith(".") or not os.path.isdir(p) or os.path.islink(p):
            continue
        out.append(Unit(e, p))
    return out


# --------------------------------------------------------------------------- #
# Laufzeit (docker)
# --------------------------------------------------------------------------- #

PROBE = r"""
PHPBIN=""
for b in php php85 php84 php83 php82 php81 php80 php8 php7 /usr/local/bin/php; do
  command -v $b >/dev/null 2>&1 && { PHPBIN=$(command -v $b); break; }
done
if [ -z "$PHPBIN" ]; then
  for f in /usr/local/sbin/php-fpm /usr/sbin/php-fpm* /usr/sbin/php-fpm /usr/bin/php-cgi* /usr/local/bin/php-cgi; do
    [ -x "$f" ] && { PHPBIN=$f; break; }
  done
fi
[ -n "$PHPBIN" ] && { echo "phpbin=$PHPBIN"; echo "phpv=$($PHPBIN -v 2>/dev/null | head -1)"; }
command -v node >/dev/null 2>&1 && echo "node=$(node -v 2>/dev/null)"
command -v bun  >/dev/null 2>&1 && echo "bun=$(bun -v 2>/dev/null)"
for p in python3 python; do
  command -v $p >/dev/null 2>&1 && {
    echo "pybrotli=$($p -c 'import brotli;print(getattr(brotli,"__version__",""))' 2>/dev/null)"
    echo "pybrotlicffi=$($p -c 'import brotlicffi;print(brotlicffi.__version__)' 2>/dev/null)"
    break; }
done
command -v dpkg-query >/dev/null 2>&1 && {
  echo "debbrotli=$(dpkg-query -W -f='${Version}' libbrotli1 2>/dev/null)"
  echo "debphp=$(dpkg-query -W -f='${db:Status-Abbrev} ${Package} ${Version}\n' 'php[0-9]*-common' 2>/dev/null | grep '^ii' | head -1 | cut -d' ' -f2-)"
}
command -v apk >/dev/null 2>&1 && {
  echo "apkbrotli=$(apk info -v brotli-libs 2>/dev/null | head -1)"
  echo "apkphp=$(apk info -v 2>/dev/null | grep -E '^php[0-9]*-common-' | head -1)"
}
echo "os=$(grep -E '^PRETTY_NAME=' /etc/os-release 2>/dev/null | cut -d= -f2 | tr -d '"')"
"""


def run(cmd, timeout=30):
    return subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                          universal_newlines=True, timeout=timeout)


def docker_runtime(docker_bin="docker"):
    units = []
    try:
        r = run([docker_bin, "ps", "--format",
                 '{{.Names}}\t{{.Image}}\t{{.Label "com.docker.compose.project.working_dir"}}'])
    except (OSError, subprocess.TimeoutExpired) as e:
        sys.stderr.write("docker nicht verfuegbar: %s\n" % e)
        return units
    if r.returncode != 0:
        sys.stderr.write("docker ps fehlgeschlagen: %s\n" % r.stderr.strip())
        return units
    for row in r.stdout.splitlines():
        if "\t" not in row:
            continue
        cols = row.split("\t")
        name, image = cols[0], cols[1]
        wdir = cols[2].strip() if len(cols) > 2 else ""
        u = Unit(name, None, kind="container")
        u.image = image + ((" · " + wdir) if wdir and wdir != "<no value>" else "")
        units.append(u)
        try:
            p = run([docker_bin, "exec", name, "sh", "-c", PROBE], timeout=30)
        except subprocess.TimeoutExpired:
            u.add("Container", image, REVIEW, "Probe Timeout -> manuell pruefen", file=image, cve="-")
            continue
        if p.returncode != 0 and not p.stdout.strip():
            # distroless o.ae.: auf statische Image-Bewertung zurueckfallen
            for comp, ver, st, d in eval_image(image):
                u.add(comp, ver, st, "kein sh im Container, nur Image-Tag bewertet · " + d, file=image)
            if not u.findings:
                u.add("Container", image, REVIEW, "kein sh im Container -> manuell pruefen", file=image, cve="-")
            continue
        kv = {}
        for line in p.stdout.splitlines():
            if "=" in line:
                k, v = line.split("=", 1)
                kv[k.strip()] = v.strip()
        osname = kv.get("os", "")
        src = "%s%s" % (image, (" (%s)" % osname) if osname else "")
        phpv = kv.get("phpv", "")
        if kv.get("phpbin"):
            m = re.search(r"PHP\s+(\d+\.\d+\.\d+)", phpv)
            if not m:
                u.add("PHP", "?", REVIEW, "%s -v lieferte keine Version (%s) -> manuell pruefen"
                      % (kv["phpbin"], phpv or "leer"), file=src)
            else:
                st, d = eval_php(m.group(1))
                # offizielle docker-library-Images bauen PHP aus Source nach /usr/local -> kein Distro-Backport
                distro = "" if kv["phpbin"].startswith("/usr/local/") else (kv.get("debphp", "") or kv.get("apkphp", ""))
                if distro and st in (AFFECTED, EOL):
                    st, d = REVIEW, "Distro-Paket %s -> Backport im Distro-Tracker pruefen (%s)" % (distro, d)
                u.add("PHP", m.group(1), st, '%s · %s -v: "%s"' % (d, kv["phpbin"], phpv), file=src)
        if kv.get("node"):
            st, d = eval_node(kv["node"])
            u.add("Node.js", kv["node"].lstrip("v"), st, d, file=src)
        if kv.get("bun"):
            st, d = eval_bun(kv["bun"])
            u.add("Bun", kv["bun"], st, d, file=src)
        if kv.get("pybrotli"):
            st, d = eval_brotli(kv["pybrotli"])
            u.add("Python Brotli", kv["pybrotli"], st, d, file=src)
        if kv.get("pybrotlicffi"):
            st, d = eval_brotli(kv["pybrotlicffi"])
            u.add("brotlicffi", kv["pybrotlicffi"], st, d, file=src)
        if kv.get("debbrotli"):
            st, d = eval_deb_brotli(kv["debbrotli"])
            u.add("libbrotli1 (deb)", kv["debbrotli"], st, d, file=src)
        m = re.search(r"brotli-libs-(\d[\w.]*)-r\d+", kv.get("apkbrotli", ""))
        if m:
            st, d = eval_brotli(m.group(1))
            u.add("brotli-libs (apk)", kv["apkbrotli"].replace("brotli-libs-", ""), st, d, file=src)
        for comp, ver, st, d in eval_image(image):
            if st == REVIEW:
                u.add(comp, ver, st, d, file=src)
    return units


# --------------------------------------------------------------------------- #
# Ausgabe
# --------------------------------------------------------------------------- #

COLORS = {AFFECTED: "\033[1;31m", EOL: "\033[1;35m", UNPINNED: "\033[33m",
          REVIEW: "\033[36m", INFO: "\033[2m", OK: "\033[32m"}
RESET = "\033[0m"
BOLD = "\033[1m"


def render(groups, verbose, color):
    def c(s, code):
        return (code + s + RESET) if color else s

    shown_status = set(ORDER) if verbose else set(ORDER) - {OK}
    total = {s: 0 for s in ORDER}
    hit_units = []
    n_units = 0
    for title, units in groups:
        if not units:
            continue
        print(c("\n== %s ==" % title, BOLD))
        for u in units:
            n_units += 1
            for f in u.findings:
                total[f["status"]] += 1
            fs = sorted((f for f in u.findings if f["status"] in shown_status),
                        key=lambda f: (ORDER[f["status"]], f["component"]))
            w = u.worst()
            if w in (AFFECTED, EOL, UNPINNED, REVIEW):
                hit_units.append((w, u.name))
            if not fs:
                if verbose:
                    print("  %s  %s" % (c("%-9s" % "CLEAN", COLORS[OK]), u.name))
                continue
            head = u.name + (("  [%s]" % u.image) if getattr(u, "image", None) else "")
            print("\n  " + c(head, BOLD))
            for f in fs:
                comp = "%s %s" % (f["component"], f["version"])
                loc = f["file"] + (":%s" % f["line"] if f["line"] else "")
                print("    %s  %-28s %-32s %s" % (c("%-9s" % f["status"], COLORS[f["status"]]),
                                                   comp[:28], loc[:32], f["detail"]))
    print(c("\n== Zusammenfassung ==", BOLD))
    parts = ["%s %d" % (c(s, COLORS[s]), total[s]) for s in (AFFECTED, EOL, UNPINNED, REVIEW, INFO) if total[s]]
    print("  Geprueft: %d Repos/Container   %s" % (n_units, "   ".join(parts) if parts else "keine Befunde"))
    urgent = sorted(n for w, n in hit_units if w in (AFFECTED, EOL))
    if urgent:
        print("  Patchen: " + ", ".join(urgent))
    print("  Legende: AFFECTED=verwundbare Version  EOL=kein Fix verfuegbar  UNPINNED=floating, verifizieren"
          "  REVIEW=manuell pruefen  INFO=Runtime nicht im Repo")
    return total


def main():
    ap = argparse.ArgumentParser(description="Detector fuer PHP2Shell (%s) und Node2Shell/HTTP2Shell (%s)"
                                             % (CVE_PHP, CVE_BROTLI))
    ap.add_argument("paths", nargs="*", help="Roots (Unterordner = Repos/Container) oder einzelnes Repo. "
                                             "Default: %s" % ", ".join(DEFAULT_ROOTS))
    ap.add_argument("--docker", action="store_true", help="laufende Container zur Laufzeit pruefen (docker exec)")
    ap.add_argument("--docker-bin", default="docker", help="z.B. 'podman'")
    ap.add_argument("--deep", action="store_true", help="auch node_modules/, vendor/, .venv/ durchsuchen")
    ap.add_argument("--max-depth", type=int, default=8, help="max. Verzeichnistiefe pro Repo (Default 8)")
    ap.add_argument("-v", "--verbose", action="store_true", help="auch OK-Befunde und saubere Repos zeigen")
    ap.add_argument("--json", action="store_true", help="JSON auf stdout")
    ap.add_argument("--no-color", action="store_true")
    a = ap.parse_args()

    roots = a.paths or [r for r in DEFAULT_ROOTS if os.path.isdir(os.path.expanduser(r))]
    if not roots and not a.docker:
        ap.error("keine Pfade angegeben und keine Default-Roots gefunden")

    groups = []
    for root in roots:
        units = units_for_root(root)
        if not units:
            sys.stderr.write("uebersprungen (kein Verzeichnis oder leer): %s\n" % root)
        for u in units:
            scan_unit(u, a.deep, a.max_depth)
        groups.append((os.path.abspath(os.path.expanduser(root)), units))
    if a.docker:
        groups.append(("Laufende Container (Runtime)", docker_runtime(a.docker_bin)))

    if a.json:
        allf = [f for _, us in groups for u in us for f in u.findings]
        print(json.dumps({"generated": datetime.now().isoformat(timespec="seconds"),
                          "findings": allf}, indent=2, ensure_ascii=False))
        total = {s: sum(1 for f in allf if f["status"] == s) for s in ORDER}
    else:
        color = sys.stdout.isatty() and not a.no_color and os.environ.get("NO_COLOR") is None
        total = render(groups, a.verbose, color)

    if total[AFFECTED] or total[EOL]:
        sys.exit(2)
    if total[UNPINNED] or total[REVIEW]:
        sys.exit(1)
    sys.exit(0)


if __name__ == "__main__":
    main()

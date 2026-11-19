#!/usr/bin/env python3
"""Read-only PHP/NGINX release audit: source trees, Dockerfiles, Compose and runtime.

Python 3.8+ / stdlib only. Rules frozen at 2026-11-19; NOT a full CVE scanner.
Older upstream versions are not proof of vulnerable distro packages (backports).
"""
import argparse
import json
import os
import re
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path

PHP_FIXED = {"8.2": "8.2.36", "8.3": "8.3.37", "8.4": "8.4.28", "8.5": "8.5.13"}
NGINX_FIXED = {"1.30": "1.30.7", "1.31": "1.31.9"}
DEFAULT_ROOTS = ("~/SourceCode", "/data/docker-containers")
SKIP = {".git", ".venv", "venv", "vendor", "node_modules", "build",
        "dist", "__pycache__", "cache", "logs", "uploads",
        "volumes", "volume", "data", "db", "database", "storage", "backups"}
APPS = {"wordpress", "drupal", "joomla", "nextcloud", "matomo",
        "phpmyadmin", "mediawiki", "typo3", "moodle", "glpi"}
PRIORITY = {"AFFECTED": 0, "EOL": 1, "UNPINNED": 2,
            "REVIEW": 3, "INFO": 4, "OK": 5}
DOCKERFILE = re.compile(r"^(?:Dockerfile(?:\..+)?|.+\.Dockerfile|Containerfile(?:\..+)?)$", re.I)
COMPOSE = re.compile(r"^(?:docker-)?compose(?:[.\w-]*)?\.ya?ml$", re.I)
VAR = re.compile(r"\x24\{([A-Za-z_]\w*)(?:(:-|-)([^}]*))?\}|\x24([A-Za-z_]\w*)")


def shell(command):
    try:
        return subprocess.run(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                              universal_newlines=True, timeout=15)
    except (OSError, subprocess.TimeoutExpired) as exc:
        return subprocess.CompletedProcess(command, 127, "", str(exc))


def classify(product, version, distro=False):
    if not re.fullmatch(r"\d+\.\d+\.\d+", version or ""):
        return "UNPINNED", "Keine exakte Version; Laufzeit prüfen"
    parts = tuple(map(int, version.split(".")))
    branch = "%d.%d" % parts[:2]
    if product == "PHP" and parts[:2] < (8, 2):
        return ("REVIEW" if distro else "EOL"), "PHP-Upstream-Branch EOL"
    fixed = (PHP_FIXED if product == "PHP" else NGINX_FIXED).get(branch)
    if not fixed:
        return "REVIEW", "Branch in aktueller Fixmatrix nicht abgedeckt"
    if distro:
        return "REVIEW", "Distro-Paket: Security-Backport und Paketrelease prüfen (Upstream-Fix %s)" % fixed
    if parts < tuple(map(int, fixed.split("."))):
        return "AFFECTED", "Unter Upstream-Security-Release %s" % fixed
    return "OK", "Upstream-Fixgrenze %s erreicht; keine generelle CVE-Freigabe" % fixed


def entry(unit, kind, product, version, status, filename, line, detail, **kw):
    result = dict(unit=unit, kind=kind, component=product, version=version or "?",
                  status=status, file=str(filename), line=line, detail=detail)
    if product == "PHP":
        result["advisory"] = "https://www.php.net/ChangeLog-8.php"
    elif product == "NGINX":
        result["advisory"] = "https://nginx.org/en/security_advisories.html"
    result.update(kw)
    return result


def load_env(folder):
    result = {}
    try:
        lines = (folder / ".env").read_text(encoding="utf-8").splitlines()
    except OSError:
        return result
    for line in lines:
        match = re.match(r"^\s*(?:export\s+)?([A-Za-z_]\w*)\s*=\s*(.*?)\s*$", line)
        if match:
            result[match.group(1)] = match.group(2).strip().strip("'\"")
    return result


def interpolate(value, env):
    def replacement(match):
        name = match.group(1) or match.group(4)
        existing = env.get(name)
        if existing is not None and (existing or match.group(2) != ":-"):
            return existing
        return match.group(3) if match.group(3) is not None else match.group(0)
    return VAR.sub(replacement, value)


def image_version(image):
    image = image.strip().strip("\"'")
    leaf = image.split("@", 1)[0].rsplit("/", 1)[-1]
    name, sep, tag = leaf.partition(":")
    name = name.lower()
    if name == "php":
        product = "PHP"
    elif name in ("nginx", "nginx-unprivileged"):
        product = "NGINX"
    elif name in APPS:
        return "PHP", None
    else:
        return None, None
    match = re.match(r"^(\d+\.\d+\.\d+)(?:$|[-_])", tag) if sep and "@" not in image else None
    return product, match.group(1) if match else None


def add_image(results, unit, file, line, image, env):
    expanded = interpolate(image, env)
    product, version = image_version(expanded)
    if product is None and "\x24" in expanded and re.search(r"php|nginx", expanded, re.I):
        results.append(entry(unit, "repo", "PHP/NGINX", "?", "UNPINNED", file, line,
                             "Image-Variable konnte nicht aufgelöst werden"))
        return
    if product is None:
        return
    status, detail = classify(product, version)
    results.append(entry(unit, "repo", product, version, status, file, line,
                         "FROM/image %s: %s" % (expanded, detail)))


def dockerfile_scan(results, unit, path, env):
    try:
        text = path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return
    variables = dict(env)
    logical = []
    for lineno, raw in enumerate(text.splitlines(), 1):
        if logical and logical[-1][1].endswith("\\"):
            start, former = logical[-1]
            logical[-1] = (start, former[:-1] + " " + raw.strip())
        else:
            logical.append((lineno, raw))
    for lineno, line in logical:
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        arg = re.match(r"^(ARG|ENV)\s+([A-Za-z_]\w*)=(\S+)", line, re.I)
        if arg:
            variables[arg.group(2)] = interpolate(arg.group(3).strip("'\""), variables)
        base = re.match(r"^FROM\s+(?:--platform=\S+\s+)?(\S+)", line, re.I)
        if base:
            add_image(results, unit, path, lineno, base.group(1), variables)
        if re.search(r"\b(?:apt(?:-get)?|apk|dnf|yum|microdnf|zypper)\b", line, re.I):
            for product, token in (("PHP", "php"), ("NGINX", "nginx")):
                if re.search(r"\b" + token + r"(?:\d|[-\s]|$)", line, re.I):
                    results.append(entry(unit, "repo", product, "?", "REVIEW", path, lineno,
                                         "Paketmanager-Installation: Distro-Fixversion prüfen"))


def compose_scan(results, unit, path, env, seen):
    try:
        lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
    except OSError:
        return
    for lineno, line in enumerate(lines, 1):
        if line.lstrip().startswith("#"):
            continue
        image = re.match(r"^\s*image\s*:\s*(\S+)", line)
        if image:
            add_image(results, unit, path, lineno, image.group(1), env)
        custom = re.match(r"^\s*dockerfile\s*:\s*(\S+)", line)
        if custom:
            rel = interpolate(custom.group(1).strip("\"'"), env)
            target = (path.parent / rel).resolve()
            if target.is_file() and target not in seen:
                seen.add(target)
                dockerfile_scan(results, unit, target, env)


def sources(roots, max_depth, deep):
    results, seen, total = [], set(), 0
    for root in roots:
        base = Path(root).expanduser()
        if not base.is_dir():
            results.append(entry(str(base), "repo", "Filesystem", "?", "REVIEW",
                                 base, None, "Pfad nicht lesbar"))
            continue
        base = base.resolve()
        def on_walk_error(exc):
            # Unreadable data/volume directories must never abort the audit.
            sys.stderr.write("WARN: Verzeichnis übersprungen: %s\n" % exc)

        for folder, dirs, files in os.walk(str(base), followlinks=False,
                                           onerror=on_walk_error):
            depth = len(Path(folder).relative_to(base).parts)
            accessible = []
            for name in sorted(dirs):
                if name in SKIP or (not deep and name.startswith(".")):
                    continue
                try:
                    if not Path(folder, name).is_symlink():
                        accessible.append(name)
                except OSError as exc:
                    sys.stderr.write("WARN: Verzeichnis übersprungen: %s\n" % exc)
            dirs[:] = accessible if depth < max_depth else []
            env = load_env(Path(folder))
            unit = Path(folder).name
            for name in sorted(files):
                # Match names first: never stat arbitrary files in mounted volumes.
                if not (DOCKERFILE.match(name) or COMPOSE.match(name)):
                    continue
                path = Path(folder, name)
                try:
                    if path.is_symlink() or path.stat().st_size > 2_000_000:
                        continue
                except OSError as exc:
                    sys.stderr.write("WARN: Datei übersprungen: %s\n" % exc)
                    continue
                if path in seen:
                    continue
                seen.add(path)
                total += 1
                if DOCKERFILE.match(name):
                    dockerfile_scan(results, unit, path, env)
                else:
                    compose_scan(results, unit, path, env, seen)
    return results, total


def runtime(docker):
    results = []
    listed = shell([docker, "ps", "-q", "--no-trunc"])
    if listed.returncode:
        return [entry("docker", "container", "Docker", "?", "REVIEW",
                      "docker ps", None, listed.stderr.strip() or "Docker nicht verfügbar")], 0
    ids = listed.stdout.split()
    for cid in ids:
        inspected = shell([docker, "inspect", cid])
        try:
            obj = json.loads(inspected.stdout)[0]
        except (ValueError, IndexError):
            results.append(entry(cid, "container", "Docker", "?", "REVIEW",
                                 "docker inspect", None, "Container-Inspektion fehlgeschlagen"))
            continue
        name = obj.get("Name", cid).lstrip("/")
        config = obj.get("Config") or {}
        image = config.get("Image") or ""
        working_dir = (config.get("Labels") or {}).get("com.docker.compose.project.working_dir", "")
        detected = False
        for product, programs in (
            ("PHP", ("php", "php8.5", "php8.4", "php8.3", "php8.2", "php-fpm",
                     "php-fpm8.5", "php-fpm8.4", "php-fpm8.3", "php-fpm8.2", "/usr/local/sbin/php-fpm")),
            ("NGINX", ("nginx", "/usr/sbin/nginx", "/usr/local/nginx/sbin/nginx")),
        ):
            version, cmd = None, None
            for program in programs:
                output = shell([docker, "exec", cid, program, "-v"])
                match = re.search(r"(?i)(?:PHP\s+|nginx/)(\d+\.\d+\.\d+)", output.stdout + output.stderr)
                if match and output.returncode == 0:
                    version, cmd = match.group(1), program
                    break
            if version is None:
                continue
            detected = True
            # Image-based binaries in /usr/local are source builds; /usr/bin can be distro packages.
            pkg = ""
            if not cmd.startswith("/usr/local/"):
                installed = shell([docker, "exec", cid, "dpkg-query", "-W",
                                   "php*-common" if product == "PHP" else "nginx*"])
                if installed.returncode == 0:
                    pkg = installed.stdout.splitlines()[0] if installed.stdout.strip() else ""
                if not pkg:
                    installed = shell([docker, "exec", cid, "apk", "info", "-v",
                                       "php" if product == "PHP" else "nginx"])
                    pkg = installed.stdout.strip() if installed.returncode == 0 else ""
            status, reason = classify(product, version, distro=bool(pkg))
            results.append(entry(name, "container", product, version, status, image, None,
                                 reason, image=image, compose_dir=working_dir,
                                 binary=cmd, distro_package=pkg))
        if not detected:
            product, version = image_version(image)
            results.append(entry(name, "container", product or "Runtime", version or "?",
                                 "REVIEW" if product else "INFO", image, None,
                                 "Runtime nicht nachweisbar; Custom-Images ggf. manuell prüfen",
                                 image=image, compose_dir=working_dir))
    return results, len(ids)


def output(results, file_count, container_count, json_mode, verbose):
    counts = {s: sum(item["status"] == s for item in results) for s in PRIORITY}
    if json_mode:
        print(json.dumps(dict(generated=datetime.now(timezone.utc).isoformat(timespec="seconds"),
                              rules_updated="2026-11-19", source_files=file_count,
                              containers=container_count, summary=counts, findings=results),
                         indent=2, ensure_ascii=False))
    else:
        print("PHP/NGINX Detector | Regeln: 19.11.2026")
        print("Quelldateien: %s | laufende Container: %s" % (file_count, container_count))
        for row in sorted(results, key=lambda r: (r["unit"], PRIORITY[r["status"]])):
            if row["status"] in ("OK", "INFO") and not verbose:
                continue
            location = str(row["file"]) + (":%s" % row["line"] if row["line"] else "")
            print("%-9s %-6s %-10s %-28s %s" % (
                row["status"], row["component"], row["version"], location, row["detail"]))
        print("  ".join("%s=%d" % (s, counts[s]) for s in PRIORITY))
    return 2 if counts["AFFECTED"] or counts["EOL"] else (1 if counts["UNPINNED"] or counts["REVIEW"] else 0)


def main(argv=None):
    parser = argparse.ArgumentParser(description="Read-only PHP/NGINX Docker and repo audit")
    parser.add_argument("paths", nargs="*", help="Roots oder Repo-Verzeichnisse")
    parser.add_argument("--docker", action="store_true", help="Laufende Container prüfen")
    parser.add_argument("--docker-bin", default="docker", help="Alternative Container-CLI")
    parser.add_argument("--max-depth", type=int, default=8)
    parser.add_argument("--deep", action="store_true", help="Versteckte Unterordner berücksichtigen")
    parser.add_argument("--json", action="store_true", help="Maschinenlesbare JSON-Ausgabe auf stdout")
    parser.add_argument("-v", "--verbose", action="store_true", help="Auch OK und INFO anzeigen")
    parser.add_argument("--no-color", action="store_true", help="Kompatibilitätsoption")
    args = parser.parse_args(argv)
    # --docker alone is runtime-only. Supplying paths explicitly combines
    # source and runtime scans. Without --docker, use existing default roots.
    roots = (args.paths if args.paths else
             ([] if args.docker else
              [r for r in DEFAULT_ROOTS if Path(r).expanduser().is_dir()]))
    if not roots and not args.docker:
        parser.error("Keine Roots gefunden: Verzeichnis angeben oder --docker")
    scan, n = sources(roots, max(0, args.max_depth), args.deep)
    live, containers = runtime(args.docker_bin) if args.docker else ([], 0)
    return output(scan + live, n, containers, args.json, args.verbose)


if __name__ == "__main__":
    sys.exit(main())

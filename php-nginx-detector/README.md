# php-nginx-detector

Read-only Scanner für **PHP- und NGINX-Sicherheitsreleases**. Durchsucht Docker-/Compose-Codebasen sowie optional die **laufenden Container**. Python-Standardbibliothek (Python ≥ 3.8), keine externen Abhängigkeiten.

Im Stil von `2shell-detector`: keine Änderungen an den untersuchten Systemen, standardmässig nur Befunde, JSON für `jq` und Exit-Codes für CI/Cron.

## Installation

```bash
chmod +x php-nginx-detector.py
./php-nginx-detector.py --help
```

## Verwendung

```bash
./php-nginx-detector.py                                      # Default-Roots, falls vorhanden
./php-nginx-detector.py /data/docker-containers              # Statische Analyse
./php-nginx-detector.py ~/SourceCode /data/docker-containers --docker # Statisch + Runtime
./php-nginx-detector.py --docker                             # Nur laufende Container (kein Dateisystemscan)
./php-nginx-detector.py /data/docker-containers --docker -v  # Auch OK/INFO
./php-nginx-detector.py --docker --json > report.json
./php-nginx-detector.py --docker --json | jq '.findings[] | select(.status=="AFFECTED" or .status=="EOL")'
```

## Optionen

| Option | Bedeutung |
|---|---|
| `paths …` | Beliebige Root-Verzeichnisse; ohne Angabe `~/SourceCode` und `/data/docker-containers`, soweit vorhanden |
| `--docker` | Ohne Pfade: ausschliesslich laufende Container prüfen (`docker ps/inspect/exec`); mit Pfaden: statisch + Runtime |
| `--docker-bin X` | Container-CLI, standardmässig `docker` |
| `--deep` | Auch versteckte Unterordner berücksichtigen; Daten-/Volume-Verzeichnisse bleiben ausgeschlossen |
| `--max-depth N` | Maximale Scan-Tiefe, standardmässig 8 |
| `-v`, `--verbose` | Auch `OK` und `INFO` ausgeben |
| `--json` | JSON auf stdout |
| `--no-color` | Kompatibilitätsoption (derzeit keine ANSI-Ausgabe) |

## Erkennung

| Quelle | Analyse |
|---|---|
| `Dockerfile`, `Dockerfile.*`, `*.Dockerfile`, `Containerfile*` | `FROM`, mehrere Build-Stages, `ARG`/Image-Variablen, Paketmanager-Installationen |
| `compose.yml`, `compose.yaml`, `docker-compose*.yml` | `image:`, einfache `.env`-Substitution, explizite `dockerfile:`-Angaben |
| Laufende Docker-Container | `php -v` beziehungsweise `nginx -v` über `docker exec`, Image und Compose-Arbeitsverzeichnis |

Floating Tags (`php:8.3-fpm`, `nginx:latest`), nicht aufgelöste Variablen und PHP-basierte Applikationsimages wie `wordpress` erzeugen `UNPINNED`. Die Runtime ist für die tatsächliche installierte Version aussagekräftiger als ein Image-Tag.

**Wichtig:** Der statische Scan wertet Dockerfiles auch unabhängig von Compose aus. Er ist bewusst textbasiert und kein vollständiger YAML-/Dockerfile-Interpreter: komplexe Compose-`build.context`-Auflösungen, `include`, `extends`, Shell-Expansionen und entfernte Dockerfiles sind manuell zu prüfen.

## Upstream-Fixmatrix (Stand 19.11.2026)

| Produkt | Branch | Upstream-Fixversion |
|---|---|---|
| PHP | 8.2 | 8.2.36 |
| PHP | 8.3 | 8.3.37 |
| PHP | 8.4 | 8.4.28 |
| PHP | 8.5 | 8.5.13 |
| NGINX | 1.30 | 1.30.7 |
| NGINX | 1.31 | 1.31.9 |

Das ist eine **Release-Triage mit fest hinterlegten Grenzen**, keine live aktualisierte CVE-Datenbank und kein Exploit-Nachweis. Fixmatrix und betroffene Konfigurationen müssen vor Patching mit den primären Hersteller-Advisories abgeglichen werden:

- PHP: https://www.php.net/ChangeLog-8.php
- NGINX: https://nginx.org/en/security_advisories.html

## Status und Exit-Codes

| Status | Bedeutung |
|---|---|
| `AFFECTED` | Erkannte Upstream-Version liegt unter der hinterlegten Sicherheitsrelease-Grenze |
| `EOL` | PHP-Upstream-Branch nicht mehr unterstützt |
| `UNPINNED` | Keine exakte Version, z. B. Floating Tag |
| `REVIEW` | Distro-Backport, nicht abgedeckter Branch oder sonstige Unsicherheit |
| `INFO` | Kein untersuchbares PHP/NGINX-Binary festgestellt |
| `OK` | Hinterlegte Upstream-Grenze erfüllt; keine umfassende Sicherheitsfreigabe |

Exit-Code `0`: keine offenen Befunde; `1`: `UNPINNED`/`REVIEW`; `2`: `AFFECTED`/`EOL`.

## Beispiel: jq

```bash
./php-nginx-detector.py /data/docker-containers --docker --json \
  | jq -r '.findings[] | select(.status=="AFFECTED" or .status=="EOL") | [.unit,.component,.version,.file,.detail] | @tsv'
```

Die JSON-Ausgabe enthält `generated`, `rules_updated`, `source_files`, `containers`, `summary` und `findings`. Ein Finding enthält unter anderem `unit`, `kind`, `component`, `version`, `status`, `file`, `line`, `detail` und bei Runtime-Befunden `image`/`compose_dir`.

## Berechtigungen und Volume-Verzeichnisse

Beim Aufruf **`--docker` ohne explizite Pfade** wird kein Source- oder Volume-Verzeichnis auf dem Host durchlaufen. Ein statischer Scan findet nur ohne `--docker` oder mit explizit angegebenen Pfaden statt.

Verzeichnisse wie `volumes/`, `storage/`, `data/`, `db/` und `backups/` werden standardmässig nicht rekursiv untersucht. Unlesbare Dateien oder Verzeichnisse werden mit `WARN` auf stderr übersprungen; sie beenden den Scan nicht. Den Scanner für den Source-Code-Scan normalerweise **ohne sudo** ausführen. Container-Zugriff über `--docker` benötigt die üblichen Docker-Berechtigungen.

## Grenzen

- Nur laufende Container. Gestoppte Images, Images ohne ausführbares PHP-/NGINX-Binary und andere Hosts können zusätzliche Prüfung erfordern.
- **Distributions-Backports:** Debian, Ubuntu, Alpine und RHEL können eine ältere Upstream-Versionsnummer mit Sicherheitsfix ausliefern. Identifizierbare Distro-Pakete erhalten daher `REVIEW`, kein automatisches `AFFECTED`.
- Statische `FROM`-Versionen können sich von gebauten/laufenden Images unterscheiden. Tags sind veränderlich, Digests enthalten keine Versionsnummer.
- Das Script prüft nicht, ob HTTP/2, HTTP/3, FastCGI oder andere CVE-relevante Konfigurationsvoraussetzungen vorliegen.
- Versionsmatrix wird nicht automatisch aktualisiert. Für andere CVEs oder neue Releases die Tabellen im Script pflegen.
- Autorisierte Systeme verwenden. Es erfolgen keine Änderungen an Containern oder Dateien.

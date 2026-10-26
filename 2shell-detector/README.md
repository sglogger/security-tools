# 2shell-detector

Detector für **PHP2Shell** und **Node2Shell / HTTP2Shell**. Durchsucht Repos und Container-Verzeichnisse nach verwundbaren PHP-, Node.js-, Bun- und Brotli-Versionen und prüft optional laufende Docker-Container zur Laufzeit.

| Name                    | CVE                               | Betroffen                                    |
|-------------------------|-----------------------------------|----------------------------------------------|
| PHP2Shell               | CVE-2026-109618, CVE-2026-109619  | PHP-Core, pre-auth RCE                       |
| Node2Shell / HTTP2Shell | CVE-2026-111497                   | Google Brotli Decoder 1.0.3–1.2.0, OOB write |

Node2Shell trifft alles, was den Brotli-Decoder mitbringt: Node.js, Bun, Python-`brotli`/`brotlicffi`, Distro-`libbrotli`, vendorte C-Quellen, Envoy, .NET usw.

**Das Tool ändert nichts**, es liest nur. Es braucht ausschliesslich die Python-Standardbibliothek (≥ 3.8) und läuft auf macOS und Linux.

---

## Installation

Keine. Script ausführbar machen und starten:

```bash
chmod +x 2shell-detector.py
./2shell-detector.py --help
```

## Verwendung

```bash
./2shell-detector.py                                  # Default-Roots: ~/SourceCode, /data/docker-containers (falls vorhanden)
./2shell-detector.py ~/SourceCode                     # alle Repos unterhalb eines Roots
./2shell-detector.py ~/SourceCode/meinrepo -v         # einzelnes Repo, inkl. OK-Befunde
./2shell-detector.py /data/docker-containers --docker # statisch + laufende Container
./2shell-detector.py --docker                         # nur Laufzeit (wenn keine Default-Roots existieren)
./2shell-detector.py --json > report.json             # maschinenlesbar
```

### Optionen

| Option            | Bedeutung                                                                 |
|-------------------|---------------------------------------------------------------------------|
| `paths …`         | Ein oder mehrere Roots bzw. einzelne Repos. Ohne Angabe: Default-Roots.   |
| `--docker`        | Laufende Container per `docker exec` prüfen (Laufzeit-Analyse).           |
| `--docker-bin X`  | Alternatives Container-CLI, z. B. `podman`.                               |
| `--deep`          | Auch `node_modules/`, `vendor/`, `.venv/`, `site-packages/` usw. durchsuchen. |
| `--max-depth N`   | Maximale Verzeichnistiefe pro Repo (Default 8).                           |
| `-v`, `--verbose` | Auch `OK`-Befunde und saubere Repos (`CLEAN`) anzeigen.                   |
| `--json`          | JSON auf stdout statt Tabelle.                                            |
| `--no-color`      | Keine ANSI-Farben (wird auch über `NO_COLOR` oder Nicht-TTY abgeschaltet). |

### Wie Roots aufgelöst werden

- Enthält der angegebene Pfad selbst ein `Dockerfile`, `compose.yml`, `package.json`, `composer.json`, `requirements*.txt`, `pyproject.toml`, `go.mod`, `.nvmrc`, `.node-version` oder `.tool-versions`, wird er als **ein** Repo behandelt.
- Sonst ist jeder (nicht versteckte, nicht verlinkte) Unterordner ein eigenes Repo bzw. Container-Verzeichnis.

---

## Was geprüft wird

### Statische Analyse (Dateien im Repo)

| Quelle                                              | Erkennt                                                                 |
|-----------------------------------------------------|-------------------------------------------------------------------------|
| `Dockerfile*`, `*.Dockerfile`, `Containerfile`      | `FROM`-Images, `ARG/ENV PHP_VERSION/NODE_VERSION/BUN_VERSION`, Distro-Pakete (`apt`, `apk`, `dnf` …), NodeSource `setup_XX.x`, Node-/Bun-Tarballs |
| `docker-compose*.yml`, `compose*.yml` (+ `.env`)    | `image:`-Zeilen, Variablen werden über `.env` aufgelöst                 |
| `.nvmrc`, `.node-version`, `.php-version`           | Gepinnte Runtime-Version                                                |
| `.tool-versions` (asdf/mise)                        | `nodejs`, `php`, `bun`                                                  |
| `package.json`                                      | `volta.node` / `volta.bun`, Inbound-Pakete                              |
| `package-lock.json`, `yarn.lock`, `pnpm-lock.yaml`  | Aufgelöste Versionen der Inbound-Pakete                                 |
| `requirements*.txt`, `constraints*.txt`, `pyproject.toml` | `brotli`, `brotlicffi`, Extras wie `[brotli]`/`[speedups]`        |
| `poetry.lock`, `uv.lock`, `pdm.lock`, `Pipfile.lock`| Exakte Python-Brotli-Versionen                                          |
| `go.mod`                                            | `andybalholm/brotli`, `google/brotli/go/cbrotli`                        |
| `Cargo.lock`                                        | `brotli-sys`, `brotlic-sys`                                             |
| `*.csproj`                                          | .NET (bündelt Brotli nativ)                                             |
| `…/brotli/…/version.h`                              | Vendorte Brotli-C-Quellen                                               |
| `libbrotli*`-Dateien                                | Mitgelieferte Binaries (Version aus Dateiname)                          |

Bekannte App-Images ohne Versionsangabe im Tag werden als PHP- bzw. Node-Träger erkannt, z. B. `wordpress`, `nextcloud`, `matomo`, `phpmyadmin` (PHP) oder `ghost`, `n8n`, `node-red`, `uptime-kuma` (Node). Envoy- und .NET-Images erzeugen einen `REVIEW`-Hinweis.

Übersprungen werden `.git`, `__pycache__`, `dist`, `coverage`, `uploads`, `cache`, `logs` und versteckte Ordner. Abhängigkeitsordner (`node_modules`, `vendor`, `.venv` …) nur mit `--deep`.

### Brotli-Inbound-Pfad

Für die Ausnutzbarkeit von Node2Shell ist entscheidend, ob die App **Brotli-komprimierte Request-Bodies** von aussen annimmt. Das Tool markiert Node-/Bun-Befunde mit `[!] Brotli-Inbound-Pfad: …` (und `"exposed": true` im JSON), wenn eines dieser Pakete als Laufzeit-Dependency vorkommt:

- `express` ≥ 5, `body-parser` ≥ 2
- `@fastify/compress`, `koa-body`, `koa-bodyparser`, `@koa/bodyparser`

Solche Befunde zuerst patchen.

### Laufzeit-Analyse (`--docker`)

Für jeden **laufenden** Container wird per `docker exec … sh -c` ein kurzes Probe-Script ausgeführt, das ermittelt:

- PHP: `php -v` (Fallback `php-fpm -v` / `php-cgi -v`), die Ausgabe wird als Beleg angezeigt
- `node -v`, `bun -v`
- Python `brotli.__version__` / `brotlicffi.__version__`
- Distro-Pakete: `libbrotli1` (dpkg) bzw. `brotli-libs` (apk), plus PHP-Distro-Paket
- Betriebssystem aus `/etc/os-release`

Das ist die verlässliche Quelle, vor allem bei floating Tags wie `php:8.3-fpm`, `wordpress:latest` oder `node:lts`. Zusätzlich wird pro Container das Compose-Projektverzeichnis angezeigt.

Besonderheiten:

- Distro-PHP (nicht unter `/usr/local/`) mit alter Upstream-Version wird auf `REVIEW` heruntergestuft, weil Distros Fixes backporten.
- Debian-`libbrotli1` mit `+deb12uN`/`+deb13uN` gilt als gefixt; Ubuntu-Pakete mit Security-Suffix werden `REVIEW`.
- Container ohne `sh` (distroless): Fallback auf die statische Bewertung des Image-Tags.
- Gestoppte Container werden **nicht** geprüft.

---

## Status-Werte

| Status     | Bedeutung                                                        | Handlung                                   |
|------------|------------------------------------------------------------------|--------------------------------------------|
| `AFFECTED` | Verwundbare Version eindeutig erkannt                            | Patchen auf die angegebene Fix-Version     |
| `EOL`      | Branch ist End-of-Life, es gibt keinen Upstream-Fix              | Auf einen unterstützten Branch upgraden    |
| `UNPINNED` | Version nicht exakt bestimmbar (floating Tag, nur Major, Variable)| Mit `--docker` oder Lockfile verifizieren |
| `REVIEW`   | Automatisch nicht entscheidbar (Distro-Backport, Go/Rust/.NET, Envoy) | Manuell gegen Advisory/Tracker prüfen |
| `INFO`     | PHP-/Node-Code ohne Runtime-Pin im Repo                          | Version dort prüfen, wo die App läuft      |
| `OK`       | Gefixte oder nicht betroffene Version (nur mit `-v` sichtbar)    | –                                          |

### Fix-Versionen (Stand 26.10.2026)

| Komponente | Gefixt ab                                   | EOL / kein Fix                  |
|------------|---------------------------------------------|---------------------------------|
| PHP        | 8.2.35, 8.3.36, 8.4.27, 8.5.12              | ≤ 8.1                           |
| Node.js    | 22.23.4, 24.22.1, 26.12.1                   | 20.x, 23.x, 25.x und älter      |
| Bun        | 1.4.4                                       | –                               |
| Brotli     | 1.0.10, 1.1.1, 1.2.1 (lib + PyPI `Brotli`); `brotlicffi` 1.2.1.0 | – (vor 1.0.3 nicht betroffen) |
| Debian `libbrotli1` | bookworm `1.0.9-2+deb12u1`, trixie `1.1.0-2+deb13u1` | –                 |

Die Tabellen stehen oben im Script (`PHP_FIXED`, `NODE_FIXED`, `BUN_FIXED`, `BROTLI_FIXED`) und müssen bei neuen Releases dort nachgeführt werden.

---

## Beispielausgabe

### Standard (nur Befunde)

```text
$ ./2shell-detector.py ~/SourceCode

== /Users/steven/SourceCode ==

  blog
    UNPINNED   PHP (wordpress) latest       docker-compose.yml:3             image: wordpress:latest · PHP-Version nicht aus Tag ableitbar -> Laufzeit pruefen (--docker)

  legacy-intranet
    EOL        PHP 7.4                      Dockerfile:1                     FROM php:7.4-apache · PHP 7.4 ist EOL, kein Upstream-Fix -> Upgrade auf >= 8.2.35

  ml-service
    AFFECTED   Python Brotli 1.1.0          requirements.txt:1               requirements.txt · Fix: 1.1.1

  shop-api
    AFFECTED   Node.js 22.11.0              Dockerfile:1                     FROM node:22.11.0-alpine · Fix: 22.23.4  [!] Brotli-Inbound-Pfad: express@5.1.0

== Zusammenfassung ==
  Geprueft: 5 Repos/Container   AFFECTED 2   EOL 1   UNPINNED 1
  Patchen: legacy-intranet, ml-service, shop-api
  Legende: AFFECTED=verwundbare Version  EOL=kein Fix verfuegbar  UNPINNED=floating, verifizieren  REVIEW=manuell pruefen  INFO=Runtime nicht im Repo
```

Spalten: **Status** · **Komponente + Version** · **Datei:Zeile** (relativ zum Repo) · **Detail** (Quelle und empfohlene Massnahme).
Die Zeile `Patchen:` listet alle Repos/Container mit mindestens einem `AFFECTED`- oder `EOL`-Befund.

### Mit `-v`

Zeigt zusätzlich `OK`-Befunde und Repos ohne Befund als `CLEAN`:

```text
  clean-app
    OK         PHP 8.4.27                   Dockerfile:1                     FROM php:8.4.27-fpm · gefixt (>= 8.4.27)
```

### Mit `--docker` (illustrativ)

Bei Containern steht statt Datei:Zeile das Image samt OS, im Kopf zusätzlich Image und Compose-Verzeichnis:

```text
== Laufende Container (Runtime) ==

  blog-web-1  [wordpress:latest · /data/docker-containers/blog]
    AFFECTED   PHP 8.3.30                   wordpress:latest (Debian GNU/L…  Fix: 8.3.36 · /usr/local/bin/php -v: "PHP 8.3.30 (cli) (built: …) ( NTS )"
    OK         libbrotli1 (deb) 1.0.9-2+deb…                                 Debian-Security-Fix (1.0.9-2+deb12u1)
```

### JSON (`--json`)

```json
{
  "generated": "2026-10-26T09:29:41",
  "findings": [
    {
      "unit": "shop-api",
      "kind": "repo",
      "status": "AFFECTED",
      "component": "Node.js",
      "version": "22.11.0",
      "cve": "CVE-2026-111497",
      "file": "Dockerfile",
      "line": 1,
      "detail": "FROM node:22.11.0-alpine · Fix: 22.23.4  [!] Brotli-Inbound-Pfad: express@5.1.0",
      "exposed": true
    }
  ]
}
```

| Feld        | Inhalt                                                                  |
|-------------|-------------------------------------------------------------------------|
| `unit`      | Repo-Ordner bzw. Container-Name                                         |
| `kind`      | `repo` oder `container`                                                 |
| `status`    | Siehe Status-Werte (inkl. `OK`, JSON enthält immer alle Befunde)        |
| `component` | z. B. `PHP`, `PHP (wordpress)`, `Node.js`, `Python Brotli`, `libbrotli1 (deb)` |
| `version`   | Erkannte Version oder Tag (`?`, wenn unbekannt)                         |
| `cve`       | `CVE-2026-109618/-109619` (PHP) oder `CVE-2026-111497` (Brotli)         |
| `file`      | Datei relativ zum Repo bzw. Image + OS bei Containern                   |
| `line`      | Zeilennummer oder `null`                                                |
| `detail`    | Quelle, Begründung und empfohlene Massnahme                             |
| `exposed`   | Nur vorhanden, wenn ein Brotli-Inbound-Pfad erkannt wurde               |

Auswertung mit `jq`, z. B. alle dringenden Befunde:

```bash
./2shell-detector.py --json --docker | jq '.findings[] | select(.status=="AFFECTED" or .status=="EOL")'
```

---

## Exit-Codes

| Code | Bedeutung                                   |
|------|---------------------------------------------|
| `0`  | Sauber (nur `OK`/`INFO`)                    |
| `1`  | Nur `UNPINNED` und/oder `REVIEW`            |
| `2`  | Mindestens ein `AFFECTED` oder `EOL`        |

Damit lässt sich das Tool direkt in CI oder Cron einbinden:

```bash
./2shell-detector.py . --no-color || [ $? -eq 1 ]   # bricht nur bei AFFECTED/EOL ab
```

---

## Grenzen

- Statische Analyse sieht nur, was im Repo steht. Floating Tags (`latest`, `8.3-fpm`, `lts`) sind immer `UNPINNED` – die tatsächliche Version liefert nur `--docker`.
- Distro-Backports (Debian, Ubuntu, Alpine, RHEL) werden nur teilweise erkannt; im Zweifel `REVIEW`.
- Go-, Rust- und .NET-Funde werden nicht versioniert bewertet, sondern immer als `REVIEW` gemeldet.
- Transitive Python-Abhängigkeiten auf Brotli werden nur über Lockfiles oder Extras (`[brotli]`, `[speedups]`) erkannt.
- Gestoppte Container, Remote-Hosts und Kubernetes-Pods werden nicht geprüft.

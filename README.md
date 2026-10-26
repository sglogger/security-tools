# security-tools

Meine Sammlung kleiner Tools für die tägliche Security-Arbeit: Schwachstellen in eigenen Repos und Containern finden, Systeme schnell überprüfen und wiederkehrende Checks automatisieren.

Die Tools sind bewusst schlank gehalten:

- **Nur lesend**, sofern nicht ausdrücklich anders dokumentiert. Sie melden Befunde, ändern aber nichts.
- **Möglichst ohne Abhängigkeiten**, damit sie direkt auf Servern und Workstations (macOS/Linux) laufen.
- **Skriptfähig**, mit sprechenden Exit-Codes und, wo sinnvoll, JSON-Ausgabe für CI, Cron oder `jq`.

## Tools

| Tool | Zweck |
|------|-------|
| [2shell-detector](2shell-detector/) | Findet verwundbare PHP-, Node.js-, Bun- und Brotli-Versionen (PHP2Shell, CVE-2026-109618/-109619; Node2Shell/HTTP2Shell, CVE-2026-111497) in Repos und laufenden Docker-Containern. |

Jedes Tool liegt in einem eigenen Ordner mit eigenem README (Verwendung, Optionen, Beispielausgabe).

## Hinweis

Die Tools sind für die Prüfung eigener bzw. autorisierter Systeme gedacht. Ergebnisse sind Hinweise, keine Garantie.
z.B.  Befunde mit `REVIEW` oder `UNPINNED` immer manuell verifizieren.

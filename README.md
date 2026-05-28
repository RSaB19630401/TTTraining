# TT-Training

Tischtennis-Trainings-App mit Spielerverwaltung, Beurteilungen, Radardiagrammen und Zeitverlauf.

## Architektur

| Komponente | Technologie | Kosten |
|------------|-------------|--------|
| Frontend | Statische HTML-Datei | kostenlos |
| Backend | Cloudflare Worker (API) | Free Tier |
| Datenbank | Cloudflare D1 (SQLite) | Free Tier |
| Quellcode | GitHub (privates Repo) | kostenlos |

## Voraussetzungen

- Node.js (>= 18)
- Cloudflare-Account (kostenlos unter https://dash.cloudflare.com/sign-up)
- Git

## Erstinstallation

### 1. Wrangler installieren und einloggen

```bash
npm install -g wrangler
wrangler login
```

### 2. D1-Datenbank erstellen

```bash
wrangler d1 create tt-training-db
```

Ausgabe enthält eine `database_id`, z.B.:
```
✅ Created DB 'tt-training-db'
database_id = "abc123-def456-..."
```

### 3. wrangler.toml anpassen

Die `database_id` aus Schritt 2 eintragen:

```toml
database_id = "abc123-def456-..."
```

Vereinsname anpassen (optional):

```toml
INITIAL_VEREIN = "TV Brühl 1912"
```

### 4. JWT-Secret setzen (Cloudflare Secret — wird NICHT nach GitHub gepusht)

```bash
wrangler secret put JWT_SECRET
```

Dann einen langen zufälligen String eingeben (min. 32 Zeichen).
Z.B. generieren via: https://generate-random.org/random-string-generator

### 5. Datenbank-Tabellen anlegen

```bash
wrangler d1 execute tt-training-db --file=schema.sql --remote
```

### 6. Deployen

```bash
wrangler deploy
```

Die App läuft unter: `https://tt-training.<dein-account>.workers.dev`

## Erster Login

1. App im Browser öffnen
2. Login: **TT-Admin** / **TT-Admin**
3. Verwaltung → Trainer anlegen (z.B. sich selbst, Rolle: **Admin**)
4. Abmelden → mit neuem Admin-Account einloggen → Passwort ändern
5. TT-Admin-Zugang ist ab jetzt automatisch gesperrt

## Rollen

| Rolle | Rechte |
|-------|--------|
| **Admin** | Alles: Spieler, Trainer, Beurteilungen, Listen, Passwort-Reset, Import/Export |
| **Trainer** | Spieler ansehen/bearbeiten, Beurteilungen erstellen/ändern, Auswertung, Export |
| **Spieler** | Nur eigene Daten (read-only): Stammdaten, Beurteilungen, Radardiagramm, Zeitverlauf |

## Automatische Accounts

**Spieler** — werden beim Anlegen erzeugt:
- Benutzername: `vorname.nachname` (Umlaute aufgelöst: ä→ae, ö→oe, ü→ue, ß→ss)
- Initialpasswort: `TVB1912` (Pflichtänderung beim ersten Login)

**Trainer** — werden beim Anlegen erzeugt:
- Benutzername: `vorname.nachname`
- Initialpasswort: `TVB1912admin` (Pflichtänderung beim ersten Login)

## Lokale Entwicklung

```bash
# .dev.vars für lokale Secrets anlegen (wird nicht gepusht)
cp .dev.vars.example .dev.vars
# Werte in .dev.vars anpassen

# Lokale D1-Datenbank initialisieren
wrangler d1 execute tt-training-db --file=schema.sql --local

# Dev-Server starten
wrangler dev
```

## Git-Workflow

```bash
# Änderungen committen
git add .
git commit -m "Beschreibung der Änderung"
git push

# Auf Cloudflare deployen
wrangler deploy
```

## Datenexport/-import

Über den Import/Export-Tab (Admin/Trainer):
- **Export:** Alle Daten als JSON-Backup herunterladen
- **Import:** JSON-Backup importieren (Daten werden zusammengeführt, vorhandene IDs aktualisiert)

## Sicherheit

- Passwörter: PBKDF2 mit 100.000 Iterationen + zufälligem Salt (gehashed, nie im Klartext)
- Sessions: JWT-Token (24h Gültigkeit), signiert mit HMAC-SHA256
- JWT-Secret: Als Cloudflare Secret gespeichert, nicht im Code
- Rollenberechtigung: Jeder API-Endpunkt prüft die Benutzerrolle

## Spätere Erweiterungen

- **Multi-Tenant:** Schema ist bereits mandantenfähig (verein_id auf allen Tabellen)
- **Eigene Domain:** In Cloudflare Dashboard → Workers → Custom Domain zuweisen
- **Bezahlmodell:** Stripe-Integration für Vereins-Registrierung
- **DSGVO:** Datenschutzerklärung + AVV bei Weitergabe an andere Vereine

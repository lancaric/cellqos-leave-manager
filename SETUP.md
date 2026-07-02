# Lokálne vývojové prostredie

Tento návod slúži na rozbehnutie projektu na úplne novom počítači. Aplikácia sa
lokálne spúšťa bez Encore: frontend cez Vite, backend cez Express a databáza v
PostgreSQL.

## 1. Nainštaluj potrebné nástroje

Potrebuješ:

- Git
- aktuálnu LTS verziu Node.js (minimálne Node.js 22, vrátane npm)
- Docker Desktop
- voliteľne Python 3, iba pre generovanie PDF reportov

Na Windows ich môžeš nainštalovať cez `winget`:

```powershell
winget install --id Git.Git -e
winget install --id OpenJS.NodeJS.LTS -e
winget install --id Docker.DockerDesktop -e
winget install --id Python.Python.3.13 -e
```

Po inštalácii otvor nový terminál a over nástroje:

```powershell
git --version
node --version
npm --version
docker --version
docker compose version
python --version
```

> Projekt má v manifestoch uvedený Bun, ale aktuálne skripty a
> `package-lock.json` používajú npm workspaces. Bun preto na lokálny vývoj
> nepotrebuješ.

## 2. Získaj projekt a nainštaluj závislosti

```powershell
git clone <URL_REPOZITARA>
cd cellqos-leave-manager
npm ci
```

Ak už repozitár máš, stačí v jeho koreňovom priečinku spustiť `npm ci`.
Príkaz nainštaluje závislosti koreňa, backendu aj frontendu.

## 3. Spusti PostgreSQL cez Docker

Spusti Docker Desktop a potom z koreňa repozitára vytvor PostgreSQL kontajner:

```powershell
docker run --name cellqos-postgres -e POSTGRES_USER=postgres -e POSTGRES_PASSWORD=postgres -e POSTGRES_DB=cellqos -p 5432:5432 -d postgres:16
```

Počkaj, kým bude databáza pripravená:

```powershell
docker logs -f cellqos-postgres
```

Keď sa zobrazí `database system is ready to accept connections`, ukonči
sledovanie logu cez `Ctrl+C`. Následne zapni rozšírenie `pgcrypto`:

```powershell
docker exec cellqos-postgres psql -U cellqos_dev -d cellqos_leave_manager -c 'CREATE EXTENSION IF NOT EXISTS "pgcrypto";'
```

Heslo `cellqos_dev` je určené iba na lokálny vývoj. Dáta zostanú zachované v
Docker volume `cellqos-postgres-data`, aj keď kontajner zastavíš.

Pri ďalšom vývoji už existujúci kontajner spustíš a zastavíš takto:

```powershell
docker start cellqos-postgres
docker stop cellqos-postgres
```

## 4. Nastav premenné prostredia

Vytvor súbor `backend/.env`:

```dotenv
DATABASE_URL="postgresql://cellqos_dev:cellqos_dev@localhost:5432/cellqos_leave_manager?schema=public"
JWT_SECRET="nahodny-dlhy-retazec-pre-lokalny-vyvoj"
PORT=4000
APP_TIMEZONE="Europe/Bratislava"
PYTHON_BIN="python"
```

Bezpečný náhodný JWT secret si môžeš v PowerShelli vygenerovať takto:

```powershell
[Convert]::ToBase64String([Security.Cryptography.RandomNumberGenerator]::GetBytes(48))
```

Súbory `.env` a `backend/.env` sú ignorované Gitom. Neukladaj do repozitára
reálne heslá ani produkčné tajomstvá.

Frontend pri lokálnom vývoji automaticky používa
`http://localhost:4000/api`. Ak backend spúšťaš inde, vytvor
`frontend/.env.local`:

```dotenv
VITE_API_BASE_URL="http://localhost:4000/api"
```

## 5. Priprav databázu

Z koreňa repozitára spusti:

```powershell
npm --workspace backend run prisma:generate
npm --workspace backend run prisma:migrate
npm --workspace backend run prisma:seed
```

Migrácia vytvorí databázovú schému a seed vloží lokálne demo dáta. Seed je
možné spustiť opakovane.

## 6. Spusti aplikáciu

Otvor dva terminály v koreňovom priečinku projektu.

Terminál 1 – backend:

```powershell
npm run dev:backend
```

Terminál 2 – frontend:

```powershell
npm run dev:frontend
```

Aplikácia bude dostupná na:

- frontend: `http://localhost:5173`
- API: `http://localhost:4000/api`

Ak je port obsadený, Vite automaticky ponúkne iný frontendový port. Backendový
port môžeš zmeniť cez `PORT` v `backend/.env`; zároveň potom uprav
`VITE_API_BASE_URL`.

## 7. Demo účty

Po seede sa môžeš prihlásiť heslom `Password123!`:

| Rola | E-mail |
| --- | --- |
| Admin | `admin@cellqos.com` |
| Manažér | `manager@cellqos.com` |
| Zamestnanec | `anna@cellqos.com` |
| Zamestnanec | `peter@cellqos.com` |
| Zamestnanec | `lucia@cellqos.com` |

Pri prvom prihlásení aplikácia vyžiada zmenu hesla.

## Voliteľné nastavenia

### SMTP e-maily

Bez SMTP aplikácia funguje, iba neposiela e-mailové notifikácie. Pre SMTP
doplň do `backend/.env`:

```dotenv
SMTP_HOST="smtp.example.com"
SMTP_PORT=587
SMTP_USER="smtp-user"
SMTP_PASS="smtp-password"
SMTP_FROM="Leave Manager <no-reply@example.com>"
SMTP_SECURE=false
SMTP_REQUIRE_TLS=true
SMTP_TLS_REJECT_UNAUTHORIZED=true
```

Port `465` zvyčajne používa `SMTP_SECURE=true`, port `587`
`SMTP_SECURE=false`. Vypnutie `SMTP_TLS_REJECT_UNAUTHORIZED` používaj iba
dočasne pri diagnostike lokálneho certifikátu.

### Active Directory / LDAP

Bez týchto premenných zostáva aktívne bežné prihlásenie e-mailom a heslom:

```dotenv
LDAP_URL="ldaps://ad.example.local:636"
LDAP_BASE_DN="DC=example,DC=local"
LDAP_BIND_DN="CN=ldapuser,DC=example,DC=local"
LDAP_BIND_PASSWORD="secret"
LDAP_EMAIL_SUFFIX="example.local"
LDAP_TIMEOUT_MS=5000
LDAP_TLS_CA_FILE="C:\cesta\k\internal-ad-ca.crt"
LDAP_TLS_REJECT_UNAUTHORIZED=true
```

Pri internej CA nastav `LDAP_TLS_CA_FILE`. Hodnotu
`LDAP_TLS_REJECT_UNAUTHORIZED=false` používaj iba na krátku diagnostiku, nie v
produkcii.

### Automatické mesačné reporty

Príjemcov je možné zadať ako zoznam e-mailov oddelený čiarkami:

```dotenv
MONTHLY_REPORT_RECIPIENTS="manager@example.com,hr@example.com"
```

Táto funkcia potrebuje funkčné SMTP a Python 3.

## Užitočné príkazy

```powershell
# produkčný build frontendu do backend/frontend/dist
npm run build

# spustenie backendu so zostaveným frontendom
npm start

# nová Prisma migrácia po zmene schémy
npm --workspace backend exec prisma migrate dev -- --name nazov_zmeny

# Prisma Studio
npm --workspace backend exec prisma studio
```

## Riešenie problémov

### Docker alebo PostgreSQL kontajner nie je dostupný

Over, že Docker Desktop beží, a skontroluj kontajner:

```powershell
docker ps -a --filter "name=cellqos-postgres"
docker logs cellqos-postgres
```

Ak je kontajner zastavený, spusti ho cez `docker start cellqos-postgres`.
Predvolený port PostgreSQL je `5432`.

Ak port používa iná služba, vytvor kontajner s mapovaním `-p 5433:5432` a v
`DATABASE_URL` zmeň port na `5433`.

### `P1000`, `P1001` alebo chyba pripojenia k databáze

Skontroluj meno databázy, používateľa, heslo a port v `DATABASE_URL`. Heslo so
špeciálnymi znakmi musí byť v URL percentuálne zakódované.

### `JWT_SECRET is required`

Backend nenašiel `backend/.env`, prípadne bol spustený z nesprávneho pracovného
priečinka. Použi koreňový príkaz `npm run dev:backend`.

### Frontend hlási sieťovú chybu

Over, že backend beží na porte `4000` a že `VITE_API_BASE_URL` končí na
`/api`. Po zmene frontendového `.env.local` reštartuj Vite.

### Potrebujem čistý reset lokálnej databázy

Nasledujúci príkaz vymaže všetky lokálne dáta a znovu vykoná migrácie aj seed:

```powershell
npm --workspace backend exec prisma migrate reset
```

Použi ho iba nad lokálnou vývojovou databázou.

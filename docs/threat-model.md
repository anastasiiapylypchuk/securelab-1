# Threat model — SecureLab, ЛР 6 (baseline 2-A)

## 1. Версія та середовище

| Параметр | Значення |
|---|---|
| Review-start commit | `769fcdee618634fe4558e46b0bd21f4e920a4184` (тег `v0.5.0`), гілка `lab/6-hardening-review` |
| SDK | .NET SDK 10.0.302 (`global.json`: 10.0.100, rollForward latestFeature) |
| ОС і клієнти | Windows, PowerShell 5.1; Microsoft Edge (Chromium) DevTools; JetBrains Rider HTTP Client; curl.exe |
| Профілі | Development (`dotnet run --project src/SecureLab.Api`, http://localhost:5080); Production-like (`ASPNETCORE_ENVIRONMENT=Production`, `--no-launch-profile`) |
| Дані | лише навчальні акаунти seed (alice, bob — Reporter; morgan — Analyst; admin) після `dotnet run --project src/SecureLab.Api -- --reset-database`; пароль seed — лише в змінній `SeedUsers__Password` поза Git |
| БД | PostgreSQL у Docker Compose (`infra/compose.yaml`), порт лише `127.0.0.1:54329` |
| Redis | лише для погодженого advanced variant: `infra/compose.redis.yaml`, порт лише `127.0.0.1:6379`, без persistence |

## 2. Компоненти в межах огляду

- Browser client: `src/SecureLab.Api/Client` — `index.html`/`app.js`, `auth-lab.html`/`auth-lab.js`, `browser-lab.html`/`browser-lab.js`, `csrf.js` (ЛР 6).
- ASP.NET Core API: `Program.cs`, `Scaffolding/Lab02Endpoints.cs`, `Scaffolding/Lab03Identity.cs`, `Presentation/Endpoints/IncidentEndpoints.cs`, `Security/AntiforgeryFilter.cs`.
- PostgreSQL (EF Core, Npgsql).
- Redis (лічильник rate limit пошуку, advanced variant).
- Конфігурація: `appsettings*.json`, змінні середовища, `infra/*.yaml`, `.gitignore`, `infra/.env.example`.
- Журнал: console logger API (diagnostic log + audit events).
- Build: `dotnet restore --locked-mode`, `packages.lock.json`, NuGet (api.nuget.org).

## 3. Активи

| Актив | Чому цінний |
|---|---|
| Credentials користувачів (пароль, auth cookie `.AspNetCore.Identity.Application`) | дають змогу діяти від імені користувача |
| Incident (title, description, коментарі) | конфіденційність чужих записів і цілісність власних |
| Право зміни `Incident.Status` (triage, лише Analyst) | канонічний привілейований перехід |
| Antiforgery token pair | захищає змінювальні запити від CSRF |
| Audit/diagnostic log | розслідування; не має розкривати секрети й зайві дані |
| Configuration secrets (connection string, `SeedUsers__Password`, адреса Redis) | доступ до сховищ |
| Доступність пошуку (`GET /api/incidents/search`) | ресурсоємна операція, ціль зловживання |

Password hash не є паролем, але також не повертається клієнту (A-02).

## 4. Суб'єкти

anonymous visitor; authenticated Reporter (alice, bob); Analyst (morgan); local developer (запускає стенд і має доступ до журналу); стороння сторінка в браузері жертви (CSRF-контекст).

## 5. Entry points

| Method + route | Хто викликає | Змінює стан | Захист |
|---|---|---|---|
| POST /api/auth/register | anonymous | так (акаунт) | валідація DTO |
| POST /api/auth/login | anonymous | так (сеанс) | login limiter `auth-login` |
| POST /api/auth/logout | authenticated | так (сеанс) | RequireAuthorization + antiforgery (ЛР 6) |
| GET /api/me, GET /api/auth/session-check | authenticated | ні | RequireAuthorization |
| GET /api/antiforgery/token | authenticated | видає cookie-частину токена | RequireAuthorization |
| GET /api/incidents, /api/incidents/{id}, /api/incidents/severity-summary, /api/incident-comments/{id} | authenticated | ні | resource authorization |
| GET /api/incidents/search?q=&sortBy= | authenticated | ні | параметризований ILike, allowlist sortBy, limiter `incident-search` |
| POST /api/incidents | authenticated | так | валідація, owner з principal, antiforgery |
| PUT /api/incidents/{id} | власник | так | resource authorization, antiforgery |
| POST /api/incidents/{id}/triage | Analyst | так (Status) | resource authorization, audit, antiforgery |
| DELETE /api/incidents/{id} | власник | так | resource authorization, antiforgery |
| GET /health | anonymous | ні | — |
| Configuration loading (env, appsettings) | startup | — | Production не читає Development-конфігурацію |
| `dotnet restore` | developer | build | `--locked-mode`, lockfiles |

## 6. Межі довіри

```
browser client (untrusted input, automatic auth cookie)
   │  HTTP на localhost (HTTPS/TLS — поза межами огляду)
   ▼
ASP.NET Core API (validation, authn/authz, antiforgery, rate limiting, safe errors, logging)
   │  connection string / EF Core            │  StackExchange.Redis
   ▼                                         ▼
PostgreSQL (application data)             Redis (лічильники rate limit, TTL)

repository + NuGet ─────────► build / restore
environment configuration ──► API startup
```

| Межа | Очікувана властивість | Конкретна перевірка |
|---|---|---|
| browser→API | змінювальний запит із cookie без валідного request token відхилено без зміни стану | REG-CSRF-01 (`CsrfRegressionTests.RegCsrf01_…`), EV-CSRF-02 |
| browser→API | текст користувача не виконується як код | REG-XSS-01 (`ClientScript_DoesNotUseDangerousInnerHtmlSink`, `tests/browser/description-dom.js`) |
| browser→API | чужий Incident недоступний, Reporter не виконує triage | A-* ЛР 4 (`GetDetails_AsOtherReporter_Returns404_…`, `Triage_AsOwnerReporter_Returns403_AndStatusUnchanged`), A-05 |
| browser→API | ідентичність береться з verified principal, а не з тіла чи header | A-03, A-04, A-05 |
| browser→API | лише точний origin читає відповіді з credentials | REG-CORS-01 (EV-CORS-01) |
| browser→API | помилка не розкриває внутрішні деталі | EV-ERR-01 |
| API→PostgreSQL | параметр пошуку не змінює структуру SQL | S-02 (`Search_*`, EV-SQLI-01) |
| API→Redis | лічильник спільний для екземплярів; збій Redis не знімає ліміт | EV-REDIS-01…03 |
| repository→build | tracked files без реальних credentials; restore не змінює lockfile непомітно | EV-SEC-01/02, `dotnet restore SecureLab.sln --locked-mode` (EV-DEP-01) |
| environment→configuration | у Production немає Dev-конфігурації (OpenAPI, CORS, reset), секрети поза Git | EV-PROD-01/02, розділ 8.4 security review |

## 7. Наявні controls

Серверна валідація і параметризовані запити (ЛР 2); Identity + cookie HttpOnly/SameSite=Lax, login limiter (ЛР 3); resource authorization (ЛР 4); safe DOM, CORS allowlist, CSP (ЛР 5); ProblemDetails + ExceptionHandler (starter). Додано в ЛР 6: antiforgery на всьому cookie-периметрі, заголовки на шляху помилки, обов'язкова автентифікація logout, audit успішного triage, limiter пошуку (in-memory → Redis).

## 8. Asset → threat → control → verification

| Asset | Threat | Control | Verification |
|---|---|---|---|
| Цілісність Incident власника | стороння сторінка надсилає PUT/DELETE з автоматичною cookie (CSRF) | `AntiforgeryFilter` → `ValidateRequestAsync` до handler | REG-CSRF-01: без токена 400 і незмінний опис; валідна пара → 204 і змінений опис |
| Право зміни Incident.Status | Reporter або CSRF ініціює triage | resource authorization (Triage) + antiforgery + audit | `Triage_AsOwnerReporter_Returns403_AndStatusUnchanged`; EV-AUDIT-01 (denied/allowed) |
| Чужі Incident | IDOR підстановкою id | IncidentAuthorizationHandler, 404 для чужого | `GetDetails_AsOtherReporter_Returns404_SameAsUnknownId_AndLeaksNothing`, `Update/Delete_AsOtherReporter_*` |
| Сеанс користувача | XSS викрадає дані/діє від імені | safe DOM (textContent), CSP enforcement, HttpOnly | REG-XSS-01; EV-CSP-01 (Console без порушень, marker показано як текст) |
| Дані БД | SQL injection через q/sortBy | ILike з параметром, allowlist sortBy | S-02; EV-SQLI-01 (`' OR '1'='1` → 0 рядків, `sortBy` з `;` → 400) |
| Внутрішня інформація | stack trace / SQL / connection string у відповіді | UseExceptionHandler + ProblemDetails, traceId | EV-ERR-01 |
| Захисні властивості браузера на помилках | 500 без CSP/nosniff | заголовки в `Response.OnStarting` | F-01 retest (EV-HDR-02) |
| Достовірність audit log | анонімні запити створюють хибні події logout | RequireAuthorization на logout | F-03 retest: анонімний logout → 401 |
| Credentials у журналі | пароль/cookie/токен потрапляють у log | structured logging без тіл і імен, EF маскує параметри | EV-LOG-01, EV-REDIS-03 (0 збігів) |
| Доступність пошуку | перебір/надмірні запити, обхід ліміту масштабуванням | limiter `incident-search` у Redis, fail-closed | EV-REDIS-01 (спільна квота), EV-REDIS-02 (failure mode) |
| Configuration secrets | реальний credential у Git | `.gitignore`, змінні середовища, study-only значення обмежені 127.0.0.1 | EV-SEC-01/02 |

## 9. Виключення

- Зовнішній penetration test не виконувався.
- Реальний HTTPS/TLS, HSTS і reverse proxy на production host не тестувалися — production host відсутній.
- Git history, stash, інші clones, forks і зовнішній CI не перевірялися (підозри витоку немає).
- DoS-навантаження й продуктивність Redis не вимірювалися.
- Сторонні браузерні розширення й ОС-рівень поза межами.

## 10. Відтворюваний старт (PowerShell)

```powershell
git switch lab/6-hardening-review
$seedSecret = Read-Host 'Локальний пароль' -AsSecureString
$env:SeedUsers__Password = [Net.NetworkCredential]::new('', $seedSecret).Password
Remove-Variable seedSecret
$env:Redis__Configuration = "127.0.0.1:6379,abortConnect=false"
docker compose --env-file infra/.env.example -f infra/compose.yaml up -d --wait
docker compose -f infra/compose.redis.yaml up -d --wait
dotnet restore SecureLab.sln --locked-mode
dotnet run --project src/SecureLab.Api -- --reset-database
dotnet test SecureLab.sln -c Release
dotnet run --project src/SecureLab.Api
```

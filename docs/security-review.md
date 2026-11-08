# Security review SecureLab, ЛР 6

## 1. Executive summary

Перевірено власний проєкт SecureLab (baseline 2-A) від review-start commit `769fcde` (тег `v0.5.0`) у локальному Development і Production-like профілях; у межах огляду — browser client, ASP.NET Core API, PostgreSQL, Redis (лише для погодженого advanced variant), конфігурація, журнал і залежності; поза межами — реальний HTTPS/production host і зовнішній pentest. Зафіксовано й виправлено три власні findings: F-02 (P1, змінювальні маршрути без antiforgery), F-01 (P2, security headers зникали на 500) і F-03 (P3, анонімний logout із хибною audit-подією, знайдено поза checklist). Додатково реалізовано погоджений викладачем advanced variant — спільний ліміт пошуку в Redis із перевіреним fail-closed. Автоматизований regression pack (42 тести, включно з повним REG-CSRF-01) і ручні сценарії пройшли після останньої зміни; фінальний прогін на прийнятому merge commit і hash тегу `v1.0.0` наведено на титульній сторінці PDF. Найважливіші залишкові ризики: login-CSRF (login/register без токена), локальний для екземпляра login limiter і Redis без ACL/TLS, допустимий лише на локальному стенді.

## 2. Scope та exclusions

**У межах огляду:** `src/SecureLab.Api` (endpoints ЛР 2–4, Identity, антифорджері, rate limiting, error handling, headers), `src/SecureLab.Api/Client` (усі три сторінки й `csrf.js`), `tests/SecureLab.Api.Tests`, `tests/http`, `tests/browser`, `infra/compose.yaml`, `infra/compose.redis.yaml`, `infra/.env.example`, `appsettings*.json`, `.gitignore`, `packages.lock.json`, console log API. Повна модель — `docs/threat-model.md`.

**Поза межами:** реальний TLS, HSTS і reverse proxy на production host (його немає); Git history, stash, інші clones, forks і зовнішній CI; DoS-навантаження; сторонні браузерні розширення.

## 3. System overview і trust boundaries

Browser client (недовірений ввід, автоматична auth cookie) → ASP.NET Core API (валідація, authn/authz, antiforgery, rate limiting, safe errors, logging) → PostgreSQL (дані) і Redis (лічильники limiter). Окремі межі: repository + NuGet → build; environment configuration → startup. Схема, активи, entry points і зв'язок кожної межі з конкретною перевіркою — у `docs/threat-model.md`, розділи 3–8.

| Межа | Властивість | Перевірка |
|---|---|---|
| browser→API | mutation з cookie без валідного токена відхилено без зміни стану | REG-CSRF-01 |
| browser→API | user text не виконується як код | REG-XSS-01 |
| browser→API | чужий ресурс недоступний | A-* ЛР 4, A-05 |
| browser→API | точний CORS origin | REG-CORS-01 |
| API→PostgreSQL | q не змінює структуру SQL | S-02 |
| API→Redis | квота спільна; збій Redis не знімає ліміт | EV-REDIS-01…03 |
| repository→build | немає реальних credentials; lockfile під контролем | EV-SEC-01/02, EV-DEP-01 |
| environment→configuration | Production без Dev-конфігурації | EV-PROD-01/02, розділ 8.4 |

## 4. Methodology та test environment

- Review-start commit: `769fcdee618634fe4558e46b0bd21f4e920a4184` (тег `v0.5.0`), гілка `lab/6-hardening-review`.
- SDK: .NET 10.0.302; ОС Windows, PowerShell 5.1; браузер Microsoft Edge (Chromium) DevTools; Rider HTTP Client; curl.exe.
- Профілі: Development (`dotnet run --project src/SecureLab.Api`, http://localhost:5080); Production-like (`ASPNETCORE_ENVIRONMENT=Production`, `ASPNETCORE_URLS=http://localhost:5080`, `ConnectionStrings__SecureLab` і `Redis__Configuration` через змінні середовища, `--no-launch-profile`).
- БД: PostgreSQL у Docker Compose, `127.0.0.1:54329`, лише навчальні дані після `--reset-database`. Redis: `infra/compose.redis.yaml`, `127.0.0.1:6379`.
- Акаунти: alice, bob (Reporter), morgan (Analyst); пароль seed — лише у змінній `SeedUsers__Password`, вводиться через `Read-Host -AsSecureString`, ніде не друкується.
- Методика: перевірка кожного control на фактичних відповідях (headers, status, тіло, повторне читання стану), відтворення дефекту на `v0.5.0`, виправлення, retest + positive regression, xUnit (`SecureLabApiFactory`, `CookieClient`), ручні сценарії в DevTools Console.
- Комміти ЛР 6: `fef3c53` (контрольна помилка `.http`), `fac88ef` (F-01), `3bfd5f8` (antiforgery, F-02, F-03, search limiter, REG-CSRF-01), `8e5cd08` (audit успішного triage), `d05df4b` (Redis advanced variant), далі — коміт документації.

## 5. Findings summary

| ID | Finding | Asset | Impact | Likelihood | Priority | Status | Retest / регресія |
|---|---|---|---|---|---|---|---|
| F-02 | Змінювальні cookie-маршрути без antiforgery | цілісність Incident, сеанс | High | Medium | P1 | Fixed (`3bfd5f8`) | REG-CSRF-01 |
| F-01 | Security headers зникають на 500 | захисні властивості браузера | Low–Medium | High | P2 | Fixed (`fac88ef`) | EV-HDR-02, REG-HDR-01 |
| F-03 | Анонімний logout і хибна audit-подія | достовірність журналу | Low | High | P3 | Fixed (`3bfd5f8`) | REG-AUTH-01 (`A06`), EV-F03-02 |

**Порядок дій.** F-02 першою: це несанкціонована зміна основного активу (Incident, у т.ч. привілейований triage) від імені користувача; передумова — лише активний сеанс жертви і відвідування підконтрольної сторінки. F-01 другою: зачіпає кожну відповідь-помилку і доступна без передумов, але тіло 500 уже безпечне, тож це втрата defense in depth, а не прямий витік. F-03 останньою: даних не розкриває й не змінює, впливає лише на достовірність журналу; доступна анонімно, але наслідок найменший. F-03 знайдено власним аналізом периметра (поза checklist).

**Тимчасово прийняті ризики:**

| Ризик | Compensating control | Відповідальна / follow-up |
|---|---|---|
| Login-CSRF і account-creation CSRF (login/register без токена) | SameSite=Lax auth cookie; JSON Content-Type вимагає preflight; CORS дозволяє лише `http://localhost:4173` і лише в Development; login limiter | Пилипчук А.В.; анонімний bootstrap токена для login/register — перед будь-яким розгортанням поза локальним стендом |
| Login limiter локальний для екземпляра | один екземпляр API на стенді; ліміт 30/10 с за IP | Пилипчук А.В.; перенести `auth-login` у Redis так само, як `incident-search`, при запуску кількох екземплярів |
| Redis без ACL/TLS | порт лише `127.0.0.1`, без persistence, у Redis лише лічильники | Пилипчук А.В.; ACL, пароль поза Git і TLS — обов'язкові для будь-якого нелокального середовища |

## 6. Detailed findings

Повні картки — `docs/findings/`:

- `F-01-error-path-headers.md` — headers на шляху помилки;
- `F-02-missing-csrf-protection.md` — antiforgery на cookie-периметрі;
- `F-03-anonymous-logout.md` — анонімний logout (поза checklist).

Кожна картка містить передумови, відтворення з expected/actual, вплив і ймовірність зі статусом перевірки, першопричину, виправлення з fixed commit, retest, positive regression, залишковий ризик і очищений доказ.

**Retest для іншої людини (найважливіший сценарій, REG-CSRF-01):**

1. Передумови: гілка з тегом `v1.0.0`, PostgreSQL і Redis підняті (розділ 4), задано `SeedUsers__Password` і `Redis__Configuration`, виконано `dotnet run --project src/SecureLab.Api -- --reset-database`.
2. Автоматично: `dotnet test SecureLab.sln -c Release --filter RegCsrf01` → `Passed: 1`. Тест входить як alice, створює власний інцидент і перевіряє: без токена → 400 і опис `before`; невалідний токен → 400 і опис `before`; після `GET /api/antiforgery/token` валідна пара → 204 і опис `after`.
3. Вручну: `dotnet run --project src/SecureLab.Api` → `http://localhost:5080/auth-lab.html` → вхід alice → DevTools Console: `PUT /api/incidents/20000000-0000-0000-0000-000000000001` без header `X-CSRF-TOKEN` → 400, опис не змінився; `GET /api/antiforgery/token` → 200; той самий PUT із `X-CSRF-TOKEN` → 204, опис змінився.

## 7. Regression results

Автоматизована частина: `dotnet test SecureLab.sln -c Release` з PostgreSQL і Redis, `SeedUsers__Password` і `Redis__Configuration` у середовищі, після `--reset-database`. Результат на коміті `d05df4b`: total 42, failed 0, succeeded 42. Окремо `--filter RegCsrf01` → total 1, succeeded 1. Результат фінального прогону на прийнятому merge commit і hash `v1.0.0` — на титульній сторінці PDF (hash коміту не може міститися в самому коміті).

| Рівень | ID | Property | Негативний сценарій | Позитивна перевірка | Тест / доказ | Результат |
|---|---|---|---|---|---|---|
| достатній | S-02 (SQLi) | q і sortBy не змінюють SQL | `q=' OR '1'='1` → 200, 0 результатів; `sortBy=title; DROP TABLE incidents` → 400 | `q=лист` → 200, 1 результат | `Search_ReturnsJson`, `Search_AsReporter_DoesNotReturnOtherUsersIncidents`, `Search_Anonymous_Returns401`; EV-SQLI-01 | PASS |
| достатній | REG-AUTH-01 | identity lifecycle, verified principal | анонім → 401 без redirect; підроблений `X-Demo-UserId` ігнорується; після logout → 401; невідомий user = хибний пароль | login → `/api/me` повертає безпечні поля | `A01`, `A02`, `A03`, `A06`, `A07`, `RealCookie_ReachesSessionCheck`, `Login_OverHttps_SetsHttpOnly_Secure_SameSiteLax` | PASS |
| достатній | A-* (IDOR / authorization) | server-side ownership і роль | чужий інцидент read/update/delete → 404 без витоку; Reporter triage → 403, статус незмінний; підроблений owner ігнорується | власник читає/змінює/видаляє; Analyst читає чуже й робить triage | `GetDetails_AsOtherReporter_Returns404_SameAsUnknownId_AndLeaksNothing`, `Update_AsOtherReporter_*`, `Delete_AsOtherReporter_*`, `Triage_AsOwnerReporter_Returns403_AndStatusUnchanged`, `Triage_AsOtherReporter_Returns404`, `Update_AsAnalyst_Returns403_*`, `A04`, `A05`, `Triage_AsAnalyst_MovesNewToTriaged`, `GetComment_*` | PASS |
| достатній | REG-XSS-01 | текст не виконується як код | marker ЛР 5 у коментарі seed-інциденту | легітимний текст відображається | `ClientScript_DoesNotUseDangerousInnerHtmlSink`; `tests/browser/description-dom.js`; EV-CSP-01 (marker показано як текст) | PASS |
| достатній + відмінний (автомат) | REG-CSRF-01 | token pair required | cookie без токена → 400, стан незмінний; невалідний токен → 400, стан незмінний | валідна пара → 204, стан змінено | `CsrfRegressionTests.RegCsrf01_PutWithoutValidToken_IsRejected_StateUnchanged_ThenValidPairSucceeds`; EV-CSRF-02 | PASS |
| достатній | REG-RL-LOGIN | login limiter збережено | 31 невдалий вхід → 30×401, далі 429 | через 11 с alice → 204 | `Login_RateLimit_Returns429_ThenRecovers`; EV-RL-01 | PASS |
| добрий | T-02 (validation) | серверна валідація | `?status=Unknown` → 400 Validation Problem Details; DisplayName 121 символ → 400; дублікат → 409; захищені поля в тілі ігноруються | валідний register → 201 | `Register_Success_Duplicate409_TooLongDisplayName400`, `CreateIncident_DuplicateTitle_Returns409Conflict`, `Update_WithForgedProtectedFields_IgnoresThem`, `GetDetails_ForUnknownId_ReturnsProblemDetails404` | PASS |
| добрий | REG-CORS-01 | точний browser origin | `http://localhost:4174` → «blocked by CORS policy», `Access-Control-*` немає | `http://localhost:4173` → JS читає `{"status":"ready"}` | EV-CORS-01 (браузер + curl) | PASS |
| добрий | REG-RL-SEARCH | quota і partitions пошуку | alice 11-й запит → 429 | bob одночасно → 200; alice після вікна → 200 | EV-RL-02 (in-memory), EV-REDIS-01 (Redis, 2 екземпляри) | PASS |
| — | REG-HDR-01 | headers на 5 класах відповідей | 500 без headers (до F-01) | 200/400/404/500 мають CSP, nosniff, Referrer-Policy; клієнт працює | EV-HDR-01/02, EV-CSP-01 | PASS |
| — | EV-ERR-01 | безпечна 500 + correlation | недосяжна БД → 500 | traceId у відповіді = TraceId у журналі | `tests/http/lab-06-unexpected-error.http` | PASS |
| відмінний | REG-REDIS | спільний ліміт і failure mode | Redis зупинено / недоступний на старті → 500 (fail-closed) | Redis знову доступний → 200; ключі з TTL 9–10 с | EV-REDIS-01…03 | PASS |

Усі сценарії вищих рівнів виконано, тож позначки «Не входить до обраного рівня» немає.

## 8. Hardening controls

### 8.1 Control → risk → verification → boundary

| Control | Ризик | Verification | Межа |
|---|---|---|---|
| Antiforgery (`AntiforgeryFilter`, `X-CSRF-TOKEN`) | CSRF з автоматичною cookie | REG-CSRF-01 | не зупиняє XSS на власному origin; login/register не покриті |
| Server-side resource authorization | IDOR/BOLA, ескалація ролі | A-* ЛР 4 | не замінює authentication |
| Safe errors + traceId | розкриття внутрішніх деталей | EV-ERR-01 | не замінює контроль доступу до журналу |
| CSP + nosniff + Referrer-Policy (у `OnStarting`) | browser defense in depth | EV-HDR-01/02, EV-CSP-01 | не замінює safe DOM |
| CORS allowlist (лише Development) | читання відповідей стороннім origin | REG-CORS-01 | CORS не є authorization; curl його не застосовує |
| Login limiter (IP) | перебір паролів | REG-RL-LOGIN | не authentication; спільний NAT ділить ліміт |
| Search limiter (user id, Redis) | зловживання пошуком, обхід масштабуванням | REG-RL-SEARCH, EV-REDIS-* | не authentication; при збої Redis пошук недоступний |
| Structured logging без чутливих полів | витік credentials у журнал | EV-LOG-01 | не виправляє надмірне збирання даних |
| Audit triage (allowed/denied) | непомітна зміна статусу | EV-AUDIT-01 | logout-подія без subject |

### 8.2 Периметр змінювальних маршрутів (cookie profile)

Джерела: `git grep -n -E "\.Map(Post|Put|Patch|Delete)\(" -- src` (сервер) і `git grep -n -E "method: *.(POST|PUT|PATCH|DELETE)" -- src/SecureLab.Api/Client` (клієнт). GET-маршрути стан не змінюють (перевірено за кодом `IncidentEndpoints.cs`, `Lab02Endpoints.cs`, `Lab03Identity.cs`, `Program.cs`).

| ID | Method + route | Файл | Джерело / розбіжність | Зміна стану | Cookie auth | Browser-accessible | Antiforgery | Regression |
|---|---|---|---|---|---|---|---|---|
| SC-01 | POST /api/incidents | Lab02Endpoints.cs | client: auth-lab.js, browser-lab.js | створює Incident, owner з principal | так | так | explicit | A-04, A-05, EV-CSRF-03 |
| SC-02 | PUT /api/incidents/{id} | IncidentEndpoints.cs | **DISCREPANCY**: немає client call | змінює Incident | так | так | explicit | REG-CSRF-01 |
| SC-03 | POST /api/incidents/{id}/triage | IncidentEndpoints.cs | **DISCREPANCY**: немає client call | змінює Status | так | так | explicit | `Triage_*`, EV-AUDIT-01 |
| SC-04 | DELETE /api/incidents/{id} | IncidentEndpoints.cs | **DISCREPANCY**: немає client call | видаляє Incident | так | так | explicit | `Delete_*` |
| SC-05 | POST /api/auth/logout | Lab03Identity.cs | client: auth-lab.js | завершує сеанс | так | так | explicit + RequireAuthorization (F-03) | A-06, EV-CSRF-04 |
| SC-06 | POST /api/auth/login | Lab03Identity.cs | client: auth-lab.js | створює сеанс | ні (анонімний) | так | не застосовується | residual risk |
| SC-07 | POST /api/auth/register | Lab03Identity.cs | client: auth-lab.js | створює акаунт | ні (анонімний) | так | не застосовується | residual risk |

DISCREPANCY SC-02…SC-04: маршрути ЛР 4 зареєстровані й перевіряються тестами та `.http`, але жодна сторінка клієнта їх не викликає. Вони лишаються в периметрі: довіряють authentication cookie й досяжні з будь-якої сторінки браузера; відсутність кнопки в UI не є захистом.

Контракт: header `X-CSRF-TOKEN`; видача `GET /api/antiforgery/token` (RequireAuthorization, `GetAndStoreTokens`, відповідь із `Cache-Control: no-cache, no-store`); cookie `SecureLab.Antiforgery` — HttpOnly, SameSite=Strict, Secure Always у Production; відмова — 400 Problem Details `Antiforgery token is missing or invalid.`; клієнтський helper `Client/csrf.js` тримає токен лише в пам'яті сторінки.

SC-06/SC-07: cookie-сеансу ще немає, токен видається лише після входу, тому захистити login/register наявним механізмом неможливо без окремого анонімного bootstrap. Login-CSRF і account-creation CSRF — residual risk (розділ 5, 10).

### 8.3 Security headers і cookie (етап 2, п. 1)

| Клас відповіді | Приклад | CSP | X-Content-Type-Options | Referrer-Policy |
|---|---|---|---|---|
| статика | `GET /` → 200 text/html | так | nosniff | no-referrer |
| успішний API | `GET /api/incidents/20000000-…-0001` → 200 | так | nosniff | no-referrer |
| validation | `GET /api/incidents?status=Unknown` → 400 | так | nosniff | no-referrer |
| not found | `GET /api/incidents/99999999-…` → 404 | так | nosniff | no-referrer |
| unexpected error | Production, недосяжна БД → 500 | так (після F-01) | nosniff (після F-01) | no-referrer (після F-01) |

CSP (enforcement): `default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self'; connect-src 'self'; object-src 'none'; base-uri 'self'; form-action 'self'; frame-ancestors 'none'`. Клієнт працює без порушень: Console на `/`, `/auth-lab.html`, `/browser-lab.html` — «No issues» (EV-CSP-01). Відповідь першої видачі антифорджері-токена додатково містить `X-Frame-Options: SAMEORIGIN` (додає ASP.NET Core); сучасні браузери застосовують суворіший `frame-ancestors 'none'`, а відповідь — JSON, не сторінка, тож практичного ризику немає.

Cookie (Development, HTTP): `.AspNetCore.Identity.Application` — HttpOnly, SameSite=Lax, Expires Session, Path `/`, Secure відсутній (SecurePolicy SameAsRequest на HTTP); `SecureLab.Antiforgery` — HttpOnly, SameSite=Strict. У Production обидві мають SecurePolicy Always; локальний HTTP-запуск цього не доводить.

### 8.4 Development vs Production

| Аспект | Development | Production-like | Доказ |
|---|---|---|---|
| OpenAPI / Scalar | `/openapi/v1.json` і `/scalar/v1` доступні | `/openapi/v1.json` → 404 Problem Details; `/scalar/v1` → 200 text/html клієнта (SPA fallback, не Scalar) | EV-PROD-01 |
| Reset БД | дозволено (`Database:AllowReset`) | `--reset-database` → `InvalidOperationException`, процес завершено, дані не змінено | EV-PROD-02 |
| CORS policy `Lab05BrowserProbe` | лише `http://localhost:4173`, GET, credentials | не реєструється | `Program.cs`, REG-CORS-01 |
| Cookie Secure | SameAsRequest | Always (auth і antiforgery) | `Lab03Identity.cs`, `Program.cs` |
| Connection string | `appsettings.Development.json` (study-only) | лише `ConnectionStrings__SecureLab` поза Git | EV-SEC-01 |
| Redis для limiter пошуку | без `Redis__Configuration` — in-memory fallback з тією самою семантикою | без `Redis__Configuration` API не стартує (ліміт не послаблюється мовчки) | `Lab03Identity.cs`, розділ 8.6 |
| Помилки | ProblemDetails + traceId | те саме, без деталей винятку | EV-ERR-01 |

### 8.5 Rate limiting

**Login limiter (ЛР 3, збережено):** політика `auth-login`, partition key — IP-адреса, fixed window 30 запитів / 10 с, без черги, відмова 429. Повторна перевірка: 31 невдалий вхід `nobody-ratelimit` → 30×401, далі 429; через 11 с вхід alice → 204 (EV-RL-01). 429 однаковий для будь-якого userName, тож не розкриває існування акаунта. Rate limit не замінює authentication/authorization.

**Search limiter (ЛР 6):** політика `incident-search` на `GET /api/incidents/search`; partition key `search:<NameIdentifier>` з verified principal (IP спільний за NAT; довільний header підробляє клієнт); fixed window 10 запитів / 10 с, без черги, 429. `UseRateLimiter` стоїть після `UseAuthorization`, тому principal відомий, а анонімний запит відсікає `RequireAuthorization` (401) раніше. Перевірка: alice 10×200, 11-й → 429; bob одразу → 200 (інший partition); alice через > 10 с → 200 (EV-RL-02).

### 8.6 Advanced variant: distributed rate limiting пошуку через Redis

Погоджено викладачем повідомленням у Moodle до реалізації (2026-11-08; відповідь — EV-ADV-00). Усі шість умов погодження виконано (таблиця нижче).

**Реалізація.** `infra/compose.redis.yaml` — `redis:7.4-alpine`, `--save "" --appendonly no`, порт лише `127.0.0.1:6379`, healthcheck `redis-cli ping`; основний `compose.yaml` не змінено. У `Lab03Identity.cs` політика `incident-search` використовує `RedisRateLimitPartition.GetFixedWindowRateLimiter` (пакет `RedisRateLimiting.AspNetCore`, клієнт `StackExchange.Redis`) з тим самим partition key і тією самою семантикою (fixed window 10/10 с). Адреса — `Redis__Configuration` поза Git (`127.0.0.1:6379,abortConnect=false`). У Redis зберігаються лише лічильники partition із TTL — без паролів, cookie, токенів і бізнес-даних.

**Спільний стан і ізоляція (EV-REDIS-01).** Два екземпляри API (`:5080`, `:5081`, Development, одна БД, `--no-build`). Alice увійшла окремо на кожен екземпляр (дві різні cookie). 11 пошуків по черзі між екземплярами: #1–#10 → 200, #11 → 429. Кожен екземпляр бачив ≤ 6 запитів, тож in-memory limiter пропустив би всі; отже квота спільна, а partition визначає id користувача, а не cookie. Bob через `:5081` → 200.

**Фактичні ключі й TTL (`redis-cli --scan`, `TTL`).** `rl:fw:{search:10000000-0000-0000-0000-000000000001}` TTL=9 (alice), `rl:fw:{search:10000000-0000-0000-0000-000000000002}` TTL=10 (bob), плюс службові ключі `…:exp`. Через 11 с ключів немає, alice → 200.

**Failure mode (EV-REDIS-02).**

| Випадок | search | `/api/incidents` | `/health` | traceId → журнал |
|---|---|---|---|---|
| Redis працює (baseline) | 200, 48 мс | 200 | 200 | — |
| Redis зупинено під час роботи | 500, 5528 мс, безпечний Problem Details | 200 | 200 | `2629ce47913ae3090688011129e91e77` → `ExceptionHandlerMiddleware`, `RequestPath:/api/incidents/search` |
| Redis знову запущено | 200, 201 мс | 200 | 200 | — |
| Redis недоступний під час старту API | API стартує (`abortConnect=false`); search → 500, 5729 мс | 200 | 200 | `5ff308c9c9682782dd14ad971a862dd6` → те саме |
| Redis запущено після такого старту | 200, 274 мс | 200 | 200 | — |

Причина в журналі: `StackExchange.Redis.RedisConnectionException: The message timed out in the backlog … (5000ms) … SocketClosed … on 127.0.0.1:6379`; ~5,5 с відповіді — це таймаут клієнта 5000 мс. SpanId у журналі також збігається з другим сегментом traceId (`9f241531e0449a58`, `36ffb44842b9be6b`). Журнал (618 рядків): `Password=` — 0, `local-study-password` — 0, seed-пароль — 0 (EV-REDIS-03).

**Чому fail-closed.** Пошук відповідає безпечною 500 Problem Details, а не пропускає запити без ліміту. Fail-open знімав би обмеження саме тоді, коли його стан неможливо перевірити, і атакувальнику достатньо було б перевантажити чи зупинити Redis, щоб обійти ліміт. Відмова зачіпає лише один endpoint: автентифікація, читання й зміна інцидентів не залежать від Redis і працюють. Ціна — до ~5,5 с очікування й недоступність пошуку на час збою.

**Як проходить `dotnet test` (умова 1).** Тести запускаються з піднятим Redis і `Redis__Configuration` у середовищі тестового процесу; тестовий host використовує ту саму Redis-політику, тож тести пошуку (`Search_*`) проходять через Redis: `dotnet test SecureLab.sln -c Release` → 42/42. Testcontainers не додано (нова залежність, зайва для локального стенда). Без змінної в Development діє in-memory fallback із тією самою семантикою — тоді тести Redis не перевіряють; фінальний прогін виконано з Redis.

| Умова погодження | Де виконано |
|---|---|
| 1. Як проходить `dotnet test` | абзац вище |
| 2. Пакети в dependency audit | розділ 9.1 |
| 3. Дві відмови, статус, час, traceId, без connection string | таблиця failure mode, EV-REDIS-02/03 |
| 4. Вхід Alice окремо на 5080 і 5081 | EV-REDIS-01 |
| 5. Та сама семантика вікна, фактичні ключ і TTL | реалізація, ключі й TTL |
| 6. Residual risk (login limiter локальний, Redis без ACL/TLS) | розділ 10 |

### 8.7 Transport (етап 2, п. 6)

Профіль запуску — лише `http` (http://localhost:5080); у `Program.cs` немає `UseHttpsRedirection()` і `UseHsts()`. Локальний HTTP-профіль не доводить безпеку транспорту в production. `UseHsts()` за замовчуванням не додає `Strict-Transport-Security` для loopback (`HstsOptions.ExcludedHosts`), тож відсутність HSTS на localhost не є дефектом. Реальний deployment, TLS termination і HSTS на production host не тестувалися — residual risk. Auth- і antiforgery-cookie у Production мають SecurePolicy Always.

### 8.8 Журнал і audit trail (етап 3, п. 4)

Sink — console logger API; журнал сесії записано через `Tee-Object` у `../lr06-logs/api.log` поза репозиторієм, після перевірки файл видалено.

Сценарії: (1) успішний вхід alice; (2) невдалий вхід alice з хибним паролем; (3) alice (Reporter) → `POST /api/incidents/a441dd3e-0710-411c-a398-700aadb9bd4c/triage` → 403, статус лишився New; (4) `GET /api/incidents?status=Unknown` → 400; (5) morgan (Analyst) → той самий triage → 204, New → Triaged; (6) Production, недосяжна БД → `POST /api/auth/login` → 500.

Пошук у журналі (422 рядки), кількість збігів (EV-LOG-01): seed password 0; `NotARealPassword1!` 0; `Wrong-Pass-123` 0; `cookie:|set-cookie` 0; `.AspNetCore.Identity.Application` 0; `X-CSRF-TOKEN` 0. Межа висновку — лише ці шість сценаріїв і цей sink.

Audit trail канонічного привілейованого переходу `Incident.Status` (EV-AUDIT-01):

- відмова: `authorization.denied subject=10000000-0000-0000-0000-000000000001 action=incident.triage resource=a441dd3e-0710-411c-a398-700aadb9bd4c result=denied occurredAtUtc=2026-11-07T20:38:45.8525367+00:00 traceId=00-aa232c42…`
- успіх (додано в ЛР 6, коміт `8e5cd08`): `authorization.allowed subject=10000000-0000-0000-0000-000000000003 action=incident.triage resource=a441dd3e-0710-411c-a398-700aadb9bd4c result=success occurredAtUtc=2026-11-07T20:41:35.7432545+00:00 traceId=00-a66f1dcd…`; паралельно запис в `incident_status_history` (changed_by_user_id, old_status, new_status, created_at_utc).

Мінімізація даних: події login містять лише тип, результат і trace — без userName і пароля (введене ім'я могло б містити помилково введений пароль); audit-події містять Guid суб'єкта, а не ім'я чи email; EF Core маскує значення SQL-параметрів (`'?'`). Log injection: structured logging із шаблонами (`{EventType}`, `{SubjectId}` …), недовірений текст не конкатенується в повідомлення. Diagnostic log відрізняється від audit event: перший — для налагодження (винятки, SQL), другий — фіксує, хто що зробив із ресурсом і з яким результатом.

## 9. Dependency and secret audit

### 9.1 Dependency audit (етап 3, п. 1–2)

Команди (SDK 10.0.302, 2026-11-07 і після додавання Redis 2026-11-08):
`dotnet restore SecureLab.sln --locked-mode` — без NU1901–NU1904;
`dotnet package list --vulnerable --include-transitive` — код завершення 0; для `SecureLab.Api` і `SecureLab.Api.Tests` джерело `https://api.nuget.org/v3/index.json` не повідомило про відомі advisories (direct і transitive). Оновлень не виконувалося, придушень (`NuGetAuditSuppress`, `WarningsNotAsErrors`) немає.

Нові залежності advanced variant (`dotnet add src/SecureLab.Api package RedisRateLimiting.AspNetCore`, `dotnet nuget why src/SecureLab.Api StackExchange.Redis`):

| Package | Version | Direct / transitive | Advisory | Сумісність із net10.0 | Рішення і причина |
|---|---|---|---|---|---|
| RedisRateLimiting.AspNetCore | 1.2.1 | direct | немає | пакет таргетує net7.0/net8.0; net10.0 використовує net8.0-збірку (сумісність вперед); build і 42 тести проходять | прийнято: інтегрується в наявний `AddRateLimiter` як ще одна політика, без власної реалізації лічильника |
| RedisRateLimiting | 1.2.1 | transitive ← RedisRateLimiting.AspNetCore | немає | те саме | прийнято: `RedisRateLimitPartition`, fixed-window на Lua-скриптах Redis (атомарний інкремент + TTL) |
| StackExchange.Redis | 2.8.0 | transitive ← RedisRateLimiting | немає | так | прийнято: стандартний .NET-клієнт Redis; `abortConnect=false` дає змогу стартувати без Redis |
| Pipelines.Sockets.Unofficial | 2.2.8 | transitive ← StackExchange.Redis | немає | так | прийнято як частина StackExchange.Redis |

`packages.lock.json` обох проєктів оновлено й закомічено разом із `.csproj` (`d05df4b`). Межа висновку: лише відомі на дату перевірки advisories цього джерела; reachability, невідомі вразливості й вразливості власного коду не оцінювалися — відсутність advisory не доводить безпеку. Офіційної збірки під net10.0 у RedisRateLimiting немає, бібліотека стороння — при оновленнях .NET її сумісність треба перевіряти окремо.

### 9.2 Secret/configuration review (етап 1, п. 3; етап 3, п. 3)

Команди (PowerShell, 2026-11-07, гілка `lab/6-hardening-review`, commit `769fcde`):

- `git ls-files '*appsettings*.json' '*.env*' '*compose*.yml' '*compose*.yaml' '*.config'` → `infra/.env.example`, `infra/compose.yaml`, `src/SecureLab.Api/appsettings.Development.json`, `src/SecureLab.Api/appsettings.json`;
- `git check-ignore -v infra/.env appsettings.Local.json` → обидва ігноруються (`.gitignore:15 .env`, `.gitignore:18 appsettings.Local.json`);
- `git --no-pager grep -n -I -i -E "password|passwd|secret|api.?key" -- .` → 77 matches;
- систематичний пошук за форматами справжніх секретів у всіх 77 tracked files (`git ls-files`, робоче дерево чисте): `git --no-pager grep -n -I -i -E "Password=|AccountKey=|ApiKey=|BEGIN (RSA |OPENSSH |EC )?PRIVATE KEY|Bearer [A-Za-z0-9._-]{20,}" -- .` → 2 matches (обидва study-only, нижче).

Межа: лише поточні tracked files; Git history, stash, інші clones і зовнішній CI не перевірялися — підозри попереднього витоку немає, повне сканування історії не є вимогою рівня. Порожній результат пошуку не доводить відсутність секретів в untracked файлах. `infra/compose.redis.yaml` (додано пізніше) секретів не містить — Redis без пароля, лише loopback.

| Path:line | Контекст | Рішення | Причина / межа |
|---|---|---|---|
| .gitignore:14 | коментар «Local configuration and secrets» | не секрет | текст коментаря |
| README.md:63 | згадка study-only значень `securelab / local-study-password` | accepted, study-only | README обмежує їх локальним стендом і забороняє повторне використання |
| README.md:138 | інструкція не комітити passwords/tokens | не секрет | документація |
| docs/git-workflow.md:124 | перелік типів ключів, які не можна комітити | не секрет | документація |
| docs/report-template.md:16, 38, 40, 52, 70, 75 | звіт ЛР 3: назви полів Password/PasswordHash, опис hasher і rate limit | не секрет | назви полів і текст, значень немає |
| infra/compose.yaml:9 | `POSTGRES_PASSWORD` локального контейнера, порт 127.0.0.1 | accepted, study-only | відкрите навчальне значення; не поширюється на інші БД і середовища |
| src/SecureLab.Api/appsettings.Development.json:3 | той самий study-only connection string, лише Development | accepted, study-only | поза Development не читається; реальний — через `ConnectionStrings__SecureLab` поза Git |
| src/SecureLab.Api/Data/SecureLabDesignTimeDbContextFactory.cs:10 | той самий study-only connection string для EF design-time | accepted, study-only | три входи узгоджені; видалення зламало б стенд |
| src/SecureLab.Api/Client/auth-lab.html:8, 13 | `<input type="password">` | не секрет | розмітка форми |
| src/SecureLab.Api/Client/auth-lab.js:11, 20 | очищення поля пароля після запиту | не секрет | безпечна практика |
| src/SecureLab.Api/Data/DbSeeder.cs:39, 42, 45, 49, 51, 53, 55, 184, 189, 191, 192, 210 | читання ключа `SeedUsers:Password` і передача в UserManager | не секрет | значення поза Git |
| src/SecureLab.Api/Data/Migrations/20260902062130_Lab03Identity.cs:52, 210; …Lab03Identity.Designer.cs:197; SecureLabDbContextModelSnapshot.cs:194 | колонка PasswordHash у згенерованій міграції | не секрет | схема без даних |
| src/SecureLab.Api/Scaffolding/Lab03Identity.cs:16, 58, 62, 70, 91, 97, 133, 136 | політика пароля, валідація DTO, виклики Identity | не секрет | код і назви полів |
| tests/SecureLab.Api.Tests/AuthenticationMechanicsTests.cs:10–12; AuthenticationTests.cs:14, 15, 17, 46, 61, 81, 95, 115, 159; IncidentEndpointTests.cs:14, 15, 17, 29; SearchMechanicsTests.cs:7, 8, 10, 15; CookieClient.cs:8, 14 | пароль читається з `SeedUsers__Password` | не секрет | значення поза Git |
| tests/SecureLab.Api.Tests/AuthenticationTests.cs:54, 191 | перелік імен полів, яких не має бути у відповіді | не секрет | негативна перевірка витоку |
| tests/SecureLab.Api.Tests/AuthenticationTests.cs:128, 133, 135, 213, 222 | навмисно хибний тестовий пароль (A-07, rate limit) | не секрет | вигадане значення |
| tests/SecureLab.Api.Tests/AuthenticationTests.cs:185, 203 | пароль нового тестового акаунта з Guid | не секрет | одноразове випадкове значення |
| tests/SecureLab.Api.Tests/packages.lock.json:208, 291 | пакет Microsoft.Extensions.Configuration.UserSecrets | не секрет | назва залежності |
| tests/http/lab-04-access.http:9, 23, 49 | пароль через `{{$processEnv SeedUsers__Password}}` | не секрет | значення з середовища |

Висновок: реальних credentials у tracked state не знайдено. Study-only значення `local-study-password` обмежене БД на 127.0.0.1; таке рішення не робить подібне tracked-значення прийнятним для іншої БД чи середовища. Якби реальний credential потрапив у Git, видалення з поточного файла чи останнього commit було б недостатнім: значення лишається в history, clones, cache, forks і logs, тому його треба відкликати або rotate.

## 10. Residual risks

- **Login-CSRF і account-creation CSRF:** login і register не захищені antiforgery-токеном (сеансу ще немає). Частково зменшують SameSite=Lax і JSON Content-Type (preflight). Тимчасово прийнято (розділ 5).
- **XSS на власному origin** отримав би antiforgery-токен так само, як helper; захист — safe DOM і CSP, а не antiforgery.
- **Development CORS:** `http://localhost:4173` може читати GET із credentials (зокрема видачу токена), але не може надіслати PUT/DELETE чи `X-CSRF-TOKEN`; цей origin фактично довірений, у Production policy відсутня.
- **Login limiter локальний для екземпляра:** при кількох екземплярах API ліміт множиться на їх кількість; ключ за IP — користувачі за спільним NAT ділять ліміт.
- **Redis без ACL/TLS і без пароля** допустимий лише на локальному стенді (порт лише 127.0.0.1); у реальному розгортанні потрібні автентифікація, TLS і мережеве обмеження.
- **Збій Redis:** пошук недоступний (fail-closed), кожен запит чекає ~5 с до таймауту; можна зменшити `connectTimeout`/`syncTimeout`, але принцип лишається.
- **Diagnostic log при збої Redis** містить ім'я хоста (`clientName`) і статистику пулу потоків — клієнту не повертається, але журнал має бути доступний лише оператору.
- **RedisRateLimiting** не має офіційної збірки під net10.0; стороння бібліотека — повторна перевірка при оновленнях.
- **Transport:** HTTPS, HSTS і reverse proxy не перевірялися.
- **Logout-подія без subject**; logout не відкликає раніше скопійовані cookie.
- **Advisory absence** не доводить відсутність вразливостей у залежностях.

## 11. Conclusion

Після ЛР 6 усі browser-accessible cookie-authenticated змінювальні маршрути вимагають валідної пари antiforgery-токенів, що доведено автоматизованим REG-CSRF-01 із перевіркою незмінності стану та позитивного сценарію. Помилки в Production-like профілі безпечні й зіставляються з журналом через traceId, security headers присутні на всіх класах відповідей, CSP не ламає клієнт, журнали не містять credentials, привілейований перехід статусу має audit trail для дозволу й відмови. Три власні findings виправлено з retest і positive regression, пріоритизацію обґрунтовано. Погоджений advanced variant робить ліміт пошуку спільним для екземплярів API і зберігає захист при збої Redis (fail-closed). Залишкові ризики (login-CSRF, локальний login limiter, Redis без ACL/TLS, неперевірений транспорт) описано чесно з compensating controls.

## 12. Evidence appendix

Усі докази очищені: значення паролів, cookie, токенів і повних connection string приховано або не потрапили в кадр. Пароль seed вводився через `Read-Host -AsSecureString`.

| ID | Що доводить | Як повторити | Результат |
|---|---|---|---|
| EV-START-01 | стартовий стан | `git status`, `git log -1 --oneline`, `git rev-parse HEAD`; `dotnet build`; `dotnet test`; `/health` | чисте дерево, `769fcde`, 0 warnings, тести PASS, `{"status":"ready"}` |
| EV-SEC-01 | tracked configuration і ignore | `git ls-files …`, `git check-ignore -v …` | 4 tracked config, `.env` і `appsettings.Local.json` ігноруються |
| EV-SEC-02 | пошук секретів | два `git grep` (розділ 9.2) | 77 і 2 збіги, класифіковано |
| EV-PROD-01 | Production без Dev-конфігурації | Production-like запуск; `curl.exe -sS -D - http://localhost:5080/openapi/v1.json`, `…/scalar/v1` | `Hosting environment: Production`; 404 Problem Details; 200 text/html клієнта (SPA fallback) |
| EV-PROD-02 | reset заборонено в Production | той самий запуск із `-- --reset-database` | `InvalidOperationException: Reset даних дозволено лише в явно налаштованому Development environment` |
| EV-ERR-01 | безпечна 500 + correlation | Production, `ConnectionStrings__SecureLab` на порт 54399, `tests/http/lab-06-unexpected-error.http` | 500 application/problem+json, traceId `00-62c7a596dd366a718c7a9ce008bb2928-f3afbfe74a7b82b8-00`; журнал `ExceptionHandlerMiddleware[1]`, `TraceId:62c7a596…`, `SpanId:f3afbfe74a7b82b8`, NpgsqlException (connection refused); без пароля й connection string |
| EV-RESTORE-01 | стенд відновлено | Development; `/health`, вхід alice, `GET /` | ready, 204, список завантажено |
| EV-HDR-01 | headers 200/400/404 | DevTools Network на трьох запитах (розділ 8.3), `curl.exe -s -o NUL -D - http://localhost:5080/` | CSP, nosniff, no-referrer присутні, по одному разу |
| EV-HDR-02 | F-01 до/після | EV-ERR-01 до і після `fac88ef` | без headers → з headers |
| EV-COOKIE-01 | cookie flags | DevTools → Application → Cookies | auth: HttpOnly, Lax; antiforgery: HttpOnly, Strict |
| EV-CSP-01 | CSP не ламає клієнт; XSS marker як текст | Console на `/`, `/auth-lab.html`, `/browser-lab.html`, прочитати інцидент 0001 | No issues; `<img src=x onerror=…>` показано як текст |
| EV-CORS-01 | REG-CORS-01 | `py -3 -m http.server 4173/4174 --directory demonstrations/cors-probe`; fetch `/health`; `curl.exe -H "Origin: …"` | 4173: 200 + ACAO; 4174: blocked by CORS, `GET … 200 (OK)` в Network; curl 4174 без `Access-Control-*` |
| EV-CSRF-01 | F-02 на `v0.5.0` | `git switch --detach v0.5.0`; PUT без токена з Console | 204, стан змінився |
| EV-CSRF-02 | REG-CSRF-01 вручну і автомат | розділ 6; `dotnet test … --filter RegCsrf01` | 400/true, 200/true, 204/true; Passed 1 |
| EV-CSRF-03 | helper у формах | Network на `auth-lab` і `browser-lab` (з F5) | `token` 200 → `incidents` 201, у запиті header `X-Csrf-Token` (значення приховано); перша видача — `Set-Cookie SecureLab.Antiforgery`, `Cache-Control: no-cache, no-store` |
| EV-CSRF-04 | logout через helper | `auth-lab` → Вийти → Мій профіль | Logout 204, Profile 401 |
| EV-F03-01 | F-03 на `v0.5.0` | `curl.exe -i -X POST http://localhost:5080/api/auth/logout` | 204 + `Auth event logout: result success` |
| EV-F03-02 | F-03 retest | той самий curl на виправленому коді | 401 Problem Details |
| EV-RL-01 | login limiter | 31 запит `nobody-ratelimit` з Console; вхід alice через 11 с | 30×401, 429; 204 |
| EV-RL-02 | search limiter, 2 partitions | 11 пошуків alice; bob у вікні InPrivate; alice через 11 с | 10×200 + 429; 200; 200 |
| EV-DEP-01 | dependency audit | розділ 9.1 | без NU19xx, 0 vulnerable, exit 0 |
| EV-LOG-01 | журнал без чутливих даних | розділ 8.8 | 422 рядки, усі пошуки 0 |
| EV-AUDIT-01 | audit triage | розділ 8.8 | denied (alice 403, статус New) і allowed (morgan 204, Triaged) |
| EV-SQLI-01 | S-02 вручну | Console: q=`' OR '1'='1`, sortBy з `;`, q=`лист` | 200/0, 400, 200/1 |
| EV-TEST-01 | автоматизований pack | `dotnet test SecureLab.sln -c Release` з Redis | 42/42 |
| EV-ADV-00 | погодження advanced variant | повідомлення в Moodle і відповідь викладача, 2026-11-08 | погоджено з шістьма умовами |
| EV-REDIS-00 | Redis піднято | `docker compose -f infra/compose.redis.yaml up -d --wait`; `… exec redis redis-cli ping` | Healthy, PONG |
| EV-REDIS-01 | спільний стан, ізоляція, ключі, TTL | розділ 8.6 | #11 → 429; bob 200; ключі `rl:fw:{search:<Guid>}`, TTL 9–10; через 11 с ключів немає |
| EV-REDIS-02 | failure mode | розділ 8.6 | 500 за 5528/5729 мс, інші маршрути 200, відновлення 200 |
| EV-REDIS-03 | зв'язок 5xx↔журнал, без секретів | `Select-String` за traceId і `Password=` | обидва traceId знайдено з `RequestPath:/api/incidents/search`, `RedisConnectionException`; 0 секретів |
| EV-GIT-01 | історія змін | `git log --oneline 769fcde..HEAD`, `git diff 769fcde..HEAD` | коміти розділу 4; diff без секретів і журналів |

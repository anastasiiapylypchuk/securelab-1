# SecureLab starter: трекер інцидентів

Це baseline starter для дисципліни «Прикладні технології програмування в
інформаційній безпеці», варіант **2-A**. Він містить один простий
трирівневий моноліт, локальний PostgreSQL, мінімальний Vanilla JavaScript
клієнт, відтворювані seed/reset і готовий `WebApplicationFactory` test harness.

Це стан системи **до ЛР 1**. Далі студент послідовно розвиває власний проєкт:
результат завершеної ЛР стає основою наступної. Якщо попередню роботу технічно
не завершено, її потрібно завершити або виправити перед переходом далі.

Starter навмисно не містить завершених рішень ЛР 1–6, автентифікації,
авторизації або навмисних уразливостей. Потрібні для конкретної роботи зміни
студент виконує у власному проєкті за методичними вказівками й лише у
дозволеному локальному середовищі.

## 1. Передумови

- .NET SDK `10.0.302` (зафіксовано у `global.json`);
- Docker із підтримкою `docker compose`;
- Git;
- вільні локальні порти `5080` і `54329`.

Перевірте:

```bash
dotnet --version
docker --version
docker compose version
```

## 2. Перший запуск

У корені starter виконайте:

```bash
docker compose --env-file infra/.env.example -f infra/compose.yaml up -d --wait
dotnet tool restore
dotnet restore SecureLab.sln
dotnet run --project src/SecureLab.Api
```

Під час першого Development-запуску API застосує готову EF Core migration і
додасть фіксовані навчальні дані. Відкрийте:

- browser client: <http://localhost:5080/>;
- health/readiness: <http://localhost:5080/health>;
- інтерактивний OpenAPI: <http://localhost:5080/scalar/v1>;
- OpenAPI JSON: <http://localhost:5080/openapi/v1.json>.

Зупиніть API через `Ctrl+C`. Контейнер БД зупиняється командою:

```bash
docker compose --env-file infra/.env.example -f infra/compose.yaml down
```

## 3. Відомий початковий стан

Seed містить Alice, Bob, Morgan (Analyst) та Admin, три інциденти, два
публічні коментарі й одну зміну статусу. UUID не випадкові: їх можна
використовувати у `.http`-сценаріях і тестах.

Локальні значення `securelab / local-study-password` є лише відкритими
навчальними credentials для БД, прив'язаної до `127.0.0.1`. Це не секрет і
його заборонено повторно використовувати для іншої БД чи середовища. Реальний
connection string передавайте поза Git через `ConnectionStrings__SecureLab`.

Щоб застосувати наявні migrations, **очистити лише відомі навчальні таблиці**
локальної БД і повернути seed до відомого стану:

```bash
dotnet run --project src/SecureLab.Api -- --reset-database
```

Команда навмисно відмовляється працювати поза явно налаштованим Development
environment. Вона знищує поточні локальні навчальні дані у відомих таблицях
БД `securelab`, але не видаляє саму БД або її схему.

## 4. Перевірка

Коли PostgreSQL уже працює:

```bash
dotnet build src/SecureLab.Api/SecureLab.Api.csproj --configuration Release
dotnet test tests/SecureLab.Api.Tests/SecureLab.Api.Tests.csproj --configuration Release
```

На macOS/Linux або у Git Bash увесь сценарій підняття PostgreSQL і тестів
виконує одна команда:

```bash
bash scripts/test.sh
```

HTTP-сценарії для ручної перевірки розташовані у `tests/http/incidents.http`.
Вони охоплюють `200`, `400`, `404` та початковий `501` для точки розширення.

## 5. Завдання ЛР 1 у starter

Працюючий близький приклад — фільтр інцидентів за `status` через browser → API
→ EF Core → PostgreSQL → JSON → безпечні DOM sinks. Обмежена точка зміни —
`GET /api/incidents/severity-summary`, який у baseline повертає `501`.

Під час ЛР 1 студент реалізує підсумок кількості інцидентів за severity,
викликає endpoint із клієнта, безпечно відображає результат, додає
відтворюваний HTTP-сценарій або адаптує інтеграційний тест і доповнює
`docs/architecture.md`. Зміна схеми БД для мінімального маршруту не потрібна.

## 6. Структура

```text
src/SecureLab.Api/
  Presentation/   endpoints і зовнішні response contracts
  Application/    сценарії застосунку
  Data/           DbContext, entities, migration, seed/reset
  Client/         HTML/CSS/Vanilla JavaScript
tests/
  SecureLab.Api.Tests/   інтеграційні й security regression приклади
  http/                  ручні HTTP-сценарії
infra/                   локальний PostgreSQL
docs/                    карта архітектури, варіант, матриця доступу, звіт
```

Це не Clean/Onion Architecture, DDD, мікросервіси або вимога TDD. Каталоги
позначають відповідальність коду в одному server project.

## 7. Типові проблеми запуску

| Ознака | Перевірка |
|---|---|
| `connection refused` до PostgreSQL | `docker compose ... ps`, порт `54329`, стан healthcheck |
| SDK не знайдено | `dotnet --version` має повернути `10.0.302` у цій директорії |
| порт API зайнятий | зупиніть інший процес на `5080` або задайте `ASPNETCORE_URLS` |
| migration не застосовується | перевірте `ASPNETCORE_ENVIRONMENT=Development` і connection string |
| змінили credentials у compose | узгоджено перевизначте `ConnectionStrings__SecureLab`; не записуйте реальне значення до Git |

Перед commit перегляньте `git status`, `git diff --staged` і переконайтеся, що
до Git не потрапили `.env`, cookies, tokens, реальні passwords, dumps або logs.

## ЛР 6: hardening і security review — запуск і перевірка

Звіт: `docs/security-review.md`, модель загроз: `docs/threat-model.md`, знахідки: `docs/findings/`.

### Prerequisites

- .NET SDK 10.0.x (див. `global.json`), Docker Desktop, PowerShell 5.1+ або Bash.
- Локальний навчальний пароль seed-акаунтів — лише у змінній середовища `SeedUsers__Password` (не в Git).
- Redis потрібен для limiter пошуку: адреса лише у змінній `Redis__Configuration`.
  У Development без неї діє in-memory fallback; у Production без неї API не стартує.

### Запуск (PowerShell)

```powershell
$seedSecret = Read-Host 'Локальний пароль' -AsSecureString
$env:SeedUsers__Password = [Net.NetworkCredential]::new('', $seedSecret).Password
Remove-Variable seedSecret
$env:Redis__Configuration = "127.0.0.1:6379,abortConnect=false"

docker compose --env-file infra/.env.example -f infra/compose.yaml up -d --wait
docker compose -f infra/compose.redis.yaml up -d --wait
dotnet restore SecureLab.sln --locked-mode
dotnet run --project src/SecureLab.Api -- --reset-database
dotnet run --project src/SecureLab.Api
```

Bash/zsh: замість перших трьох рядків —
`read -rsp 'Локальний пароль: ' SeedUsers__Password; export SeedUsers__Password; printf '\n'`,
змінні задавати через `export`.

### Тести

```powershell
dotnet test SecureLab.sln -c Release
dotnet test SecureLab.sln -c Release --filter RegCsrf01
```

Тести, що змінюють стан, отримують antiforgery-токен через `GET /api/antiforgery/token`
і header `X-CSRF-TOKEN` (`AntiforgeryTestExtensions.UseAntiforgeryTokenAsync`).

### Production-like профіль (PowerShell, окреме вікно)

```powershell
$db = "Host=127.0.0.1;Port=54329;Database=securelab;Username=securelab"
$db = "$db;Password=local-study-password;Include Error Detail=false"
$env:ASPNETCORE_ENVIRONMENT = "Production"
$env:ASPNETCORE_URLS = "http://localhost:5080"
$env:ConnectionStrings__SecureLab = $db
$env:Redis__Configuration = "127.0.0.1:6379,abortConnect=false"
dotnet run --project src/SecureLab.Api --no-launch-profile -c Release
```

`local-study-password` — відкрите навчальне значення лише для локальної БД на 127.0.0.1;
не використовуйте його повторно. Reset у Production заборонено.
Контрольована помилка: змінити порт у `$db` на 54399 і виконати `tests/http/lab-06-unexpected-error.http`.

### Клієнт

`http://localhost:5080/auth-lab.html` (вхід, створення, вихід), `http://localhost:5080/browser-lab.html`.
Змінювальні запити клієнт надсилає через `Client/csrf.js` (`SecureLabCsrf.mutate`).

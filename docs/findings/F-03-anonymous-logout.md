# F-03. Logout приймав анонімні запити й записував хибну audit-подію

**Статус:** Fixed
**Актив:** достовірність журналу автентифікації; цілісність authentication-контракту cookie-периметра
**Компонент:** POST /api/auth/logout (`src/SecureLab.Api/Scaffolding/Lab03Identity.cs`)
**Пріоритет:** P3

## Передумови і межі огляду

Commit `v0.5.0` (`769fcde`), Development, http://localhost:5080; клієнт без жодної cookie (curl.exe).
Дефект знайдено власним аналізом під час складання таблиці периметра змінювальних маршрутів (SC-05):
усі інші cookie-маршрути мали `RequireAuthorization`, logout — ні. Методика цієї перевірки прямо не
називає (поза checklist).

## Відтворення

1. `git switch --detach v0.5.0`, `dotnet run --project src/SecureLab.Api`.
2. `curl.exe -i -X POST http://localhost:5080/api/auth/logout` без cookie.
   Очікувано: 401, бо сеансу немає. Фактично: `204 No Content` і `Set-Cookie` на видалення cookie.
3. Журнал API: `Auth event logout: result success, trace 0HNPT4KTUHE80:00000001` — подія «успішного
   виходу», якого не було.

## Вплив і ймовірність

**Статус перевірки:** спостережено локально.

Прямого доступу до даних немає. Проте audit trail фіксує неіснуючі «успішні logout»: будь-хто може
засмічувати журнал хибними подіями, і розслідування за ним стає менш надійним. Маршрут, що змінює стан
сеансу, був поза authentication-контрактом периметра. Impact Low, likelihood High (анонімний доступ,
без передумов) → P3.

## Першопричина

Реєстрація `app.MapPost("/api/auth/logout", ...)` не мала `.RequireAuthorization()`, тому handler
виконувався для анонімного principal і безумовно логував `result success`.

## Виправлення

`.RequireAuthorization().AddEndpointFilter<AntiforgeryFilter>()` на logout: анонімний запит зупиняється
на authorization (401) до handler і до запису події; автентифікований потребує валідного antiforgery-токена.
Fixed commit `3bfd5f8`.

## Retest

На виправленому коді `curl.exe -i -X POST http://localhost:5080/api/auth/logout` без cookie →
`401 Unauthorized`, `application/problem+json`, з security headers; хибної події logout у журналі немає.

## Positive regression

Автентифікований logout через helper на `auth-lab.html` → `Logout: 204`, потім «Мій профіль» →
`Profile: 401`. Автотест `AuthenticationTests.A06_Logout_ThenMe_Returns401` пройшов (у складі 42/42).

## Залишковий ризик

Подія logout не містить ідентифікатора суб'єкта (лише тип, результат, trace) — для розслідування
доводиться зіставляти trace з іншими записами. Logout не відкликає раніше скопійовані cookie
(сеанс stateless до SecurityStamp).

## Доказ

EV-F03-01 (curl 204 і журнал на `v0.5.0`), EV-F03-02 (curl 401 на виправленому коді), EV-CSRF-04,
тест `A06_Logout_ThenMe_Returns401`. Значення cookie не збережено.

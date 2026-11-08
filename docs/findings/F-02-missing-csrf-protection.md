# F-02. Cookie-authenticated змінювальні маршрути не мали antiforgery-перевірки

**Статус:** Fixed
**Актив:** цілісність Incident (створення, зміна, видалення, перехід статусу) і сеанс користувача
**Компонент:** POST /api/incidents, PUT /api/incidents/{id}, POST /api/incidents/{id}/triage, DELETE /api/incidents/{id}, POST /api/auth/logout
**Пріоритет:** P1

## Передумови і межі огляду

Commit `v0.5.0` (`769fcde`), Development, http://localhost:5080. Акаунт alice (Reporter);
seed-інцидент alice `20000000-0000-0000-0000-000000000001`. Reset:
`dotnet run --project src/SecureLab.Api -- --reset-database`.
Поза межами: реальна атака зі стороннього домену, HTTPS.

## Відтворення

1. `git switch --detach v0.5.0`, `dotnet run --project src/SecureLab.Api`.
2. `/auth-lab.html` → вхід alice → `Login: 204` (у браузері є auth cookie).
3. DevTools Console: `GET /api/incidents/{id}` → запам'ятати description.
4. `PUT /api/incidents/{id}` з новим description, Content-Type JSON, **без** будь-якого anti-CSRF header.
   Очікувано: відмова 4xx, опис не змінено. Фактично: `204`, повторний GET показує змінений опис
   (`v0.5.0 PUT без токена: 204 | стан змінився: true`).

## Вплив і ймовірність

**Статус перевірки:** спостережено локально.

Сервер змінював стан лише за наявності authentication cookie, яку браузер додає автоматично.
Сторінка того самого site (інший порт localhost, піддомен) або маршрут, що колись прийме
form-формат, могли б змусити браузер жертви змінити чи видалити інцидент, а для Analyst — виконати triage.
SameSite=Lax і JSON Content-Type (preflight) частково обмежують сценарій, але не є явною серверною
перевіркою. Impact High (несанкціонована зміна даних), likelihood Medium (потрібен активний сеанс
і відвідування підконтрольної сторінки) → P1.

## Першопричина

У фіксованому cookie-профілі не було стандартного ASP.NET Core antiforgery-механізму: жоден змінювальний
endpoint не викликав `IAntiforgery.ValidateRequestAsync`, клієнт не мав request token.

## Виправлення

- `Program.cs`: `AddAntiforgery` (HeaderName `X-CSRF-TOKEN`, cookie `SecureLab.Antiforgery`,
  SecurePolicy Always у Production); маршрут `GET /api/antiforgery/token` (RequireAuthorization) → `GetAndStoreTokens`.
- `Security/AntiforgeryFilter.cs`: `ValidateRequestAsync` до handler; `AntiforgeryValidationException` →
  400 Problem Details `Antiforgery token is missing or invalid.`; інші винятки не маскуються.
- Фільтр підключено до кожного маршруту периметра SC-01…SC-05 (DELETE — явно).
- `Client/csrf.js`: lazy-токен лише в пам'яті сторінки, скидання після login/logout і `pageshow`,
  лише same-origin, без автоматичного повтору; `auth-lab.js` і `browser-lab.js` надсилають mutation через `SecureLabCsrf.mutate`.
- Тести, що змінюють стан, отримують токен через `AntiforgeryTestExtensions.UseAntiforgeryTokenAsync`.

Fixed commit `3bfd5f8`.

## Retest

REG-CSRF-01 на виправленому коді (alice, той самий інцидент):
PUT без токена → `400`, title `Antiforgery token is missing or invalid.`, опис не змінився;
PUT з невалідним токеном → `400`, опис не змінився.

## Positive regression

Той самий клієнт: `GET /api/antiforgery/token` → 200 → PUT з валідною парою → `204`, опис змінено.
Форма створення в `auth-lab` → `token` 200 → `incidents` 201 (header `X-Csrf-Token` у запиті);
`browser-lab` після F5 знову отримує токен → 201; logout через helper → 204, потім `/api/me` → 401.
`dotnet test SecureLab.sln -c Release` → 42/42.

## Залишковий ризик

JavaScript, що виконається на власному origin (XSS), може отримати токен так само, як helper —
від цього захищають safe DOM і CSP, а не antiforgery. Login і register не захищені токеном
(сеансу ще немає) — login-CSRF прийнято як residual risk. Development CORS policy дозволяє
`http://localhost:4173` читати GET із credentials (зокрема видачу токена), але не дозволяє PUT/DELETE
і header `X-CSRF-TOKEN`, тож використати токен цей origin не може; у Production policy відсутня.

## Доказ

`CsrfRegressionTests.RegCsrf01_PutWithoutValidToken_IsRejected_StateUnchanged_ThenValidPairSucceeds`,
команда `dotnet test SecureLab.sln -c Release --filter RegCsrf01` → Passed 1; EV-CSRF-01…04.
Значення токенів і cookie не збережено.

# F-01. Security headers зникають на неочікуваній помилці (500)

**Статус:** Fixed
**Актив:** захисні властивості браузера (CSP, nosniff, Referrer-Policy) на всіх відповідях API
**Компонент:** спільний middleware заголовків у `src/SecureLab.Api/Program.cs` разом з `UseExceptionHandler`
**Пріоритет:** P2

## Передумови і межі огляду

Commit `769fcde` (review-start) з гілки `lab/6-hardening-review`. Production-like запуск:
`ASPNETCORE_ENVIRONMENT=Production`, `ASPNETCORE_URLS=http://localhost:5080`, `--no-launch-profile`,
`ConnectionStrings__SecureLab` вказує на навмисно недосяжний порт `127.0.0.1:54399`.
Запит — `tests/http/lab-06-unexpected-error.http` (POST /api/auth/login з вигаданим паролем).
Поза межами: відповіді, сформовані reverse proxy; HTTPS.

## Відтворення

1. Development: `GET /` → 200, `GET /api/incidents/20000000-0000-0000-0000-000000000001` (alice) → 200,
   `GET /api/incidents?status=Unknown` → 400, `GET /api/incidents/99999999-9999-9999-9999-999999999999` → 404.
   Усі відповіді містять `Content-Security-Policy`, `X-Content-Type-Options: nosniff`, `Referrer-Policy: no-referrer`.
2. Production-like, недосяжна БД: виконати `lab-06-unexpected-error.http`.
   Очікувано: ті самі три заголовки. Фактично: `500 application/problem+json` з безпечним тілом
   і traceId `00-766c23666f95dfca2a8eae3b20efa3d6-cecf6f4a24eca7d9-00`, але **без жодного** з трьох заголовків.

## Вплив і ймовірність

**Статус перевірки:** спостережено локально.

Тіло 500 уже безпечне (лише type, title, status, traceId), тому прямого витоку немає. Проте відповіді
помилок лишаються без defense in depth: без nosniff, без CSP і з довільним Referer. Політика заголовків
непослідовна між класами відповідей. Сценарій доступний будь-кому, хто спричинить необроблену помилку
(збій БД, інфраструктури): impact Low–Medium, likelihood High → P2.

## Першопричина

Блок `app.Use(...)` встановлював заголовки **до** `await next(context)`. Коли далі виникає виняток,
`ExceptionHandlerMiddleware` очищає відповідь (разом із вже встановленими заголовками) і формує нову
500, у яку наш middleware більше не втручається.

## Виправлення

Заголовки встановлюються в `context.Response.OnStarting(...)` — безпосередньо перед відправленням
відповіді, тобто вже після того, як exception handler її переписав. Виняток для `/scalar` у Development
збережено. `Headers.Append("Referrer-Policy", …)` замінено на присвоєння, щоб не було дублів.
Fixed commit `fac88ef` («F-01: keep security headers on exception handler responses»), `Program.cs`.

## Retest

Той самий запит у тому самому Production-like профілі → `500 application/problem+json`, traceId
`00-6e8be80b1527355997a9b903bb84557a-2b22a6794db73dc3-00`, тепер із `X-Content-Type-Options: nosniff`,
`Referrer-Policy: no-referrer`, `Content-Security-Policy: default-src 'self'; … frame-ancestors 'none'`.
Тіло не змінилося: без stack trace, SQL, шляхів і connection string. (Запуск без `-c Release`, бо
попередній Release-процес утримував файл; середовище Production підтверджено рядком `Hosting environment: Production`.)

## Positive regression

`curl.exe -s -o NUL -D - http://localhost:5080/` → `200 text/html`, кожен із трьох заголовків рівно один раз.
Браузерний клієнт (`/`, `/auth-lab.html`, `/browser-lab.html`) працює, Console без порушень CSP.
`dotnet test SecureLab.sln -c Release` → 42/42.

## Залишковий ризик

Відповіді, які формує щось поза pipeline ASP.NET Core (reverse proxy, Kestrel до middleware), не перевірені.
Заголовки — defense in depth і не замінюють safe DOM, валідацію чи авторизацію. Ця finding підказана
методикою (етап 2, п. 1), тому не зараховується як «поза checklist».

## Доказ

EV-HDR-01 (200/400/404 у Development), EV-HDR-02 (500 до/після), `tests/http/lab-06-unexpected-error.http`,
`git show fac88ef`. Значення cookie, токенів і паролів не збережено.

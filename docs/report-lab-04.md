# Звіт ЛР04

## Контекст і межа виконання
- Рівень: відмінний («Відмінно»). Виконано вимоги достатнього, доброго та відмінного рівнів (рівні накопичувальні).
- Власний baseline 2-A, base tag v0.3.0, hash: ⟨вивід `git rev-parse "v0.3.0^{commit}"`⟩.
- Головна action: details/read (`GET /api/incidents/{id}`). Додатково: list, search, severity-summary, update, delete, triage, child `GET /api/incident-comments/{id}`.
- Політика для чужого головного ресурсу: **404** (обґрунтування в docs/access-matrix.md).
- ЛР 3 після тегу не виправлялась, тег v0.3.0 не пересувався.

## Матриця і server-side рішення
Матриця: docs/access-matrix.md.

- **Query scoping:** умова `isAnalyst || OwnerUserId == currentUserId` стоїть у самому запиті для details, list, search (до сортування й `Take(50)`), severity-summary (до `GroupBy`) та child-коментаря (через `comment.Incident.OwnerUserId`). Рядки в пам'яті не фільтруються.
- **Resource-based handler:** `IncidentAuthorizationHandler` з операціями Read, Update, Delete, Triage (файл `Application/Incidents/IncidentAuthorization.cs`). Mutating endpoint-и завантажують entity, викликають `IAuthorizationService` і змінюють стан лише після дозволу.
- **DTO:** `UpdateIncidentRequest` містить лише `Title` і `Description`. `OwnerUserId`, status, severity та роль із тіла не приймаються. Id користувача й роль беруться лише з `HttpContext.User`.
- **Відмови:** усі гілки 404 використовують один helper `IncidentNotFound()` без id у `detail`.

## Вразливий стан і PoC
Vulnerable commit: `8bda51159455328739ce9ebe985c920650d5b5b2` (PoC-сценарій `tests/http/lab-04-access.http`). Початок звіту: `3886dedbfe947b43bc7e641944c0f156858495ae`.

Дефект: `GetDetailsAsync` шукав інцидент лише за id і не порівнював його з principal, а маршрут не вимагав автентифікації.

| Запит | Очікувано за матрицею | Фактично (до виправлення) |
|---|---|---|
| Alice → власний інцидент | 200 | login 204, read 200 |
| Alice → інцидент Bob | 404 | read 200 з даними Bob («Невідома спроба входу», «Боб Мельник»): IDOR/BOLA |
| Анонім → інцидент Bob (`curl`) | 401 | 200 з повним JSON і коментарем |

Окремо: маршрут не вимагав автентифікації, тож крім горизонтального підвищення привілеїв був доступний анонімно. Також `search` був доступний анонімно, а `severity-summary` рахував усі інциденти. У виводах немає cookie та пароля.

## Виправлення та retest
Fixed commit: ⟨hash commit-а, на який поставлено тег v0.4.0⟩.

Ті самі запити після виправлення:

| Запит | Фактично (після) |
|---|---|
| Alice → власний інцидент | read_status=200 |
| Alice → інцидент Bob | read_status=404, `{"title": "Інцидент не знайдено", "status": 404, "traceId": ...}` |
| Morgan (Analyst) → інцидент Alice | read_status=200 |
| Анонім → інцидент Bob | 401 Unauthorized |

- **Mutation:** після відмови Bob (404) і Analyst (403) стан інциденту незмінний (порівняння відповіді GET до й після).
- **Read:** відповідь details не містить `ownerUserId` та `email`.
- **Узгодженість 404:** відповіді для чужого й неіснуючого id збігаються за status, Content-Type, `title` і `status` у тілі; відрізняється лише `traceId` (A-10).

## Доказова таблиця

| ID | Рівень | Сценарій | Передумови | Дія | Очікувано | Фактично | Доказ |
|---|---|---|---|---|---|---|---|
| A-01 | добрий | Анонімний доступ | немає authentication context | protected request | `401`, не HTML redirect | 401, без redirect | `GetDetails_Anonymous_Returns401`, `GetComment_Anonymous_Returns401` |
| A-02 | достатній, обов'язковий | Власний ресурс | Alice має власний seed resource | details; update власного | allow | 200, id збігається з seed id Alice; update 204 і зміна title | `GetDetails_AsOwner_ReturnsOwnIncident`, `Update_AsOwner_ChangesContent` |
| A-03 | достатній, обов'язковий | Чужий ресурс | Alice, Bob resource | details з підміненим id | `403` або `404`; state без змін | 404; дані Bob у відповіді відсутні | `GetDetails_AsOtherReporter_Returns404_SameAsUnknownId_AndLeaksNothing` |
| A-03R | достатній, entry-контракт ЛР 5 | Дозволений аналітичний read | Morgan (`Analyst`), ресурс Alice | `GET /api/incidents/{id}` | allow для аналізу; права довільної mutation немає | 200; update тим самим користувачем дає 403 | `GetDetails_AsAnalyst_ReadsOtherUsersIncident`, `Update_AsAnalyst_Returns403_AndDoesNotChangeIncident` |
| A-04 | добрий | Чужий ресурс, усі змінювальні дії | Alice, Bob resource | update і delete з підміненим id | deny, state без змін | 404, стан інциденту без змін | `Update_AsOtherReporter_Returns404_AndDoesNotChangeIncident`, `Delete_AsOtherReporter_Returns404_AndIncidentRemains` |
| A-05 | добрий | List | Alice | list | лише дозволена множина | Alice бачить свій інцидент і не бачить інцидент Bob; Analyst бачить усі | `GetList_AsReporter_ReturnsOnlyOwnIncidents`, `GetList_AsAnalyst_ReturnsAllIncidents` |
| A-06 | добрий | Вертикальне підвищення привілеїв | звичайний Reporter | triage | deny, status без змін | 403; статус лишається New | `Triage_AsOwnerReporter_Returns403_AndStatusUnchanged` |
| A-07 | добрий | Дозволена привілейована дія | Analyst, статус New | triage | allow | 204, статус Triaged; повторний triage: 409 | `Triage_AsAnalyst_MovesNewToTriaged`, `Triage_WhenAlreadyTriaged_Returns409` |
| A-08a | добрий, альтернатива A-08b | Overposting: контракт ігнорує невідоме поле | authenticated user; DTO не містить protected field | update з `ownerUserId`, `status`, `severity`, `role` | дозволений content змінюється, protected state ні | 204; змінився лише title; owner, status (New), severity (Low) без змін | `Update_WithForgedProtectedFields_IgnoresThem` |
| A-08b | добрий, альтернатива A-08a | Overposting: контракт відхиляє зайве поле | — | — | — | не виконувалось: обрано альтернативу A-08a | — |
| A-09 | добрий | Аудиторська подія | denied privileged request | знайти `authorization.denied` у виводі API | безпечна подія без секретів | подія містить subject, action=incident.triage, resource, result=denied, occurredAtUtc, traceId; traceId збігається з тілом відповіді 403 (`00-a6df256c19b7ad2ae100e86dcfa5754a-c0b78bb074f2b28f-00`); cookie, пароля, тіла запиту немає | скріншот консолі (403) і рядка з виводу API |
| A-10 | добрий, лише політика 404 | Нерозрізнюваність 404 | той самий authenticated client; id чужого й неіснуючого ресурсу | два однакові запити, змінено лише id | однакові status, Content-Type і тіло після вилучення `traceId` | status, Content-Type, `title`, `status` однакові; відрізняється лише `traceId` | `GetDetails_AsOtherReporter_Returns404_SameAsUnknownId_AndLeaksNothing` |
| A-11 | відмінний | Власні endpoint-и ЛР 1–2 | Alice; Morgan | `search` і `severity-summary` | результат обмежений дозволеною множиною | search: анонім 401, Reporter не знаходить інцидент Bob, Analyst знаходить; summary: сума для Alice менша за суму для Morgan | `Search_Anonymous_Returns401`, `Search_AsReporter_DoesNotReturnOtherUsersIncidents`, `Search_AsAnalyst_ReturnsOtherUsersIncident`, `SeveritySummary_AsReporter_CountsOnlyOwnIncidents` |
| A-12 | добрий | Child resource та internal comment | Alice (`Reporter`); id коментаря Morgan до інциденту Bob (comment-2) | `GET /api/incident-comments/{id}` | чужий коментар і internal не потрапляють до Reporter | comment-2 для Alice: 404; internal comment-3 для Alice: 404, для Morgan: 200; публічний коментар власного інциденту: 200 | `GetComment_OfOtherReportersIncident_Returns404`, `GetComment_InternalOnOwnIncident_Returns404_ForReporter`, `GetComment_Internal_Returns200_ForAnalyst`, `GetComment_PublicOnOwnIncident_Returns200` |

## Основний finding і залишковий ризик
1. **Контекст:** ресурс Incident, action details/read; суб'єкти Alice, Bob (Reporter) і Morgan (Analyst).
2. **Гіпотеза:** Alice прочитає інцидент Bob, підставивши його id.
3. **Стан до:** Alice → інцидент Bob дало 200 з даними Bob; vulnerable commit `8bda51159455328739ce9ebe985c920650d5b5b2`.
4. **Першопричина:** `GetDetailsAsync` шукав за id без порівняння з principal, а маршрут не вимагав автентифікації. Додатково `search` не вимагав автентифікації, а `severity-summary` не обмежувався власником.
5. **Виправлення:** `RequireAuthorization()` на групі; умова за власником і роллю в запиті; для mutation resource handler; єдиний helper 404; DTO без захищених полів.
6. **Retest:** ті самі запити після виправлення (таблиця вище); стан Bob не змінюється.
7. **Позитивна регресія:** власник читає і змінює своє; Analyst читає для аналізу й виконує triage зі статусу New.
8. **Залишковий ризик:**
    - CSRF для cookie-автентифікованих mutating endpoint-ів лишається навчальним боргом до ЛР 6.
    - Concurrent transitions і optimistic concurrency не перевірялись (відтворюваний сценарій не надано).
    - Batch/export у проєкті немає.
    - Тести triage лишають у базі інциденти зі статусом Triaged, бо видалення дозволено лише для статусу New; їх прибирає `--reset-database`.

**Схема рішення:** запит Alice з id → cookie формує перевірений principal → обмежений запит або рішення handler для entity → правило owner/role/status → дозвіл або погоджена відмова 404/403/409 → відповідь; mutation лише після дозволу.

### Окремий finding A-11 (search і severity-summary)
- **До:** `GET /api/incidents/search` не вимагав автентифікації й шукав по всіх інцидентах; `severity-summary` рахував усі інциденти незалежно від користувача.
- **Причина:** рішення про доступ не враховувало principal на цих маршрутах.
- **Виправлення:** `RequireAuthorization()` на search; умова `isAnalyst || OwnerUserId == userId` у самому запиті (search до сортування й `Take(50)`, summary до `GroupBy`), без фільтрації в пам'яті.
- **Після:** анонім отримує 401, Reporter бачить лише власні записи й підсумки, Analyst бачить усі.

### Least privilege і видимість ресурсу
- Analyst має лише читання й перехід New → Triaged, бо саме це названо в baseline 2-A; update і delete для нього 403.
- Administrator додаткових прав не має: baseline їх не публікує, а роль не дає обходу ownership.
- 404 для чужого ресурсу не розкриває його існування; 403 використано лише там, де суб'єкт ресурс бачить (Analyst, власник для triage).
- Залишкові ризики: див. пункт 8 основного finding.

## Browser flow (усі рівні)
Login alice на auth-lab.html → головна сторінка → власні details відображено (знімок 1) → деталі інциденту Bob: «Помилка: Інцидент не знайдено» (знімок 2).
Клієнт використовує `textContent` / `createTextElement(...)`, `innerHTML` не використовується (тест `ClientScript_DoesNotUseDangerousInnerHtmlSink`). Клієнт лише показує рішення сервера. Знімки без cookie, пароля та вкладок Application/Network.

## Добрий рівень: роль, transition, child, audit (також для відмінного)
- **Transition:** `POST /api/incidents/{id}/triage` доступний лише Analyst і лише зі статусу New; наступний статус (Triaged) визначає сервер, тіла запиту немає. Для Reporter 403, для чужого Reporter 404, для статусу не New 409. Запис додається до історії статусів.
- **Child:** коментар повертається, лише якщо суб'єкт бачить батьківський інцидент; internal comment бачить лише Analyst. Reporter-власник internal не бачить ні у details, ні через child endpoint.
- **Audit:** подія `authorization.denied` записується в гілці відмови всередині endpoint-а (subject, action, resource, result, час сервера, traceId за формулою `Activity.Current?.Id ?? httpContext.TraceIdentifier`).

## Відмінний рівень (додатково до всього доброго)
- Відокремлений resource-based handler `IncidentAuthorizationHandler` з операціями Read, Update, Delete, Triage.
- A-11: search і severity-summary обмежено дозволеною множиною; окремий finding вище.
- Захист overposting і вертикальне підвищення підтверджені A-08a і A-06.
- Batch/export у проєкті немає; concurrent transitions: не застосовується (сценарій не надано).

## Перевірки, відтворення і подання (усі рівні)
- ОС: ⟨Windows, версія⟩; .NET SDK 10.0.302; PostgreSQL у Docker (compose з infra/).
- Команди:
```
  docker compose --env-file infra/.env.example -f infra/compose.yaml up -d --wait
  dotnet run --project src/SecureLab.Api -- --reset-database
  dotnet test tests/SecureLab.Api.Tests/SecureLab.Api.Tests.csproj --configuration Release
```
- Результат останнього прогону: `total: ⟨N⟩; failed: 0; succeeded: ⟨N⟩`.
- Тег v0.4.0 = fixed commit `⟨hash⟩`; hash вписано наступним commit після тегу.
- Невиконані перевірки: A-08b (обрано A-08a), concurrent transitions, batch/export.
- Примітка до тестів: ліміт спроб входу з ЛР 3 (30 запитів за 10 секунд) вичерпувався великою кількістю входів в одному тестовому класі; у `IncidentEndpointTests` входи кешуються (по одному на користувача). Сам ліміт не змінено.

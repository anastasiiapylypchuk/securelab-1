# Власна карта source-to-sink

Поле: **Incident.Description**. Стан/commit: до fix `dfaa558` (sink `innerHTML`), після fix `0963d3a` (sink `textContent`); фінальний стан — `v0.5.0`. Вхід/Guid запису: канонічний marker з `resources/lab05-marker.txt`, запис `13daec59-505b-45c3-9ac1-8bf93eb1521f` (автор Alice).

| Крок | Файл та функція/DTO | Конкретне поле/значення | Доказ і довіра |
|---|---|---|---|
| Source | `Client/browser-lab.html`, форма `#edit`, `<textarea name="description">` | введений текст (marker) | контрольоване користувачем |
| Request | `Client/browser-lab.js`, обробник `submit` форми `#edit` → `fetch("/api/incidents", { method: "POST" })` | JSON-поле `description` у Payload | Network: `POST /api/incidents` 201, Payload = marker; контрольоване користувачем |
| Validation/mapping | `Scaffolding/Lab02Endpoints.cs`: `CreateIncidentRequest` → validation ЛР 2 (required, довжина ≤ 4000) → mapping у `Incident` | ті самі символи, `<`/`>` не відкидаються | validation не робить значення trusted |
| Storage | `Incident.Description`, колонка `description` таблиці `incidents` (PostgreSQL) | те саме значення | збережене значення користувача |
| Response | `GET /api/incidents/{id}` → `IncidentQueries.GetDetailsAsync` → `IncidentDetailsResponse.Description` | JSON-поле `description` (`\"` — лише JSON-escape) | Network: GET 200, Response JSON до і після fix однаковий; недовірене для браузера |
| Client transform | `browser-lab.js`, функція `load()`: `current = await response.json()` | `current.description` без змін | недовірене |
| Sink/context | до fix: `load()` → `document.querySelector("#description").innerHTML = current.description` (**HTML parser**); після fix: `setPlainText(document.querySelector("#description"), current.description)` → `element.textContent` (**текстовий вузол**) | до: елемент `<img onerror>`, marker `executed`; після: один текстовий вузол, `null` | до — небезпечний; після — безпечний |

## Другий потік: IncidentComment.Text (Добре / Відмінно)

Стан/commit: seed додано в `dfaa558`, fix у `0963d3a`. Запис: інцидент `20000000-0000-0000-0000-000000000001`, коментар `30000000-0000-0000-0000-000000000005` (автор Morgan, `IsInternal = false`).

| Крок | Файл та функція/DTO | Конкретне поле/значення | Доказ і довіра |
|---|---|---|---|
| Source | `Data/DbSeeder.cs`, `SeedAsync`, константа `Lab05Marker` (у продукті — будь-який автор коментаря) | marker | контрольоване користувачем (у продукті) |
| Request | у стенді — seed під час `--reset-database`; endpoint створення коментаря в API немає | — | відтворюваний seed |
| Validation/mapping | `IncidentComment` initializer у `AddRange` | `Text = Lab05Marker` | без змін |
| Storage | `IncidentComment.Text`, таблиця `incident_comments` | те саме значення | збережене значення користувача |
| Response | `GET /api/incidents/{id}` → масив `comments` (internal-коментарі відфільтровано, ЛР 4) | JSON-поле `comments[].text` | недовірене для браузера |
| Client transform | `browser-lab.js`, `load()`, цикл `for (const comment of current.comments ?? [])` | `comment.text` без змін | недовірене |
| Sink/context | до fix: `paragraph.innerHTML = comment.text` (**HTML parser**); після: `setPlainText(paragraph, comment.text)` (**текстовий вузол**) | до: `<img>` у `#comments`, `executed`; після: текст, `null` | до — небезпечний; після — безпечний |

## Інвентаризація `browser-lab.js`

| Файл/функція | Категорія даних | Контекст | Обґрунтоване рішення |
|---|---|---|---|
| `load()`: `status.textContent = GET: …` | server-generated (HTTP-статус) | text | безпечно |
| `load()`: `#title.textContent = current.title` | збережене значення користувача | text | безпечно |
| `load()`: `#description.innerHTML = current.description` | збережене значення користувача | HTML parser | **замінено** на `setPlainText` (textContent) |
| `load()`, цикл: `paragraph.innerHTML = comment.text` | збережене значення користувача | HTML parser | **замінено** на `setPlainText` (textContent) |
| `load()`: `#edit.elements.description.value = current.description` | збережене значення користувача | значення поля форми | безпечно: `value` не парситься як HTML |
| submit: `status.textContent = POST: …` | server-generated | text | безпечно |

Посилань (`href`/`src`) з даних, `eval`, `new Function`, inline event handlers у файлі немає. Третього sink немає. Повторний render: `#comments` очищується `replaceChildren()` перед циклом.

## Поглиблена перевірка (Відмінно)

`tests/browser/description-dom.js`: для marker-запису `#description.textContent === JSON.description` і `childElementCount === 0`; для `…0001` кожен `<p>` у `#comments` має текст, що дорівнює `comments[i].text`, без дочірніх елементів, кількість збігається з JSON; після повторного `load()` коментарі не дублюються; 6 позитивних рядків відображаються без змін; `data-lab05-marker === null`. Результат: `FAIL: Description text changed` на `dfaa558`, `PASS` на `40eec3e` (Edge 156).

## Гіпотеза

Значення з `<textarea name="description">` зберігається в `Incident.Description` (PostgreSQL), повертається через JSON-поле `description` і в `load()` передається в `#description.innerHTML` в HTML-контексті; тому, якщо рядок містить елемент з inline event handler, браузер інтерпретує дані як розмітку й виконає код у сеансі будь-якого глядача з правом читання запису.


# Докази безпеки браузера (DEL-01)

Рівень: **відмінний («Відмінно»)**. Паролі, значення cookie/token і export browser storage не записано; на скрінах значення cookie замазано.

## Стенд і Git-стан (Для всіх)

ОС, browser/version, API/probe origins: Windows, Microsoft Edge 156; .NET SDK 10.0.302; API `http://localhost:5080` (Development); probes `http://localhost:4173` (allowed) і `http://localhost:4174` (disallowed).

Release/base_commit/entry_parent з receipt (`.scaffolds/lab-05.json`): release `lab-05-start-v1`, inherits `v0.4.0`, base_commit `d084ba4ad9b83b0bb906c71424cfd9e305e5fa397`, entry_parent `4d2cb57b5bdde806a65f11bbf6967db886805138`. entry_parent ≠ base_commit, бо після `v0.4.0` в гілці ЛР 4 є коміт `4d2cb57` «Search: stable order by Id» (стабільне сортування пошуку); тег `v0.4.0` не змінювався, гілку `lab/5-browser-xss` створено від `4d2cb57`.

Vulnerable/fixed hashes, v0.5.0, main і спосіб передавання:

| Стан | Commit |
|---|---|
| Vulnerable (scaffold) | `6651bc3` |
| Vulnerable + public seed comment (спостереження «до») | `dfaa558` |
| Fixed XSS (safe DOM, helper) | `0963d3a` |
| Development-only CORS | `67aa5cf` |
| CSP report-only + перенесення inline-стилів | `c48a6b3` |
| CSP enforcement | `40eec3e` |
| DOM-тест і документи | див. `git log` / `git show v0.5.0` |
| `v0.5.0` = `main` = `lab/5-browser-xss` | див. `git log` / `git show v0.5.0` |

Передавання: `git merge --ff-only lab/5-browser-xss` у `main`, `lab05.bundle` (`git bundle verify` — OK, три refs).

Перевірка стенда: `dotnet run --project src/SecureLab.Api -- --reset-database`, `dotnet test tests/SecureLab.Api.Tests -c release` — 41/41 passed (до і після seed коментаря).

Механізм сеансу (Application → Storage → Cookies → `http://localhost:5080`), без Value: назва `.AspNetCore.Identity.Application`, Domain `localhost`, Path `/`, HttpOnly ✓, SameSite Lax, Secure —.

## Гіпотеза й REG-XSS-01 (Для всіх)

Карта Description: `docs/source-to-sink.md`.

Гіпотеза source → storage → response → sink/context: `<textarea name="description">` → `Incident.Description` (PostgreSQL) → JSON `description` → `load()` → `#description.innerHTML` (HTML context); елемент з inline event handler буде розібрано як розмітку й виконано в сеансі будь-якого глядача.

Передумови, локальний користувач, Guid запису, marker, команди:
- reset/start: `docker compose --env-file infra/.env.example -f infra/compose.yaml up -d --wait`; `dotnet run --project src/SecureLab.Api -- --reset-database`; `dotnet run --project src/SecureLab.Api`;
- користувачі: alice (Reporter, автор), morgan (Analyst, глядач), bob (Reporter, контроль); вхід через `/auth-lab.html`;
- marker — лише однорядковий `resources/lab05-marker.txt`; дія — тільки `data-lab05-marker="executed"` на `#lab05-marker-target`;
- create/read: `/browser-lab.html` → назва `test marker`, опис = marker → «Створити й прочитати» → Guid `13daec59-505b-45c3-9ac1-8bf93eb1521f`;
- перевірка в Console: `document.querySelector("#lab05-marker-target").getAttribute("data-lab05-marker")`.

| Спостереження | До fix (`dfaa558`) | Після fix (`0963d3a`) | Посилання на доказ |
|---|---|---|---|
| Значення в БД/API | JSON `description` = marker (`POST 201`, `GET 200`) | той самий JSON, без змін | Payload POST; Response до/після |
| DOM основного Description | `<div id="description">` містить елемент `<img src="x" onerror=…>`; запит `x` у Network | один текстовий вузол із рядком marker; `<img>` і запиту `x` немає | Elements, Network до/після |
| Дія marker | `null` → `'executed'` | `null` → `null` | Console до/після |
| Апостроф/лапки, 5 < 7, Unicode, HTML-like рядок | лапки, `5 < 7 і 9 > 3`, `Київ — Ω` — без змін; `<b>жирний</b> текст` → елемент `<b>`; seed `…0003` → видно лише «Текст» (`<script>` став елементом) | усе без змін; `<b>жирний</b> текст` видно з дужками, один текстовий вузол; `…0003` — усе речення | скріни сторінок і Elements |
| Довжина за власними правилами ЛР 2 | 3900 × «А» (межа 4000): GET 200, рядок видно | те саме, без client error | скріни `test long` |
| Вікно Morgan: GET і перевірка marker; контроль Bob | Morgan (InPrivate): GET 200, `null` → `'executed'`, `/api/me` = morgan — **stored XSS**; Bob: GET 404, `null`, `/api/me` = bob | Morgan: GET 200, marker як текст, `null` → `null` | скріни Morgan/Bob |

Класифікація: **stored** (збережене в PostgreSQL значення виконується пізніше в іншого користувача) + **DOM-based** (небезпечне перетворення — клієнтський `innerHTML`).

Finding:
- **Актив:** browser session глядача інциденту (у т.ч. Analyst) і дані, доступні від його імені.
- **Передумови:** автентифікований Reporter контролює `Incident.Description`; автор коментаря — `IncidentComment.Text`; глядач має право читання запису.
- **Першопричина:** `Client/browser-lab.js`, `load()`: `#description.innerHTML = current.description` і `paragraph.innerHTML = comment.text` — збережений текст користувача передається в HTML parser.
- **Safe DOM diff:**
  ```diff
  +function setPlainText(element, value) {
  +  element.textContent = value ?? "";
  +}
  -  document.querySelector("#description").innerHTML = current.description;
  +  setPlainText(document.querySelector("#description"), current.description);
  -    paragraph.innerHTML = comment.text;
  +    setPlainText(paragraph, comment.text);
  ```
- **Retest:** той самий marker і той самий запис — текст, `null`, без `<img>` і запиту `x` (Alice і Morgan); коментар `…0001` — текст, `null`; normal text без змін.
- **Залишковий ризик:** інші сторінки/поля клієнта поза інвентаризацією; сторонній UI Scalar (`/scalar`, лише Development); майбутні URL/attribute-контексти.

REG-XSS-01 (повторювана): після reset/start увійти як alice → `/browser-lab.html` → Console-перевірка = `null` → створити запис із marker → очікування: marker видно як текст, у `#description` лише текстовий вузол, перевірка = `null`, у Network немає `x`, Response JSON = вхідне значення; InPrivate morgan → той самий Guid → `null`; Guid `…0001` → `#comments` — текст, `null`; normal text (лапки, `<`, Unicode, 3900 символів) без змін. Негативний контроль: на `dfaa558` той самий marker → `<img>` у DOM і `'executed'` в Alice та Morgan. Автоматизація: `tests/browser/description-dom.js`.

## CORS і REG-CORS-01 (Для всіх)

Прогноз (Етап 3, крок 1), заповнено до зміни policy:

| Сценарій | Чи доходить request до API? | Чи може JavaScript прочитати response? | Чому |
|---|---|---|---|
| same-origin 5080 → API | так | так | той самий origin, CORS не потрібен |
| simple GET 4173 → API | так | ні | немає valid CORS response, SOP браузера |
| simple GET 4174 → API | так | ні | origin не в allowlist |
| curl/.http → API | так | не застосовується | це не browser JavaScript, SOP не діє |
| preflighted 4173 → API («Добре / Відмінно») | спершу OPTIONS; actual GET — лише після успішного preflight | ні без успішного preflight | browser preflight і CORS |

Команди запуску probes (з кореня проєкту, кожна у своєму терміналі):
```powershell
py -3 -m http.server 4173 --bind localhost --directory demonstrations/cors-probe
py -3 -m http.server 4174 --bind localhost --directory demonstrations/cors-probe
```

Policy — лише Development, один exact origin 4173; 4174 — контроль; `AllowCredentials()` лишено для cookie-досліду (Добре/Відмінно):
```csharp
if (builder.Environment.IsDevelopment())
    builder.Services.AddCors(o => o.AddPolicy("Lab05BrowserProbe", p =>
        p.WithOrigins("http://localhost:4173").WithMethods("GET")
         .WithHeaders("X-Lab-Cors-Probe").AllowCredentials()));
// app.UseRouting(); UseCors (Development) → UseAuthentication → UseAuthorization → UseRateLimiter
```

| Клієнт / простий запит | До policy | Fixed state | Status, ACAO, Console / доказ |
|---|---|---|---|
| Same-origin 5080 | працює | працює | 200, CORS не потрібен; `/browser-lab.html` |
| Allowed 4173 | `TypeError`, `No 'Access-Control-Allow-Origin'` | `{status: 200, body: '{"status":"ready"}'}` | до: GET 200 (OK) у Network, `Origin: http://localhost:4173`, без ACAO; після: `Access-Control-Allow-Origin: http://localhost:4173` |
| Disallowed 4174 | `TypeError`, `No 'Access-Control-Allow-Origin'` | те саме | GET **200** — request дійшов і виконався; ACAO відсутній |
| Direct HTTP / curl | 200 | 200, тіло видно повністю | `curl.exe -i [-H "Origin: …"] http://localhost:5080/health` |

REG-CORS-01:
```powershell
curl.exe -sS -D - -o NUL -H "Origin: http://localhost:4173" "http://localhost:5080/health"
curl.exe -sS -D - -o NUL -H "Origin: http://localhost:4174" "http://localhost:5080/health"
```
Обидві: `HTTP/1.1 200 OK`, `X-Content-Type-Options: nosniff`, `Referrer-Policy: no-referrer`. Для 4173: `Access-Control-Allow-Origin: http://localhost:4173`, `Access-Control-Allow-Credentials: true`. Для 4174: жодного `Access-Control-*`. Browser evidence: на 4174 Network містить request до абсолютної `http://localhost:5080/health` з `Origin: http://localhost:4174`, а код сторінки отримує `TypeError`.

Перевірка порядку через читання 401 без cross-origin cookie: на 4173 `await fetch("http://localhost:5080/api/incidents").then(r => r.status)` → **401** (число, без `blocked by CORS policy`) — CORS стоїть до authorization.

Пояснення різниці browser/direct HTTP: SOP/CORS — правило браузера для web content; API запит виконує в обох випадках, а браузер лише вирішує, чи віддати response коду сторінки. curl не браузер, тому читає response; для нього діють тільки authn/authz/validation API.

## Додатково для Добре та Відмінно

Другий flow IncidentComment.Text: `docs/source-to-sink.md`, розділ 2. Public seed comment: Guid `30000000-0000-0000-0000-000000000005`, інцидент `…0001`, автор Morgan, `IsInternal = false`, `Text = Lab05Marker` (коміт `dfaa558`; тести 41/41 після зміни, похідні counts не змінювались). DOM до: у `#comments` другий `<p>` містить `<img src="x" onerror=…>`, `null` → `'executed'`; після: текстовий вузол, `null` → `null`.

Єдиний safe helper і виклики для обох полів: `function setPlainText(element, value) { element.textContent = value ?? ""; }` у `Client/browser-lab.js`; виклики: `setPlainText(document.querySelector("#description"), current.description)` і `setPlainText(paragraph, comment.text)`.

Preflight з 4173 і 4174, OPTIONS → GET / blocked GET, exact origin/header/method:
- до policy: OPTIONS **405** (`Allow: GET, HEAD`, request `Access-Control-Request-Method: GET`, `Access-Control-Request-Headers: x-lab-cors-probe`); actual GET — provisional headers, не надіслано;
- після, 4173: OPTIONS **204** з `Access-Control-Allow-Origin: http://localhost:4173`, `-Methods: GET`, `-Headers: X-Lab-Cors-Probe`, далі GET 200;
- після, 4174: OPTIONS **204 без жодного `Access-Control-*`**, `Response to preflight request doesn't pass access control check`; actual GET не надіслано. Висновок робиться за заголовками, а не за статусом.

Cookie-дослід:
| Дослід | Результат |
|---|---|
| Alice увійшла; 4173 → «GET» (`credentials: "include"`) | `200: [...]`; request `Origin: http://localhost:4173` + `Cookie`; response `Access-Control-Allow-Origin: http://localhost:4173`, `Access-Control-Allow-Credentials: true` |
| 4174 → «GET» | «Браузер не надав response JavaScript»; Network **200** — запит із cookie виконано, відповідь приховано |
| без `AllowCredentials()`, 4173 | `The value of the 'Access-Control-Allow-Credentials' header in the response is '' which must be 'true' when the request's credentials mode is 'include'` |
| `AllowCredentials()` повернуто, InPrivate без входу | **401** з ACAO і `Allow-Credentials: true`; JS прочитав HTTP-відмову |

Cookie надсилається з 4173 на 5080, бо порт не входить до поняття site: це різні origins, але той самий site (SameSite=Lax не заважає). Кінцевий `AllowCredentials()` — лише в Development policy для 4173. Review XSS/CORS/CSRF/authorization — `docs/report-lab-05.md`, розділ «Review».

| Директива CSP | Фактичні ресурси застосунку | Обране джерело / причина |
|---|---|---|
| default-src | fallback для неявних типів | `'self'` — усе з 5080 |
| script-src | `app.js`, `browser-lab.js`, скрипт `auth-lab.html` з 5080 | `'self'`; inline-скриптів і обробників немає |
| style-src | `styles.css` з 5080 (inline `style=""` з `index.html` перенесено в `styles.css`) | `'self'`, без `unsafe-inline` |
| connect-src | `/api/...` на 5080 | `'self'`; 4173 навмисно не додано (тимчасовий CORS-стенд) |
| img-src | власних зображень немає | `'self'` |
| frame-ancestors | вбудовування не потрібне | `'none'` (не має fallback до `default-src`) |

Також: `object-src 'none'; base-uri 'self'; form-action 'self'`. Повна policy:
`default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self'; connect-src 'self'; object-src 'none'; base-uri 'self'; form-action 'self'; frame-ancestors 'none'`.

Місце зміни middleware: наявний `app.Use` у `Program.cs` після `UseStatusCodePages` (там уже `nosniff` і `Referrer-Policy`); другої middleware не додано. Виняток `/scalar` лише в Development (сторонній UI-package Scalar) — залишковий ризик для ЛР 6.

Enforcement: document `/` і `/browser-lab.html` — **200**, один header `Content-Security-Policy` з policy вище; три сторінки flow (`/`, `/browser-lab.html` з читанням `…0001`, `/auth-lab.html`) — Issues порожні, усе працює. Кероване порушення `new Image().src = "http://localhost:4173/x.png"`: `Loading the image … violates the following Content Security Policy directive: "img-src 'self'". The action has been blocked.`; Issues — Blocked; `x.png` — provisional headers, не надіслано.

| Header / control | Фактичне значення | Ризик і межа захисту / policy rationale |
|---|---|---|
| X-Content-Type-Options | `nosniff` (baseline) | забороняє MIME sniffing; не замінює правильний серверний `Content-Type` і validation |
| Referrer-Policy | `no-referrer` (baseline) | URL сторінки (шляхи, Guid) не витікає стороннім сайтам у `Referer`; клієнт не переходить на зовнішні сайти й не потребує Referer, тому policy підходить; не замінює заборону класти секрети в URL |
| frame-ancestors | `'none'` у CSP | забороняє вбудовування в чужий iframe (clickjacking); не замінює authorization чи XSS-fix |

## Додатково для Відмінно

DOM-тест: файл `tests/browser/description-dom.js`; запуск — увійти як alice, `/browser-lab.html`, Ctrl+Shift+R, вставити файл цілком у Console. Browser: Microsoft Edge 156. Vulnerable `dfaa558` → `FAIL: Description text changed`; fixed `40eec3e` → `PASS: description, comments, re-render and normal text rendered as plain text`.

Comments, повторний render без дублювання та позитивні рядки: тест перевіряє кожен `comments[].text` інциденту `…0001` (текст = JSON, без дочірніх елементів, кількість збігається), повторний `load()` без дублювання, і 6 позитивних рядків (`9801cf0c-…` `<b>`, `d9a41861-…` лапки, `4e7cae43-…` `5 < 7`, `e99395c3-…` Unicode, `ec4ce385-…` 3900 символів, seed `…0003`).

CSP report-only → enforcement:
| Режим | Спостереження |
|---|---|
| Report-only, flow | document 200, header `Content-Security-Policy-Report-Only`; Issues: `style-src-attr` × 2 — inline `style` у `index.html` рядки 25, 27 (Report-only). Виправлено переносом у `styles.css` (`.summary-section`, `#summaryStatus`), не `unsafe-inline`; після — «No issues» на трьох сторінках |
| Report-only, кероване порушення | `…violates "img-src 'self'". The policy is report-only, so the violation has been logged but no further action has been taken.`; `x.png` пішов (404 від Python-сервера) |
| Пастка кешу | сторінка, відкрита до перезапуску API, лишалась зі старою report-only policy; після Ctrl+Shift+R — document 200 і новий header |
| Enforcement | header `Content-Security-Policy`; `…The action has been blocked.`; `x.png` не надіслано |
| CSP маскує sink | на `dfaa558` під enforcement у `#description` є `<img>`, але `Executing inline event handler violates … 'script-src 'self''… blocked`, marker = `null` → CSP — defense in depth, а не виправлення |

safe-url.js / атрибут: `resources/copyable/safe-url.js` у Console → 7 рядків: `https://example.com/a`, `http://localhost:5080/incidents/1`, `null`, `null`, `null`, `http://localhost:5080/incidents/1` (href створеного посилання), `null` (атрибута onclick немає). Посилань із даних у `browser-lab.js` немає, тому функцію в клієнт не додано.

Пояснення text/attribute/URL/JavaScript та ризик third-party scripts — `docs/report-lab-05.md`, розділ «Додатково для Відмінно».


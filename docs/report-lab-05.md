# Звіт WEB ЛР 5


## Для всіх рівнів

**DEL-01:** карта `docs/source-to-sink.md`, докази `docs/browser-security-evidence.md`, скріни `docs/evidence/`.

| До | Причина | Fix | Retest | Залишковий ризик |
|---|---|---|---|---|
| канонічний marker в описі (і в seed-коментарі) виконувався в сеансах Alice і Morgan — stored + DOM-based XSS | `Client/browser-lab.js`, `load()`: `innerHTML` для `current.description` і `comment.text` | єдиний helper `setPlainText` → `textContent` для обох полів | той самий marker і запис: текст, `null`, без `<img>` і запиту `x`; JSON до/після однаковий; normal text без змін; DOM-тест FAIL → PASS | інші сторінки клієнта; Scalar (`/scalar`, Development); майбутні URL/attribute-контексти |

**DEL-02:** release `lab-05-start-v1`, base_commit `d084ba4ad9b83b0bb906c71424cfd9e305e5fa397` (`v0.4.0`), entry_parent `4d2cb57` (v0.4.0 + стабільне сортування пошуку ЛР 4). Vulnerable `6651bc3` (scaffold) / `dfaa558` (+ seed коментаря); fixed XSS `0963d3a`; CORS `67aa5cf`; CSP report-only `c48a6b3`; CSP enforcement `40eec3e`; фінальний див. `git log` / `git show v0.5.0` = `v0.5.0`. Передано: `git merge --ff-only` у `main`; `lab05.bundle` (`git bundle verify` OK; `git bundle list-heads`: `main`, `lab/5-browser-xss`, `v0.5.0` → див. `git log` / `git show v0.5.0`).

**DEL-03:** відповіді на контрольні питання й пояснення рішень — нижче.

### Контрольні питання

1. **Чому value з БД може залишатися недовіреним?** Бо в БД його поклав користувач. Збереження й повернення через API не змінюють походження: це «збережене значення користувача», а не server-generated. На стенді marker пройшов validation ЛР 2, лежав у PostgreSQL і повернувся JSON-ом без змін.
2. **Source, transformation і sink у моєму flow.** Source — `<textarea name="description">`; transformation — POST JSON → DTO/validation → `Incident.Description` → `GET` → `IncidentDetailsResponse.Description` → `response.json()` → `current.description`; sink — `#description.innerHTML` (до fix) / `textContent` через `setPlainText` (після).
3. **Stored vs reflected vs DOM-based.** Stored — payload зберігається на сервері й виконується під час пізнішого перегляду (Morgan відкрив запис Alice). Reflected — сервер одразу повертає значення з поточного запиту в HTML-відповідь. DOM-based — небезпечне перетворення виконує клієнтський JS (тут `innerHTML`). Ознаки не взаємовиключні: мій flow — stored + DOM-based.
4. **Чому блокування `<script>` не усуває XSS?** Код виконується й без `<script>`: `<img onerror>`, `<svg onload>`, `javascript:` URL тощо. Більше того, `<script>`, вставлений через `innerHTML`, не виконується, а `onerror` — виконується (саме так спрацював marker). Blacklist залежить від одного запису payload, а parser усе одно отримує недовірений HTML.
5. **Коли `textContent`, а коли sanitizer?** `textContent` — коли поле за контрактом звичайний текст (наш випадок: formatted HTML заборонено). Sanitizer — лише за окремої продуктової вимоги приймати обмежений HTML; тоді підтримувана бібліотека (DOMPurify) з мінімальним allowlist тегів, атрибутів і URL-схем.
6. **Чому sanitizer не пишуть regular expression?** HTML не є регулярною мовою: вкладеність, різні лапки, регістр, entity-кодування, неповні теги й правила виправлення помилок parser браузера. Regex легко обійти; sanitizer має розбирати HTML так само, як браузер, і застосовувати allowlist.
7. **З яких трьох компонентів складається origin?** Схема, host, порт: `http://localhost:5080` і `http://localhost:4173` — різні origins (інший порт).
8. **Що browser надсилає в CORS preflight і хто його ініціює?** Ініціює сам браузер (не код сторінки) перед «не простим» запитом — у нас через заголовок `X-Lab-Cors-Probe`. Надсилає `OPTIONS` з `Origin`, `Access-Control-Request-Method: GET`, `Access-Control-Request-Headers: x-lab-cors-probe`, без cookie.
9. **Хто оголошує CORS-політику і хто її застосовує?** Оголошує API — заголовками `Access-Control-Allow-*` (policy `Lab05BrowserProbe` у `Program.cs`). Застосовує браузер: вирішує, чи надіслати actual request після preflight і чи віддати response JavaScript-у. API при цьому запит виконує (4174 → 200).
10. **Чому curl читає response, коли browser script отримує CORS error?** SOP/CORS — правило браузера для web content. curl не браузер, він просто отримує HTTP-відповідь (`Origin: 4174` → 200 з тілом). Для curl діють лише серверні authentication, authorization і validation.
11. **Чому CORS не є authorization і не замінює CSRF-захист?** CORS не перевіряє, хто користувач і чи має він право; він лише регулює, чи прочитає скрипт відповідь. Запит з чужого origin із cookie доходить і виконується (4174 + cookie Alice → 200), тому для доступу потрібна authorization (Bob → 404, без cookie → 401), а для state-changing запитів — antiforgery (ЛР 6).
12. **Чому wildcard origin не поєднують із credentials?** Тоді будь-який сайт міг би читати відповіді з даними користувача, надіслані з його cookie. Протокол CORS це забороняє, ASP.NET Core відмовляє в запуску. Потрібен точний allowlist (у нас лише `http://localhost:4173`, лише Development).
13. **Яку межу має CSP і чому вона не замінює safe DOM rendering?** CSP — другий рубіж: обмежує джерела ресурсів і inline-виконання, але не прибирає sink. На `dfaa558` під enforcement `<img>` у DOM з'явився, а marker = `null`: виконання заблокувала CSP, але вразливість лишилась — послаблення policy, `unsafe-inline`, інший контекст чи старий браузер знову її відкриють. Тому виправлення — safe DOM, CSP — defense in depth.
14. **Який risk зменшують nosniff, Referrer-Policy і frame-ancestors?** `nosniff` — браузер не «вгадує» тип відповіді й не виконає текст як скрипт/HTML; `Referrer-Policy: no-referrer` — URL сторінки (шляхи, Guid) не передається стороннім сайтам; `frame-ancestors 'none'` — сторінку не можна вбудувати в чужий iframe (clickjacking).

## Додатково для Добре та Відмінно

Посилання (усе — у `docs/browser-security-evidence.md`): IncidentComment.Text — public seed comment `…0005` (`dfaa558`), до/після; safe helper — `setPlainText` у `Client/browser-lab.js`, виклики для опису й коментарів; preflight — до policy OPTIONS 405, після: 4173 OPTIONS 204 з трьома `Allow-*` → GET 200, 4174 OPTIONS 204 без `Access-Control-*`; cookie-дослід — 4173 200 + `Allow-Credentials: true`, 4174 200 на сервері, але відповідь приховано, без `AllowCredentials()` — помилка `must be 'true'`, без входу — 401 з CORS; enforcement CSP — document 200, один header `Content-Security-Policy`, кероване порушення `…blocked`; headers — `nosniff`, `no-referrer`, `frame-ancestors 'none'`.

**Review XSS / CORS / CSRF / authorization:**
- **XSS** — недовірені дані інтерпретуються як код у моєму origin; тут значення з БД потрапляло в `innerHTML`. Виправляється в sink (safe DOM API), а не фільтром на вході; дані в БД і JSON не змінено.
- **CORS** — сервер оголошує, чи може браузер віддати cross-origin response JavaScript-у. Не автентифікація й не авторизація: запит із 4174 разом із cookie Alice дійшов до API і виконався (200), браузер лише приховав відповідь.
- **CSRF** — браузер сам додає cookie до запиту, ініційованого чужою сторінкою; CORS цього не зупиняє. Для state-changing запитів потрібен antiforgery-контроль (ЛР 6).
- **Authorization** — сервер перевіряє principal + action + resource незалежно від CORS: Bob → 404 на запис Alice; запит без cookie з дозволеного 4173 → 401, хоча CORS-заголовки є.

**Обґрунтування policy:** CORS — навчальний Development-стенд з одним exact origin `http://localhost:4173` (4174 — негативний контроль), `AllowCredentials()` лише для cookie-досліду; у Production policy не реєструється, штатна топологія — same-origin `http://localhost:5080`. CSP складено з фактичних ресурсів (усі з 5080): `default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self'; connect-src 'self'; object-src 'none'; base-uri 'self'; form-action 'self'; frame-ancestors 'none'`; inline-стилі перенесено в `styles.css` замість `unsafe-inline`; виняток `/scalar` лише в Development. `no-referrer` підходить, бо клієнт не потребує Referer.

## Додатково для Відмінно

**DOM-тест:** `tests/browser/description-dom.js`, Console у Microsoft Edge 156 на `/browser-lab.html` (alice). `dfaa558` → `FAIL: Description text changed`; `40eec3e` → `PASS: description, comments, re-render and normal text rendered as plain text`.

**Report-only → enforcement:** report-only виявив два inline `style` у `index.html` (`style-src-attr`, рядки 25 і 27) — перенесено в `styles.css`; кероване порушення `new Image()` до 4173 у report-only записано, але запит пішов; в enforcement — `The action has been blocked.`, запит не надіслано. Окремо спостерігали пастку кешу: стару policy тримала сторінка, відкрита до перезапуску API.

**Comments і повторний render:** тест перевіряє кожен `comments[].text` інциденту `…0001`, відсутність дочірніх елементів, збіг кількості з JSON і відсутність дублювання після повторного `load()` (`replaceChildren()` перед циклом).

**URL/атрибут і різні правила виведення:**

| Контекст | Приклад | Правило |
|---|---|---|
| Текстовий вузол | `#description`, `<p>` коментаря | `textContent` / `createTextNode`; не `innerHTML` для даних |
| Атрибут | `title`, `alt`, `data-*` | `setAttribute` зі статичною назвою; ніколи не створювати `on*`-атрибути з даних |
| URL (`href`, `src`) | посилання з даних | `new URL(value, base)` + allowlist схем `http:`/`https:` (для продукту — і hosts); інакше посилання не створювати. `safe-url.js`: `javascript:alert(1)` і ` JaVaScRiPt:alert(1)` → `null` |
| JavaScript | `eval`, `new Function`, `setTimeout("…")`, inline handlers | дані ніколи не стають кодом; обробники — лише `addEventListener` у зовнішньому JS |

`textContent` захищає лише текстовий контекст; для URL потрібна окрема перевірка схеми.

**Залишковий ризик third-party scripts:** у досліджуваному flow (`/`, `/browser-lab.html`, `/auth-lab.html`) сторонніх скриптів немає — усі ресурси з `http://localhost:5080` (перевірено в Network), `script-src 'self'` це закріплює. Єдиний сторонній UI — Scalar на `/scalar`, лише в Development і з документованим винятком із CSP; його залежності перевіряються в ЛР 6.

## Межі перевірки

Перевірено фактично: два sink у `browser-lab.js` (опис і коментарі), три сторінки клієнта під CSP, CORS для `/health` і `/api/incidents` з двох origins і curl, усе — локально в Edge 156 на Windows, Development. Поза стендом: інші браузери (Firefox, Safari), Production-конфігурація, справжній cross-site сценарій SameSite (порти localhost — той самий site), сторонній UI Scalar, CSRF/antiforgery (ЛР 6). Нереальних PASS не записано.


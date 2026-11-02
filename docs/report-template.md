# Звіт WEB ЛР03

## Відтворення (усі рівні)

Обраний рівень/оцінка: Відмінно (включає «Задовільно» і «Добре»); 
baseline 2-A; 
base tag v0.2.0: commit 6a64908; scaffold release/base_commit: lab-03-start-v1 / 6a6490820f82ebc55cbd6cef8a302634a3b4bef3 (commit зі scaffold a464a3c); 
гілка: lab/3-authentication; 
перевірений commit/tag v0.3.0: тег v0.3.0 (hash: ); 
ОС/SDK: Windows, .NET SDK 10.0.302, net10.0; 
команди build/tests: dotnet build, dotnet test tests/SecureLab.Api.Tests; 
фактичний результат: збірка успішна, Passed: 17, Failed: 0, Total: 17; 

## Власна реалізація і межі (усі рівні та позначені доповнення)

DTO boundary: RegistrationInput містить лише UserName, Email, DisplayName, Password; CreateIncidentRequest містить лише Title, Description, Severity, OccurredAtUtc. Полів Id, ролі, OwnerUserId, Status, hash у request DTO немає, невідомі поля JSON ігноруються. Відповіді: RegisterResponseDto (Id, UserName, DisplayName) і явно обрані поля /api/me (id, userName, displayName).

Звідки /api/me та create беруть id: лише з HttpContext.User, claim ClaimTypes.NameIdentifier, з перевіркою Guid.TryParse. Обидва endpoint мають .RequireAuthorization(); X-Demo-UserId не використовується.

Cookie options і межа HTTP: HttpOnly = true, SameSite = Lax, Secure: у Development SameAsRequest, поза ним Always. Локальний HTTP-запуск не доводить Secure, тому прапорець перевірено тестом на HTTPS-адресі.

Фактичні flags: тест Login_OverHttps_SetsHttpOnly_Secure_SameSiteLax підтвердив httponly, secure, samesite=lax. У DevTools при HTTP: path=/; samesite=lax; httponly, без secure.

Строк дії: стандартний для Identity, окремо не змінювався. Cookie сеансова, без expires; закриття вікна не замінює logout.

Однакові login-відмови: невідомий користувач і хибний пароль дають однаковий 401 application/problem+json з однаковими type, title, status (тест A-07). Відрізняється лише діагностичний traceId.

Duplicate-контракт: повторна реєстрація дає 409 {"message":"User with this name or email already exists"}; некоректні дані дають 400 {"message":"Registration failed"}. Регресія: тест Register_Success_Duplicate409_TooLongDisplayName400.

Rate limit і події: політика auth-login, ключ: IP-адреса, 30 спроб за 10 секунд, QueueLimit = 0, відхилення 429. Відновлення перевірено тестом Login_RateLimit_Returns429_ThenRecovers (31-ша спроба 429, після 10,5 с знову 401). Події: «Auth event login: result success|failure» і «Auth event logout: result success» із trace id.

CSRF навчальний борг: захист обмежується SameSite=Lax. Повної CSRF-моделі немає, це борг до ЛР 6. HttpOnly і відсутність CORS CSRF не усувають.

Обрані поглиблення: (1) знайдено й усунено додатковий auth defect; (2) threat analysis login flow.

## Докази

Маршрут довіри: запит входу → SignInManager.PasswordSignInAsync перевіряє пароль за збереженим hash → сервер видає захищену cookie → браузер надсилає її автоматично → authentication handler розшифровує її → claims потрапляють у HttpContext.User → власник ресурсу береться з principal.

Стандартна перевірка пароля: hash обчислює Identity password hasher під час UserManager.CreateAsync; під час входу PasswordSignInAsync повторює обчислення й порівнює результати. Зворотного перетворення немає. Власного хешування в проєкті немає. Hash не повертається, бо response DTO містять лише явно обрані поля.

Чому client UserId не є доказом особи: значення в body, query або header (X-Demo-UserId, ownerUserId) може написати будь-хто. Cookie сервер зашифрував сам, тому principal із cookie вважається перевіреним.

Endpoint-и перебору акаунтів та компроміси:
- POST /api/auth/register відповідає 409 на існуючий акаунт, тобто підтверджує його існування. Це усвідомлений компроміс заради зрозумілої відповіді користувачу. Rate limit на register не налаштований, це залишковий ризик.
- POST /api/auth/login не розрізняє невідомого користувача й хибний пароль, повторні спроби обмежує rate limit.

| ID | Рівень | Передумова/дія | Очікувано | Фактично | Безпечний доказ |
|---|---|---|---|---|---|
| T-01 | достатній | register з коректним DTO | safe 201 | 201, у відповіді лише id, userName, displayName | скриншот register-check |
| T-02 | достатній | повторна реєстрація; DisplayName зі 121 символу | safe rejection | повтор: 409; 121 символ: 400 {"message":"Registration failed"} | скриншоти; тест Register_Success_Duplicate409_TooLongDisplayName400 |
| T-03 | достатній | опис identity_users без даних | password не відкрито | є PasswordHash типу text, стовпця з відкритим паролем немає; доменні таблиці посилаються на identity_users | скриншот опису таблиці |
| A-01 | достатній | анонімний POST /api/incidents | 401, no redirect | 401, application/problem+json, без Location і без WWW-Authenticate | тест A01; curl із 401 |
| A-02 | достатній | login alice → GET /api/me | principal user | 200, id Alice, userName alice, без чутливих полів | тест A02 |
| A-05 | достатній | Bob створює запис із ownerUserId Alice | новий owner = Bob | 201, owner у БД = Bob | тест A05 |
| S-01 | достатній | перегляд відповідей, консолі API і git diff --staged | без витоків | чутливих даних не виявлено | checklist |
| A-03 | добрий | cookie Alice + X-Demo-UserId Боба | principal не змінюється | відповідь лишилась Alice; без cookie 401 | тест A03; probe-check (isAlice: true); curl |
| A-04 | добрий | create від Bob без owner | owner = principal | owner = Bob | тест A04 |
| A-06 | добрий | login → logout → /api/me | 401 | logout 204, Set-Cookie з порожнім значенням і expires=1970, далі 401 | тест A06; скриншот DevTools |
| A-07 | добрий | невідомий користувач і хибний пароль | однаковий результат | обидва 401, однакові type, title, status | тест A07 |
| Browser flow | добрий | п'ять перевірок етапу 4 | state/profile/create/logout | до входу Profile: 401; після login профіль Alice; Create: 201 без поля власника; після logout Profile: 401; Local/Session storage і cookies порожні | скриншоти сторінки, Network, Application |
| Duplicate | добрий | повторна реєстрація | послідовний 409 | 409 | тест register |
| Cookie flags | добрий | тест HTTPS login | HttpOnly, Secure, SameSite=Lax | підтверджено | тест Login_OverHttps_SetsHttpOnly_Secure_SameSiteLax |
| Rate limit і події | добрий | 30 спроб, 31-ша, очікування вікна | 429, відновлення, без credentials | 31-ша спроба 429; після вікна 401; події без credentials | тест rate limit; три рядки подій із консолі API |
| Поглиблення 1 | відмінний | register із DisplayName зі 121 символу до і після перевірки довжини | 400 замість помилки сервера | до: 500; після: 400, запис не створюється | два скриншоти; тест register |
| Поглиблення 2 | відмінний | threat analysis | критерій обраного пункту | див. нижче | текст звіту |

Контрольні точки: CP-01 (T-01, T-02, T-03); CP-02 (/api/me після login, 401 до входу, A-03, A-06, A-07, flags); CP-03 (анонімний POST create дає 401; POST із forged ownerUserId зберігає власника з principal, A-05).

Обґрунтування partition key та виключених полів події: ключ rate limit це IP-адреса, бо він зменшує кількість спроб з одного джерела. Недолік: користувачі за спільним NAT ділять ліміт. Ключ за введеним ім'ям користувача дав би стороннім змогу заблокувати чужий вхід, тому його не використано. Ліміт підвищено з 5 до 30 за 10 с, бо тестовий хост не має IP-адреси клієнтів і всі клієнти ділять ключ «unknown»; з лімітом 5 падали тести. In-memory limiter це локальний навчальний контрзахід, а не захист розподіленої системи. У події входять тип, результат і trace id. Навмисно виключено: password, cookie, password hash, token, тіло запиту та введене ім'я користувача (воно могло містити помилково введений пароль).

Поглиблення 1, додатковий auth defect:
- Дефект: атрибути [Required] і [StringLength] на RegistrationInput у minimal API не перевіряються автоматично, тож довжина полів не контролювалась.
- До: DisplayName зі 121 символу доходив до БД (стовпець обмежено 120 символами) і давав 500 для обох запитів.
- Виправлення: явна перевірка довжини в endpoint register (UserName і Email до 256, DisplayName до 120, Password до 100).
- Після: 400 {"message":"Registration failed"}, запис не створюється; звичайна реєстрація далі дає 201, дублікат 409.
- Регресія: тест Register_Success_Duplicate409_TooLongDisplayName400.
- Окремо про /api/me: вихідний стан (X-Demo-UserId без cookie повертав профіль іншого користувача) взято з опису методички, власного скриншота «до» немає. Стан «після»: 401 без cookie, а з cookie Alice і чужим header відповідь лишається Alice.

Поглиблення 2, threat analysis login flow:
- Активи: облікові дані (пароль, hash), сеансова cookie, акаунти та їхні інциденти.
- Entry points: POST /api/auth/login, POST /api/auth/register, POST /api/incidents, GET /api/me.
- Trust boundaries: браузер і сервер (усе, що надсилає клієнт, недовірене); сервер і БД.
- Загроза: підбір паролів (credential stuffing) через /api/auth/login.
- Контрзаходи: rate limit за IP (429), однаковий 401 для невідомого користувача й хибного пароля, події входу без credentials, стандартний hasher із сіллю.
- Залишковий ризик: розподілена атака з багатьох IP обходить ліміт за IP; користувачі за спільним NAT ділять ліміт; limiter локальний; блокування акаунта після невдалих спроб не ввімкнено; register розкриває існування акаунта. Ризик не перебільшується до рівня промислової системи.


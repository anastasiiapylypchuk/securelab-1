# Звіт до лабораторної роботи № TODO

## 1. Ідентифікація стану

- Варіант: 2-A «Трекер інцидентів».
- Гілка: main
- Фінальний тег: v0.1.0
- Commit hash: fdd56fa76e71ac2a8ba5f31e044e3fa1323263e2

## 2. Змінений маршрут

Наскрізний потік:
Кнопка у Client/index.html
  → обробник у Client/app.js
  → GET /api/incidents/severity-summary
  → IncidentEndpoints.cs (Presentation) 
  → IncidentQueries.cs (Application) 
  → SecureLabDbContext.Incidents` (Data / EF Core) 
  → PostgreSQL 
  → IncidentSeveritySummaryResponse (DTO) 
  → масив JSON (200 OK) 
  → безпечний вивід через textContent у Client/app.js.

Фрагмент коду (Application → DbContext):

public async Task<IReadOnlyList<IncidentSeveritySummaryResponse>> GetSeveritySummaryAsync(CancellationToken cancellationToken)
{
    var dbSummary = await dbContext.Incidents.AsNoTracking()
        .GroupBy(i => i.Severity)
        .Select(g => new { g.Key, Count = g.Count() })
        .ToDictionaryAsync(x => x.Key, x => x.Count, cancellationToken);

    var result = Enum.GetValues<IncidentSeverity>().OrderByDescending(s => s)
        .Select(s => new IncidentSeveritySummaryResponse(s.ToString(), dbSummary.GetValueOrDefault(s, 0)))
        .ToList();

    return result;
}

##3 Виконані зміни
Реалізовано точку розширення /api/incidents/severity-summary, замінивши початкову заглушку 501 Not Implemented на повноцінну логіку (статус 200 OK).
Створено окремий response DTO IncidentSeveritySummaryResponse без зайвих полів сутності.
Додано асинхронний query через AsNoTracking(), GroupBy, Count() та ToDictionaryAsync.
Застосовано політику повного переліку (включно з нульовими групами для Critical) та сталий порядок сортування.
Оновлено клієнтську частину (app.js), забезпечивши безпечний вивід даних через textContent (захист від XSS) та обробку станів завантаження і помилок.

## 4. Перевірка

ID,Передумови,Дія,Очікувано,Фактично,Доказ
T-01,"PostgreSQL healthy, API запущено",GET /health,"200, API може з’єднатися з БД","200 OK, стан Healthy",Файл incidents.http
T-02,Відновлений seed,GET /api/incidents?status=Triaged,"200, список відповідає фільтру","200 OK, JSON-масив відфільтрованих інцидентів",DevTools Network
T-03,Відновлений seed,GET /api/incidents?status=Resolved,200 з порожнім масивом,"200 OK, масив []",incidents.http / list-flow
T-04,Відновлений seed,GET /api/incidents/99999999-...,404 у Problem Details,404 Not Found (Problem Details),incidents.http
T-05,Відновлений seed,GET /api/incidents?status=Unknown,400 Validation Problem Details,400 Bad Request,incidents.http
T-06,"Реалізовано етап 3, seed",GET /api/incidents/severity-summary,200; повний перелік та сталий порядок,"200 OK, масив з Critical:0, High:1, Medium:1, Low:1",incidents.http / тест
T-07,API та клієнт запущено,Натиснути кнопку підсумку у UI,Безпечний показ результату та станів,Дані відображаються у списку через textContent,Скриншот інтерфейсу та Network
T-08,Змінено дані у БД,"Команда --reset-database і повтор T-02, T-06",Seed повертає стенд до відомого стану,Стан успішно відновлено,Вивід команди в терміналі

## 5. Security-сценарій

У цій лабораторній роботі реалізовано захист від XSS-вразливостей на стороні клієнта: замість небезпечного методу innerHTML для рендерингу елементів інтерфейсу використовується створення вузлів через document.createElement та запис тексту виключно через властивість textContent. Крім того, переглянуто git diff перед створенням коміту для гарантування відсутності чутливих даних (паролів, рядків підключення, токенів) у репозиторії.

## 6. Висновок

У ході виконання лабораторної роботи було успішно реалізовано наскрізне розширення функціоналу трекера інцидентів (варіант 2-A). Спроектовано новий серверний ендпоінт, підключено базу даних із використанням ефективних запитів EF Core, розроблено безпечний клієнтський інтерфейс та пройдено повний цикл автоматизованих і ручних перевірок. Робота повністю готова до здачі та зафіксована у репозиторії згідно з вимогами безпечного Git-циклу.

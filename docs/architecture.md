# Карта архітектури (Варіант 2-A: Підсумок за severity)

## Компоненти

| Компонент | Розташування | Відповідальність |
|---|---|---|
| Browser client | `src/SecureLab.Api/Client/` | Надсилає HTTP-запити, безпечно показує відповідь через DOM API |
| Presentation | `Presentation/` | Описує endpoints, читає зовнішні параметри, формує HTTP-відповідь |
| Application | `Application/` | Виконує сценарій отримання списку або деталей інциденту |
| Data | `Data/` | Відображає C#-сутності на PostgreSQL через EF Core/Npgsql |
| PostgreSQL | `infra/compose.yaml` | Зберігає навчальні дані у локальному контейнері |

## Наскрізний маршрут (severity-summary)
click на кнопку підсумку у Client/app.js
  → GET /api/incidents/severity-summary
  → Presentation/Endpoints/IncidentEndpoints.cs (MapGet маршрут)
  → Application/Incidents/IncidentQueries.cs (GetSeveritySummaryAsync)
  → Data/SecureLabDbContext.cs (таблиця incidents)
  → PostgreSQL (GROUP BY агрегація через EF Core)
  → IncidentSeveritySummaryResponse (DTO) у Presentation/Contracts/
  → масив JSON (200 OK)
  → document.createElement та textContent у Client/app.js

## Межі довіри

Межа                       |Чому даним ще не можна довіряти                        |Де перевіряємо або обмежуємо
Користувач → Browser client|Користувач контролює введення і дії в браузері         | Обмежуємо на рівні UI (кнопки, випадаючі списки), проте це лише для зручності, а не для справжньої безпеки
Browser client → API       |Клієнт і HTTP-запит можна змінити поза UI              |Маршрутизатор (Endpoint Routing) перевіряє шляхи; API валідує вхідні параметри (наприклад, статус через Enum) перед виконанням логіки
PostgreSQL → API → DOM     |У БД може зберігатися раніше введений недовірений текст|Бекенд віддає лише суворий DTO без зайвих полів, а клієнтський JS вставляє дані виключно через textContent, що нейтралізує будь-який HTML/JS код

## Конфігураційні входи

global.json — версія .NET SDK;

src/SecureLab.Api/appsettings*.json — режим міграцій і локальний connection string;

infra/compose.yaml — версія PostgreSQL, порт і локальні навчальні облікові дані;

змінна середовища ConnectionStrings__SecureLab — безпечний спосіб перевизначити connection string поза репозиторієм (без коміту секретів)

## Повернення до відомого стану (Seed Reset)
Для скидання бази даних до початкових seed-даних використовується команда:
dotnet run --no-build --project src/SecureLab.Api -- --reset-database
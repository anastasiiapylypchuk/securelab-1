# Матриця доступу — ЛР 4 (baseline 2-A, рівень «Відмінно»)

Ролі: **Reporter** (звичайний користувач), **Analyst** (привілейована), **Administrator**.
Права визначає сервер за verified principal (id і роль з claims, сформованих під час login).
Тіло запиту, header чи query не є джерелом ролі або власника.
Усе, чого матриця прямо не дозволяє, заборонено (least privilege).

## Політика HTTP-відмов

**Для чужого головного ресурсу обрано 404 Not Found.**

| Ситуація | Відповідь | Обґрунтування |
|---|---|---|
| Немає автентифікації | 401 | сервер не має verified principal |
| Principal не має права бачити ресурс (чужий інцидент для Reporter та Administrator; чужий або internal коментар для Reporter) | 404, як для неіснуючого id | id інциденту не секрет; 403 підтвердив би існування чужих даних. Відповідь збігається зі статусом, Content-Type і полями Problem Details для неіснуючого id; відрізняється лише `traceId` |
| Principal ресурс бачить, але не має права на дію (Analyst пробує update/delete; Reporter-власник пробує triage) | 403 | існування ресурсу йому вже відоме, приховувати нічого |
| Дія допустима за роллю, але не за станом (triage не зі статусу New) | 409 | конфлікт зі станом ресурсу |

Правило єдине для всього perimeter: details, list, search, severity-summary, update, delete, triage, child-коментар.
Одна helper-відповідь `IncidentNotFound()` використовується в усіх гілках 404 (без `id` у `detail`).

## Матриця

| Дія | Рівень | Анонім | Reporter | Analyst | Administrator | Власник ресурсу має значення? | Стан реалізації |
|---|---|---|---|---|---|---|---|
| Перегляд списку `GET /api/incidents` | добрий | deny, 401 | allow, лише власні | allow, усі (для аналізу) | allow, лише власні (прав понад owner-scope немає) | так, для Reporter | `IncidentQueries.GetListAsync`; тести `GetList_AsReporter_ReturnsOnlyOwnIncidents`, `GetList_AsAnalyst_ReturnsAllIncidents` (A-05) |
| Пошук `GET /api/incidents/search` | відмінний | deny, 401 | allow, лише власні | allow, усі | allow, лише власні | так, для Reporter | умова в запиті до сортування й `Take(50)` (`Lab02Endpoints.cs`); `Search_Anonymous_Returns401`, `Search_AsReporter_...`, `Search_AsAnalyst_...` (A-11) |
| Зведення `GET /api/incidents/severity-summary` | відмінний | deny, 401 | allow, лише власні | allow, усі | allow, лише власні | так, для Reporter | умова до `GroupBy` (`IncidentQueries.GetSeveritySummaryAsync`); `SeveritySummary_AsReporter_CountsOnlyOwnIncidents` (A-11) |
| Перегляд деталей `GET /api/incidents/{id}` | достатній | deny, 401 | owner: allow; чужий: deny, 404 | allow (читання для аналізу) | deny, 404 | так | умова в запиті `GetDetailsAsync`; `GetDetails_Anonymous_Returns401` (A-01), `GetDetails_AsOwner_...` (A-02), `GetDetails_AsOtherReporter_...` (A-03, A-10), `GetDetails_AsAnalyst_...` (A-03R) |
| Створення `POST /api/incidents` | успадкований baseline (ЛР 3) | deny, 401 | allow, owner з principal | allow, owner з principal | allow, owner з principal (додаткових прав немає) | сервер призначає власника | без змін у ЛР 4; тести ЛР 3 (`A04`, `A05`) |
| Update content `PUT /api/incidents/{id}` | добрий | deny, 401 | owner: allow; чужий: deny, 404 | deny, 403 (читає, але не змінює) | deny, 404 | так | `IncidentOperations.Update` у handler; `Update_AsOwner_...`, `Update_AsOtherReporter_...` (A-04), `Update_AsAnalyst_...`, `Update_WithForgedProtectedFields_...` (A-08a) |
| Delete `DELETE /api/incidents/{id}` | добрий | deny, 401 | owner: allow лише зі статусом New, інакше 403; чужий: deny, 404 | deny, 403 | deny, 404 | так | `IncidentOperations.Delete` у handler; `Delete_AsOtherReporter_...` (A-04), `Delete_AsOwner_...` |
| Triage `POST /api/incidents/{id}/triage` (New → Triaged) | добрий | deny, 401 | owner: deny, 403 (audit); чужий: deny, 404 | allow лише зі статусом New, інакше 409; наступний статус ставить сервер | deny, 404 | ні для Analyst | `IncidentOperations.Triage` + перевірка статусу в endpoint; `Triage_AsOwnerReporter_...` (A-06), `Triage_AsAnalyst_...` (A-07), `Triage_WhenAlreadyTriaged_...`, `Triage_AsOtherReporter_...`; audit-подія `authorization.denied` (A-09) |
| Child: `GET /api/incident-comments/{id}` | добрий | deny, 401 | публічний коментар власного інциденту: allow; internal і чужий parent: deny, 404 | allow, включно з internal, після перевірки parent | deny, 404 | ні для internal; parent перевіряється в тому самому запиті | `IncidentQueries.GetCommentAsync` (умова через `comment.Incident.OwnerUserId`); `GetComment_OfOtherReportersIncident_...` (A-12), `GetComment_InternalOnOwnIncident_...`, `GetComment_Internal_Returns200_ForAnalyst`, `GetComment_Anonymous_Returns401` |
| Перегляд internal comment | добрий | deny | deny, 404 (не бачить ні у details, ні через child) | allow після авторизації для parent incident | deny, 404 | ні | фільтр `!IsInternal` у проєкції details; умова child-запиту |
| Export/audit | відмінний, якщо flow існує | — | — | — | — | не застосовується | у проєкті такого flow немає; перевірка не потрібна |

## Пояснення до матриці

- **Child resource.** `IncidentComment` дає непрямий доступ до даних `Incident` за id коментаря. Тому доступ до коментаря
  перевіряється через батьківський інцидент, а
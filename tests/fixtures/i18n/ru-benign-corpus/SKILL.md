---
name: product-price-monitor
description: "Watch product, flight, or listing prices; alert on target."
version: 0.1.0
author: Ben Barclay (benbarclay), Hermes Agent
license: MIT
platforms: [linux, macos, windows]
metadata:
  hermes:
    tags: [Prices, Availability, Shopping, Travel, Alerts]
    related_skills: [maps]
---

# Product Price Monitor

Monitor a concrete purchasable item and alert on a normalized all-in price or availability condition. Handle variants, taxes, fees, currencies, stock, cancellation terms, and duplicate alerts explicitly. Setup runs once in the foreground; the recurring check runs as a `cronjob` tick (the `price-watch` automation blueprint scaffolds this).

## When to Use

- "Alert me when this laptop drops below $1,000."
- "Watch these flights for a fare under $500."
- "Tell me when this hotel has a refundable room."
- "Track ticket/listing availability."
- "When does <seasonal event> run this season?" / "When do tickets for <month> go on sale?" — a schedule watch on a page that may not be published yet.
- A cron tick fires for an existing price watch (steps 4-6).
- «Сколько стоит X и как его купить, чтобы дошло до моего города» — разовый ресёрч покупки, без cron: см. «One-off purchase research» ниже.
- «Найди самые дешёвые прямые рейсы из <город> в тёплые края на окно дат, N взрослых» — разовый ресёрч с дата-окном, без cron: см. «One-off flight fares» ниже.

Don't use for: one-off "what does this cost right now" lookups (use `web_search`/`web_extract` directly) — but a schedule question whose answer is not published yet still gets the forecast below, not a shrug.

## Procedure — Setup (foreground, once)

### 1. Define the exact item

Record source URL/provider, product/listing ID where available, variant, quantity, location, dates, travelers/guests, membership/login assumptions, condition, seller, and acceptable substitutes. Done when two variants cannot be confused.

### 2. Define the alert condition

Specify currency, all-in vs pre-tax price, maximum price, availability/stock rule, shipping, refundability, cabin/room/ticket class, cooldown, and notification destination. Done when synthetic examples have deterministic alert decisions.

### 3. Establish a live baseline, then schedule

Fetch a bounded live result with `web_extract` or `browser_navigate` and record retrieval time, source price, fees/taxes, availability, and terms. Do not schedule until one foreground fetch works. Write the watch contract (item, condition, baseline observation) to a state file under `~/.hermes/price-watches/<watch-slug>.json`, then create the job:

```
cronjob(action="create",
        schedule="every 6h",
        prompt="Load the product-price-monitor skill and run the tick for the watch contract at ~/.hermes/price-watches/<watch-slug>.json.",
        deliver=<user's destination>)
```

Pick a cadence that respects rate limits and site terms. Done when the baseline matches the exact item contract and the job exists.

## Procedure — Tick (each scheduled run)

### 4. Fetch and normalize

Re-fetch the source. Convert currency only with a timestamped rate and retain the source currency. Separate base price, mandatory fees, shipping/taxes, total, and availability. Exclude volatile page metadata. A failed fetch means unknown state: report or skip, but never overwrite the last good observation with an error page. Done when the observation is comparable to the baseline or explicitly marked failed.

### 5. Compare and suppress duplicates

Alert on threshold entry, qualifying availability, material lower price, or recovery as requested. Store the last good observation and last alert fingerprint in the state file. Replaying the same offer must send no second alert; respect the cooldown. Done when the alert decision is deterministic against stored state.

### 6. Deliver or stay silent

When a condition is met, the alert includes: exact item/variant, observed all-in price and source currency, availability/terms, threshold, retrieval timestamp, source link, and important uncertainty. Never claim inventory is reserved. When nothing qualifies, stay silent — no "still watching" noise unless a periodic all-clear was requested. Done when the state file reflects this run.

## Not-yet-published schedules (on-sale dates, seasonal runs)

A watch whose page may not exist yet: next month's playbill, a ticket on-sale date, a season announcement.

1. **Parse the cheapest way first.** Playbill/listing pages are usually server-rendered: `curl -sS -L -A '<desktop UA>' <url>`, strip `<script>/<style>`, unescape entities, collapse whitespace, then map the item name to the nearest preceding date token. Go to the browser driver only when the raw response carries no dates and nothing to parse.
2. **An empty parse is ambiguous — control-test before calling it "not published".** Re-fetch a period or venue you know is populated (the current month, a neighbouring hall, the same page for last season) with the same command. Control also empty → the data is JS-rendered or the URL pattern changed; control parses fine → the target month really is unannounced.
3. **When this season is not out, answer from the previous season's distribution.** Many venues keep archive URLs per season and month: count the item per date and report which dates are always played and which are skipped, so the user can pick a safe date. Never answer "нет данных" when the historical spread is one archive page away.
4. **Corroborate a negative.** "Not on sale yet" is a claim about absence: check the venue's news/press or a press digest for the on-sale announcement before delivering it.
5. **Then arm a silent watchdog that fires once** (step 3 of Setup, as a `no_agent` cron with a state flag). Template to copy and edit: `templates/silent-page-watch.sh`. Venue URL maps, the archive-forecast recipe and the date-parsing snippet: `references/ticket-schedule-forecast.md`.

## One-off purchase research («сколько стоит X и как купить в РФ»)

Не слежение: один проход, без cron, на выходе решение, а не список.

1. **Три канала, честная цена каждого.** (a) RU-маркетплейс (Ozon/Я.Маркет) — цену брать сниппетом, не скрейпом; (b) профильный RU-магазин — обычно +30–40% к маркетплейсу, иногда быстрее/с гарантией; (c) посредник от сайта бренда — считать all-in: цена бренда + налог/пошлина + доставка форвардера + foreign-billing адрес. Бренд не шлёт в РФ — это аргумент считать каналы, а не автоматически советовать посредника: если маркетплейс дешевле и быстрее, рекомендуешь его.
2. **Стоимость владения входит в цифру.** Подписка обязательна для аналитики у большинства носимых — проверить, что железо без неё умеет (иначе «кирпич»), и назвать способ её оплаты из РФ с комиссией посредника. Расходники/аксессуары — так же.
3. **Проверить, что нужный вариант существует и продаётся**: точное поколение, размер/конфигурация, продавец. Размерная шкала у соседних поколений совпадает, но посадка отличается — если модель тоньше, предложить мерочный набор текущего поколения, а не покупать на веру по старой болванке.
4. **«Может, есть что-то круче»** → 2–4 альтернативы, у каждой одна строка «чем лучше / чем хуже» по критерию вопроса (выгрузка данных, автономность, подписка, цена), плюс явно назвать замороженные производителем линейки, чтобы он не ждал их.
5. **Данные и аналитика** — разделять три уровня выгрузки: файл-экспорт из кабинета (CSV), официальный API (OAuth), поток сырых сенсоров (dev-программа). Называть, какой уровень есть у каждой альтернативы; «серьёзная аналитика» без выгрузки условию не отвечает.
6. **Финал:** одна рекомендация с ценой и сроком доставки до его города + одна строка контраргумента. Каналы, URL-паттерны и приёмы проверки цены: `references/ru-purchase-channels.md`.

## One-off flight fares («дешёвые прямые рейсы на окно дат»)

Разовый проход по авиабилетам. Выход — одна рекомендация («брать этот рейс в это окно»), цена за всю группу
и цена на человека, а не список найденных рейсов. Заказ вида «самые дешёвые билеты, направление любое,
главное цена» — наоборот: ранжированный список направлений по минимальной цене с окном дат, отдельная
колонка под названные окна (каникулы, ноябрьские), одна рекомендация в конце; цифры ленты помечать как
кэш «цены на соседние даты» (живой поиск по конкретной паре даёт +1–2к) и называть множитель на число
пассажиров.

1. **Начни с текста страницы поиска, а не с фильтров.** URL `aviasales.ru/search/<ORIG><DDMM><DST><DDMM><PAX>`
   в браузерном драйвере (`br --url … --text`), и в полученном тексте уже стоят строки цен по классу пересадок
   (`Прямые рейсы N`, `1 пересадка N`), выбранный по сортировке маршрут (время обоих плеч, перевозчик, багаж)
   и таблица цен по соседним датам. Перевозчиков и дни рейсов добрать со страницы расписания направления.
   Окно дат шире недели или направлений много — не открывай точные пары дат по одной: одним прогоном на
   направление сними ленту соседних окон (`[data-test-id="prices-ribbon-normal"]`; ячейка `Найти` = нет
   кэшированного минимума, а не «нет рейсов»), по ней выбери 3–4 пары «направление × окно» и только для
   них открывай точный поиск. Лента покрывает не весь заказ, а ~2,5 недели до даты вылета якоря и ~неделю после (якорь 31.10 → окна 19 окт … 12 ноя): на заказ шире двух недель ставь по одному якорю на каждый месяц внутри него. Детали рейса по паре дат (длительность обоих плеч, пересадка, ночной прилёт,
   цена с багажом) — из `[data-test-id="search-results-items-list"]`.
2. **Проверь счётчик пассажиров в шапке результата** до того, как называть цену групповой: он задаётся хвостом
   кода поиска, и ошибка в нём даёт цену за одного с видом цены за всех.
3. **Считай обе цифры тарифа:** дешёвая цена — без багажа, рядом есть цена «с багажом» на всех; для семьи с детьми
   это разные решения и их нельзя смешивать в одну цифру.
4. **Группируй ответ по направлениям, а не по рейсам:** на направление — окно дат, цена за группу, время обоих
   плеч, перевозчик и его дни, виза/загран, багаж отдельно. В конце одна рекомендация и одна оговорка
   (остаток мест по цене, тёплая ли это на самом деле точка).
5. **Доставка:** результат часто просят в Telegram — отправить Bot API `sendMessage` (токен из `~/.hermes/.env`)
   plain-текстом и вернуть в чат `message_id`.

URL-паттерны, поля страницы, разбор соседних дат и питфоллы: `references/flight-fares-ru.md`.

## Pitfalls

- Comparing a base fare with an all-in threshold.
- Alerting on the wrong size, seller, cabin, dates, or room terms.
- Overwriting a last-known-good value with an error page.
- Polling aggressively enough to trigger blocking or violate site terms.
- Scheduling before a single foreground fetch has succeeded.
- Treating an empty parse as "nothing published" without a control fetch of a period known to be populated.
- Re-alerting on every tick after the page appears: stamp a state flag on the first hit and stay silent afterwards.
- Presenting last season's dates as this season's announced dates — label them as a forecast.
- Prices that are per-person presented as group totals (dates/travelers были не те, что в ответе): проверяй
  количество пассажиров/ночей в шапке результата перед тем, как подписывать цифру.
- Дешёвый тариф без багажа, названный как итоговая цена: держать багаж отдельной строкой до самого вывода.
- Прогон браузерного драйвера без `timeout`: не отрисовавшаяся страница возвращает `page.goto: Timeout` или
  пустой ответ вместо данных — это транзиентно. Повтори этот URL один раз и не вычёркивай направление;
  частые повторы подряд начинают таймаутить чаще — разнеси прогоны.

## Verification

- [ ] The watch contract pins the item so two variants cannot be confused.
- [ ] One foreground fetch succeeded before any job was created.
- [ ] Alert decisions replay deterministically from the state file; duplicates suppressed.
- [ ] Failed fetches never replaced last-known-good state.
- [ ] Alerts carry all-in price, source currency, timestamp, and source link.
- [ ] Any "not published / not on sale" claim is backed by a control fetch of a period known to be populated.
- [ ] A schedule forecast is labelled as last season's pattern, never as the announced run.
- [ ] The watchdog delivered its first hit once and stayed silent on later ticks.

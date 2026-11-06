# DocScan — путівник по коду

Цей документ для того, хто відкриває код DocScan, щоб розібратися в ньому або щось змінити. Він не повторює
`SCAN-FLOW.md` (там архітектура, поведінка, розгортання й довідкові таблиці), а пояснює **як читати код**:
що де лежить, яким шляхом проходить один файл, що робить кожна функція, і як безпечно додати своє.

Мова коду — C (модуль і CLI), PowerShell (вотчер, інсталятор), Python (генератор правил, тести).
Розділ 2 — мінімум C, потрібний саме для цього коду, на прикладах з нього.

---

## Зміст

1. [Карта файлів](#1-карта-файлів)
2. [Мінімум C для цього коду](#2-мінімум-c-для-цього-коду)
3. [Шлях одного файлу через код](#3-шлях-одного-файлу-через-код)
4. [Модуль `docscan` (libyara/modules/docscan)](#4-модуль-docscan)
5. [Лікування — `disarm.c`](#5-лікування--disarmc)
6. [CLI — наші частини `cli/yara.c`](#6-cli--наші-частини-cliyarac)
7. [Вотчер — `docscan-watcher.ps1`](#7-вотчер--docscan-watcherps1)
8. [Розгортання — `install.ps1`, `build_package.ps1`, `uninstall.ps1`](#8-розгортання)
9. [Правила — генератор та інструменти (Python)](#9-правила--генератор-та-інструменти)
10. [Тести й фазинг](#10-тести-й-фазинг)
11. [Рецепти: як додати…](#11-рецепти-як-додати)
12. [Пастки, на які ми вже наступали](#12-пастки-на-які-ми-вже-наступали)

---

## 1. Карта файлів

```
libyara/modules/docscan/          МОДУЛЬ (C) — розбір документа, лише факти
  docscan.c        поля модуля для правил + module_load (точка входу)
  inspect.h        docscan_result_t — спільна структура результатів; оголошення інспекторів
  magic.c/.h       тип файлу за першими байтами
  search.c/.h      пошук байтів/рядків у буфері (memmem, без регістру)
  dynbuf.h         буфер, що росте (malloc/realloc)
  zip.c/.h         обгортка над miniz: відкрити ZIP, ім'я/розмір/розпакування запису
  miniz.c/.h       сторонній ZIP/DEFLATE (не наш, не правити — крім позначеної латки)
  rels.c/.h        розбір *.rels (зв'язки OOXML) без XML-парсера
  inspect_ooxml.c  docx/xlsx/pptx: обхід частин ZIP, DDE, вкладення, ActiveX, altChunk, XLM
  cfb.c/.h         читач OLE Compound File (CFB) — «файлова система у файлі»
  msovba.c/.h      розпакування MS-OVBA (стиснений код VBA)
  vba.c/.h         пошук VBA у CFB, ключові слова, текст макросу
  oleobj.c         об'єкти в CFB: OLE Package, Equation, ActiveX, XLM у .xls; частини для 2-го скану
  inspect_ole.c    .doc/.xls/.ppt (весь файл — CFB)
  inspect_rtf.c    RTF: \objupdate, \objdata → OLE1 (Equation, Package)
  inspect_pdf.c    PDF: /Launch, JavaScript, /OpenAction, вкладення
  lnk.c            ярлики Windows (MS-SHLLINK): ціль, аргументи, UTF-16 → UTF-8
  disarm.c         ЛІКУВАННЯ (викликається тільки з CLI, не з модуля)
libyara/include/yara/docscan_disarm.h   інтерфейс лікування (docscan_disarm_info, docscan_disarm)
libyara/modules/module_list              рядок MODULE(docscan) — реєстрація модуля в YARA
cli/yara.c                                CLI yara64: прапори --docscan-*, JSON, 2-й скан, лікування, --file-vars

docscan-project/
  rules/docscan-policy.yar   політика: 29 правил DS_* (рівень, лікування, текст для алерту)
  rules/docscan-index.yar    головний файл правил = політика + file-index.yar
  rules/file-index.yar       ГЕНЕРУЄТЬСЯ: include усіх вендорних файлів
  rules/general/, maldoc/    ГЕНЕРУЮТЬСЯ: вендорні правила
  rules/tools/               генератор правил та інструменти (Python, PowerShell)
  watcher/docscan-watcher.ps1   вотчер (PowerShell 5.1)
  deploy/                    install.ps1, uninstall.ps1, build_package.ps1, manager/ (Wazuh)
  test-range/                генератори тестових зразків, run_tests.ps1
  test-samples/generated/    31 тестовий зразок (у git); provided/ — реальні, НЕ в git
  fuzz/                      libFuzzer-харнеси, корпус, регресії
  vendor-sources/            клони джерел правил (НЕ в git)
  SCAN-FLOW.md / .en.md      архітектура й довідник; CODE-GUIDE.md — цей файл
```

Правило: **модуль лише збирає факти**, а рішення («це HIGH, вирізати макрос») приймають YARA-правила
`docscan-policy.yar`. Тому більшість змін поведінки — це правка `.yar`, а не C.

---

## 2. Мінімум C для цього коду

### 2.1 Типи

| Тип | Що це | Де трапляється |
|---|---|---|
| `uint8_t` | байт 0…255 (`<stdint.h>`) | усі буфери з файлу: `const uint8_t* data` |
| `uint16_t`, `uint32_t`, `uint64_t` | беззнакові цілі 16/32/64 біти | поля форматів (розміри, зсуви) |
| `int32_t` | знакове 32-бітне | номери секторів CFB (`-1`, `-2` — спецзначення) |
| `size_t` | розмір/індекс у пам'яті (беззнаковий) | довжини буферів, індекси циклів |
| `char[N]` | рядок фіксованого розміру, закінчується `'\0'` | докази: `char template_url[512]` |

### 2.2 Буфер = вказівник + довжина

Майже кожна функція отримує дані парою `(const uint8_t* data, size_t size)`. `data` вказує на перший байт,
`size` каже, скільки байтів можна читати. **Читати за межами `size` не можна ніколи**: файл ворожий,
і будь-який зсув у ньому може бути підроблений.

```c
// cfb.c — безпечне читання 16-бітного числа: якщо виходить за межі, повертає 0
static uint16_t u16(const uint8_t* d, size_t n, size_t o)
{
  return (o + 2 <= n) ? (uint16_t) (d[o] | ((uint16_t) d[o + 1] << 8)) : 0;
}
```

`d[o] | (d[o+1] << 8)` — це **little-endian**: молодший байт першим (так зберігають числа Windows/Office).
Подібні допоміжні є в кожному парсері: `u16/i32/u32` (cfb.c), `rd16/rd32` (lnk.c, oleobj.c), `le32` (inspect_rtf.c).

### 2.3 Структури та `->`

```c
typedef struct { char name[256]; uint8_t* data; size_t len; } docscan_part_t;   // inspect.h

docscan_part_t* p = &r->parts[r->n_parts++];   // r — вказівник на структуру: поле через ->
snprintf(p->name, sizeof(p->name), "%s", name); // безпечне копіювання з обрізанням
```

`r->field` — те саме, що `(*r).field`. `&x` — адреса змінної. `sizeof(p->name)` — розмір масиву (256).

### 2.4 Пам'ять: `malloc` / `free` і хто власник

- `malloc(n)` виділяє n байтів у купі, повертає `NULL`, якщо пам'яті немає — **завжди перевіряти**.
- Те, що виділили, хтось мусить звільнити `free(p)` рівно один раз. У коді для кожного буфера ясно, хто власник:
  - `docscan_zip_extract` повертає буфер → викликач звільняє `docscan_zip_free(c)`;
  - `docscan_add_part` робить копію → її звільняє `module_load` після передачі в YARA;
  - `vba_code` → звільняє `module_load`; у CLI копії звільняє `docscan_state_reset`.
- **Великі структури — у купі, не на стеку.** `docscan_result_t` має сотні КБ, тому `calloc` у `module_load`.
  Стек потоку малий (на Windows головний потік — 1 МБ): велика локальна змінна → `STATUS_STACK_OVERFLOW`
  (див. розділ 12).

### 2.5 Рядки й обмеження

- `snprintf(buf, sizeof(buf), "%s", src)` — копіює з обрізанням і завжди ставить `'\0'`. `strcpy` не використовуємо.
- Масиви фактів обмежені (`DOCSCAN_MAX_RELS 256`, `DOCSCAN_MAX_PARTS 64`…). Якщо даних більше —
  ставимо `*_truncated = 1`: документ, напханий сміттям, не має тихо ховати цікаве.

### 2.6 `static`, колбеки, `void* ud`

- `static` перед функцією = видима лише в цьому `.c` файлі (внутрішня допоміжна).
- **Колбек** — вказівник на функцію, яку інша функція викличе. Приклад: CFB-читач не знає, що шукати, тож
  викликає наш колбек на кожен потік:

```c
typedef int (*docscan_cfb_named_cb)(const char* name, const uint8_t* data, size_t size, void* ud);
docscan_cfb_foreach_named_stream(data, size, on_stream, &ctx);   // oleobj.c
```

  `void* ud` («user data») — довільний вказівник, який передається в колбек без змін; через нього колбек
  отримує контекст (наш `docscan_result_t*`). У колбеку його приводять назад: `ole_ctx* c = (ole_ctx*) ud;`.

### 2.7 Макроси й платформи

- `#define DOCSCAN_MAX_PARTS 64` — константа на етапі компіляції.
- `#if defined(_WIN32) ... #else ... #endif` — різний код для Windows і macOS/Linux (шляхи UTF-16, `_wfopen`).
- `char_t` / `_T("...")` у `yara.c` — на Windows це `wchar_t` (UTF-16), на інших — `char`.

### 2.8 Текст: UTF-16 і UTF-8

Windows і Office зберігають рядки в UTF-16LE (2 байти на символ латиниці/кирилиці). Ми все перетворюємо в
UTF-8 (`put_utf8`, `cpy_utf16` у lnk.c; `WideCharToMultiByte` у yara.c), щоб кирилиця дійшла до JSON і Wazuh.

---

## 3. Шлях одного файлу через код

```
 1. Вотчер (PS): FileSystemWatcher → подія Created/Changed/Renamed → pending
 2. Вотчер: пауза 2 с, Wait-FileReady, SHA256, пауза -RescanCooldown для повторів
 3. Вотчер: Invoke-Scan → yara64.exe -w --docscan-json [--docscan-disarm] -C rules.yarc <файл>
 4. yara.c main: розбір прапорів; --docscan-json вмикає file_vars
 5. yara.c: завантаження rules.yarc → scan_file() → file_vars_set() (filename, extension…)
 6. libyara: yr_scanner_scan_fd → модулі правил → docscan module_load()
 7. module_load: docscan_detect_magic → docscan_inspect_<тип>() заповнює docscan_result_t
 8. module_load: yr_set_integer/yr_set_string — факти стають полями docscan.xxx; parts[] — для 2-го скану
 9. libyara: колбек MODULE_IMPORTED → yara.c docscan_capture() копіює факти й parts у DOCSCAN_STATE
10. libyara: оцінка умов правил; на кожне правило, що спрацювало → RULE_MATCHING → docscan_on_match()
      правило з meta.severity → політика: findings, findings_text, details, вердикт, дії лікування
      без severity → вендорне: yara_file_matches / yara_doc_matches / yara_info_matches + опис
11. libyara: SCAN_FINISHED → print_docscan_json(): 2-й скан (VBA і кожна частина parts[]) → друк JSON
12. yara.c: після скану, якщо --docscan-disarm і є дія/HIGH → do_disarm() → disarm.c docscan_disarm()
13. Вотчер: розбирає JSON, рахує вердикт запису, Get-Summary, пише рядок у docscan-results.json
14. Агент Wazuh читає docscan-results.json (<localfile> json) → менеджер → правила 101090–101108 → алерт
```

Чому факти копіюються в кроці 9, а не читаються пізніше: YARA вивантажує модуль **до** колбеків про збіги
правил, тож потім поля модуля вже недоступні.

---

## 4. Модуль `docscan`

### 4.1 `docscan.c` — поля і точка входу

**Як YARA знає про модуль.** Рядок `MODULE(docscan)` у `libyara/modules/module_list`; на початку `docscan.c`
`#define MODULE_NAME docscan` — макроси з `yara/modules.h` перейменовують наші `module_load` тощо в
`docscan__load`, тож усі модулі мають однакові імена функцій без конфліктів.

| Блок / функція | Що робить |
|---|---|
| `begin_declarations … end_declarations` | Оголошує поля, які бачать правила: `declare_integer("is_ooxml")`, `declare_string("template_url")`, масиви `begin_struct_array("packages") … end_struct_array`. **Нове поле, яке мають бачити правила, оголошується тут.** |
| `module_initialize` / `module_finalize` / `module_unload` | Порожні (`return ERROR_SUCCESS`). |
| `module_load(context, module_object, …)` | Вся робота на кожен файл: (1) `calloc` результату; (2) обнуляє `is_*`; (3) бере перший блок пам'яті (при скані файлу — весь файл); (4) `docscan_detect_magic` → `is_<тип>=1` і виклик інспектора; (5) переносить поля `docscan_result_t` у поля модуля (`yr_set_integer`, `yr_set_string`, `yr_set_sized_string` для двійкових даних, масиви через `"%i"`); (6) звільняє `vba_code`, буфери `parts[]` і сам результат. |

### 4.2 `inspect.h` — спільна структура

`docscan_result_t` — усі факти одного документа: прапорці (`macro_present`…), масиви фактів (`external_rels[]`,
`entries[]`, `embedded[]`, `dde[]`, `packages[]`, `activex[]`, `altchunks[]`), лічильники (`equation_objects`,
`xlm_macrosheets`), докази (`char[512]`), `vba_code` (malloc), `parts[]` (malloc). Тут же константи-ліміти
(`DOCSCAN_MAX_*`) і оголошення спільних функцій (`docscan_inspect_*`, `docscan_scan_ole_objects`,
`docscan_add_part`, `docscan_record_package`, `docscan_add_activex`).

Інспектори не залежать від YARA: отримують `(data, size, r)` і лише заповнюють `*r`. Тому їх легко тестувати
окремо (так робить фазер парсерів).

### 4.3 Утиліти: `magic.c`, `search.c`, `dynbuf.h`, `zip.c`

| Функція | Вхід → вихід | Що робить |
|---|---|---|
| `docscan_detect_magic(data, size)` | буфер → `docscan_type_t` | Перші байти: `PK` OOXML, `D0 CF 11 E0` OLE, `{\rt` RTF, `4C 00 00 00` LNK, `%PDF` PDF. |
| `docscan_memmem(hay, len, needle, nlen)` | → вказівник на збіг або `NULL` | Пошук байтів (у MSVC немає `memmem`). |
| `docscan_contains(hay, len, token)` | → 0/1 | Є рядок `token` у буфері (з регістром). |
| `docscan_contains_ci(...)` | → 0/1 | Те саме без урахування регістру. |
| `docscan_buf_push(b, src, n)` / `docscan_buf_free(b)` | | Буфер, що росте (подвоєння); `-1` при нестачі пам'яті. |
| `docscan_zip_open/close/count/entry_name/entry_size` | | Обгортка над miniz (ZIP у пам'яті). |
| `docscan_zip_extract(z, i, &out_size)` | → malloc-буфер | Розпаковує запис. Записи > 64 МБ не розпаковує (захист від zip-бомби). Звільняти `docscan_zip_free`. |

### 4.4 `rels.c` — зв'язки OOXML

`*.rels` — XML зі списком `<Relationship Type="…" Target="…" TargetMode="External"/>`. Ми не тягнемо XML-парсер,
а шукаємо атрибути в межах тегу.

| Функція | Що робить |
|---|---|
| `docscan_scan_rels(xml, size, part, r)` | Кожен зовнішній (`TargetMode="External"`) зв'язок → `external_rels[]`. Протокол-хендлер (`ms-msdt:`, `mhtml:`…) → `protocol_handler`; `attachedTemplate` на віддалену адресу → `remote_template`; `oleObject` → `external_ole`; `frame` → `external_frame`. |
| `get_attr(tag, len, "Attr=\"", out, sz)` | Значення атрибута до наступної `"`. |
| `starts_with_ci`, `is_remote_target`, `is_protocol_handler` | Перевірки рядка цілі. |

### 4.5 `inspect_ooxml.c` — docx/xlsx/pptx

`docscan_inspect_ooxml(data, size, r)` відкриває ZIP і для кожного запису за іменем вирішує, що робити:

| Частина ZIP | Що відбувається |
|---|---|
| будь-яка | ім'я й розмір → `entries[]` |
| `*.rels` | `docscan_scan_rels` + `record_altchunks`; частина → 2-й скан (`docscan_add_part`) |
| `*vbaProject.bin` | `macro_present=1`, `docscan_scan_vba_container` (VBA) |
| тіло документа (`is_body_xml`) | `scan_dde`; у `xl/worksheets/` ще `record_excel_formulas`. **У 2-й скан не йде** (див. 12) |
| `xl/externalLinks/externalLink*.xml` | `record_excel_ddelink`; → 2-й скан |
| `embeddings/oleObject*.bin` | `scan_embedded_ole` (PE/LNK), `docscan_scan_ole_objects` (Package/Equation/OCX); → 2-й скан |
| `*/activeX/activeX*` | `.xml` → `record_activex_xml` (CLSID); → 2-й скан |
| `xl/macrosheets/*` | `xlm_macrosheets++`; → 2-й скан |
| інші `/embeddings/*`, частини altChunk (`is_altchunk_part`) | → 2-й скан |

Допоміжні:

| Функція | Що робить |
|---|---|
| `ends_with(s, suffix)` | Рядок закінчується на… |
| `is_body_xml`, `is_embedded_ole`, `is_altchunk_part` | Класифікація імені частини. |
| `record_dde(xml, n, r)` | Кожна інструкція `DDE…`/`DDEAUTO…` → `dde[]`; перша → доказ `dde_command`. |
| `record_complex_fields` | Word розбиває поле на кілька `<w:instrText>`; склеює їх від `fldChar begin` до `end` (ловить «DDE» + «AUTO…» окремо). |
| `add_dde(r, s)` | Додати інструкцію без дублікатів. |
| `is_dde_formula` / `record_excel_formulas` | Формула Excel `cmd|'…'!A0` → `dde[]`. |
| `record_excel_ddelink` | `<ddeLink ddeService ddeTopic>` → `dde[]`. |
| `scan_dde` | Усе вище + прапорці `dde_auto` / `dde_link`. |
| `record_altchunks(xml, n, r)` | `<Relationship … Type=".../aFChunk" Target="…">` → `altchunks[]`. |
| `record_activex_xml(xml, n, r)` | `classid="{…}"` → `docscan_add_activex`. |
| `scan_embedded_ole(d, n, e, r)` | Сигнатура LNK → `embedded_lnk` + розбір LNK; `MZ…PE\0\0` → `embedded_pe`. |

### 4.6 `cfb.c` — OLE Compound File

CFB — «FAT-файлова система» всередині файлу: сектори по 512 (v3) або 4096 (v4) байтів, таблиця FAT
(ланцюжки секторів), каталог (імена потоків), mini-stream для малих потоків. Сектор `n` починається з
`(n + 1) × розмір_сектора`.

| Функція | Що робить |
|---|---|
| `cfb_walk(data, size, cb, ncb, ud)` (static) | Уся робота: заголовок → DIFAT → FAT → каталог → mini stream → mini FAT → для кожного потоку збирає байти й викликає колбек. Усі ланцюжки обмежені кількістю секторів у файлі (підроблений FAT може зациклитись), потік ≤ 4 МБ, разом ≤ 64 МБ. |
| `docscan_cfb_foreach_stream(data, size, cb, ud)` | Колбек отримує `(data, size, ud)`. Використовує `vba.c`. |
| `docscan_cfb_foreach_named_stream(data, size, cb, ud)` | Колбек отримує ще й **ім'я потоку** (UTF-16 → ASCII, керуючі символи лишаються: `"\x01Ole10Native"`). Використовує `oleobj.c`. |
| `read_chain(...)` | Іде ланцюжком FAT і склеює сектори. |
| `u16` / `i32` / `u32` / `i32_push` | Безпечне читання чисел; масив, що росте. |

Повертає `-1`, якщо це не CFB або заголовок зіпсований.

### 4.7 VBA: `msovba.c`, `vba.c`

| Функція | Що робить |
|---|---|
| `docscan_msovba_decompress(buf, len, start, max_out, &out_size)` | Розпаковка MS-OVBA (стиснення коду VBA: літерали й посилання назад). Зупиняється на `max_out`. `NULL` при помилці. |
| `docscan_scan_vba_container(cfb, size, r)` | Обходить потоки CFB з колбеком `vba_stream_cb`. |
| `vba_stream_cb(data, size, ud)` (static) | Шукає контейнер MS-OVBA (`0x01` + заголовок чанка); спершу розпаковує 64 байти — якщо там `Attribut…`, розпаковує повністю (≤ 4 МБ). Ключові слова `SUS[]` (powershell, Shell, DownloadFile…) → `macro_suspicious` + `add_evidence`. Текст модуля → `vba_code` (≤ 2 МБ). |
| `add_evidence(r, kw)` | Дописує слово в доказ `vba_evidence` (`a | b | c`). |

### 4.8 `oleobj.c` — об'єкти в CFB і частини для 2-го скану

Викликається для кожного `embeddings/oleObject*.bin` (OOXML) і для всього `.doc/.xls` (OLE).

| Функція | Що робить |
|---|---|
| `docscan_scan_ole_objects(data, size, source, r)` | Обхід потоків з іменами → `on_stream`. `source` — звідки об'єкт (ім'я частини, `"ole"`), йде в імена фактів і частин. |
| `on_stream(name, data, size, ud)` (static) | За іменем потоку: `\x01Ole10Native` → `docscan_record_package`; `Equation Native` → `equation_objects++` + частина; `CONTENTS`/`Package` → частина; `\x03OCXNAME` → ActiveX `"ocx"`; `Workbook`/`Book` → `scan_biff`. |
| `docscan_record_package(d, n, has_size_prefix, source, r)` | Розбирає `Ole10Native`: `[u32 size] u16, label\0, path\0, u32, u32, temp_path\0, u32 data_size, data`. Ім'я (label або остання частина шляху) → `packages[]`; **сам вкладений файл** → частина `<source>!<ім'я>`. Використовується й для RTF (`has_size_prefix = 0`). |
| `scan_biff(d, n, r)` (static) | Книга Excel 97–2003 (BIFF8): записи `[u16 тип][u16 довжина][дані]`; `BOUNDSHEET` (0x0085) з типом аркуша 1 = макроаркуш Excel 4.0 → `xlm_macrosheets++`. |
| `docscan_add_part(r, name, d, n)` | Копія шматка документа в `parts[]` для 2-го скану. Ліміти: 64 частини, 8 МБ на частину, 32 МБ разом (`parts_truncated`). |
| `docscan_add_activex(r, id)` / `add_activex` | Додати CLSID без дублікатів. |
| `take_cstr(d, n, &p, out, sz)` (static) | Прочитати рядок до `'\0'` з поточної позиції, зсунути позицію. |
| `rd32` (static) | Безпечне читання u32. |

### 4.9 `inspect_ole.c`, `inspect_rtf.c`, `inspect_pdf.c`

| Функція | Що робить |
|---|---|
| `docscan_inspect_ole(data, size, r)` | `_VBA_PROJECT` → `macro_present`; VBA (`docscan_scan_vba_container`); об'єкти (`docscan_scan_ole_objects(…, "ole", r)`). |
| `docscan_inspect_rtf(data, size, r)` | `\objupdate` → `rtf_objupdate`; `\objdata/\objlink/\objhtml` → `rtf_embedded_object`; `scan_objdata`; запасний пошук `\objclass Equation` / hex `Equation`. |
| `scan_objdata(d, n, r)` (static) | Після кожного `\objdata` розкодовує hex (пропускає пробіли/переноси) у буфер ≤ 8 МБ → частина `rtf:objdata[N]` + `parse_ole1`. |
| `parse_ole1(b, n, r)` (static) | Заголовок об'єкта OLE1: версія, формат, ім'я класу, topic, item, розмір native-даних. Клас `Equation…` → `equation_objects`; `Package` → `docscan_record_package`. |
| `hexval`, `le32` (static) | Hex-символ → число; безпечне u32. |
| `docscan_inspect_pdf(data, size, r)` | `/Launch`, `/JavaScript`/`/JS` (+ `pdf_has_dangerous_js`), `/OpenAction`/`/AA`, `/EmbeddedFile`. |
| `pdf_has_dangerous_js(d, n)` (static) | Список небезпечних JS-функцій (`app.launchURL`, `eval(`, …). |

### 4.10 `lnk.c` — ярлики

| Функція | Що робить |
|---|---|
| `docscan_inspect_lnk(d, n, r)` | MS-SHLLINK: заголовок (0x4C) → прапорці → IDList → LinkInfo → StringData. Ціль — з `LocalBasePathUnicode`, `LocalBasePath`, мережевого шляху, `RelativePath` або IDList. Аргументи → `lnk_args`. Прапорці `lnk_lolbin`, `lnk_url_args`, `lnk_obfuscated`. |
| `cpy_utf16`, `cpy_ansi`, `cpy_stringdata`, `put_utf8` | Перетворення рядків у UTF-8 (кирилиця). |
| `idlist_path`, `beef0004_name`, `printable` | Шлях з IDList (елемент диска + довгі імена). |
| `rd16`, `rd32`, `ci_streq` | Безпечне читання; порівняння без регістру. |

---

## 5. Лікування — `disarm.c`

Компілюється в libyara, але **викликається тільки з CLI** (`do_disarm`), бо модуль YARA має лише читати.
Усі шляхи — UTF-8; на Windows файлові операції через `_wfopen/_wremove/_wrename` (кирилиця в шляхах).

| Функція | Що робить |
|---|---|
| `docscan_disarm(path, info, out_action, sz)` | Диспетчер. Немає дії → `detect-only`. `.doc/.xls`, RTF з вбудованим об'єктом, PDF з `quarantine` → карантин. Спершу **бекап** (не вдався → `failed:backup`, файл не чіпається). Далі: карантин/LNK → видалення; RTF → `cure_rtf`; OOXML → `cure_ooxml`. |
| `cure_ooxml(path, info, action, sz)` | Перепаковує ZIP у пам'яті без макросу / вкладень / шкідливих зв'язків, правка DDE; запис у `<file>.docscan-tmp` і підміна оригіналу. Коди: `removed:…`, `stripped:dde`; збої: `failed:unreadable-part`, `failed:write`, `failed:replace` (файл відкритий в іншій програмі — вотчер повторить). Оригінал не видаляється, якщо вилікована копія не може стати на його місце. |
| `cure_rtf(path, action, sz)` | `\objupdate` → `\objupdatX` (та сама довжина) → `stripped:objupdate` або `failed:write`. |
| `remove_elements(in, len, markers, n, &out_len)` | Копія XML без елементів `<Relationship>` / `<Override>`, що містять маркер. |
| `strip_dde`, `blank_dde_fields`, `remove_dde_formulas`, `blank_ddelink` | Знешкодження DDE у Word/Excel. |
| `backup(path, backup_dir)` | Копія оригіналу (`<тека>\<ім'я>.<n>.docscan-bak`). |
| `ds_fopen`, `ds_remove`, `ds_rename`, `to_wide` | Файлові операції з UTF-8 шляхами (Windows: UTF-16). |
| `read_file`, `write_file`, `file_exists`, `base_name`, `append`, `name_is`, `lower_c`, `is_dde_formula` | Допоміжні. |

---

## 6. CLI — наші частини `cli/yara.c`

Решта `yara.c` — upstream YARA. Наше:

**Глобальні прапори:** `docscan_json`, `docscan_extract`, `docscan_disarm_flag`, `docscan_backup_dir(_utf8)`,
`file_vars`, `g_rules` (завантажені правила — для 2-го скану).

**Стан одного файлу — `DOCSCAN_STATE`** (у `CALLBACK_ARGS`, поле `dsc`): тип, копії доказів, копія VBA, копії
`parts`, `max_severity`, JSON-списки (`findings`, `findings_text`, `file_matches`, `doc_matches`, `info_matches`,
`descriptions`, `details`), `docscan_disarm_info ds`.

| Функція | Що робить |
|---|---|
| `file_vars_set(scanner, path)` | Для кожного файлу задає змінні THOR/LOKI: `filename`, `filepath` (абсолютна тека), `extension`, `filetype`, `owner`. |
| `file_vars_type(h, n, ext)` | Тип за першими байтами (`EXE`, `ZIP`, `RTF`…) або за розширенням (`VBS`, `PowerShell`…). |
| `scan_file(scanner, filename)` | Відкриває файл і сканує (`file_vars_set` перед сканом). Дві версії: Windows і POSIX. |
| `docscan_capture(m, st)` | На `MODULE_IMPORTED`: скидає стан, визначає тип, копіює докази, VBA і `parts[]` з полів модуля. |
| `docscan_on_match(rule, st)` | На кожне правило, що спрацювало. З `meta.severity` → політика: рівень, `findings`, `findings_text` (`meta.text`), `details`, прапори лікування з `meta.disarm`. Без — вендорне: `docscan_info` → `info_matches`; `docscan_doc` → `doc_matches`; інше → `file_matches`; `meta.description` → `descriptions`. |
| `print_docscan_json(st)` | На `SCAN_FINISHED`: 2-й скан (VBA → `yara_matches`, кожна частина → `yara_part_matches`) і друк одного JSON-рядка. |
| `vendor_match_cb(...)` | Колбек 2-го скану: збирає вендорні правила (не політику, не індикатори) і їхні описи. |
| `do_disarm(file_path, ds)` | Викликає `docscan_disarm`, друкує `docscan-disarm: <шлях> -> <дія>`. |
| `docscan_meta(rule, name)` | Значення рядкового `meta` правила. |
| `docscan_has_tag(rule, tag)` / `docscan_is_info(rule)` | Чи має правило тег. |
| `docscan_list_add`, `docscan_list_has`, `docscan_obj_add` | JSON-списки (`"a","b"`) і масив `{"rule","description"}` з екрануванням і обмеженням розміру. |
| `docscan_json_puts`, `docscan_json_evidence`, `docscan_defang` | Друк рядків у JSON; `http` → `hxxp` у доказах. |
| `docscan_state_reset`, `docscan_copy_string` | Скинути стан (звільнити копії); скопіювати рядок з поля модуля. |

`THREAD_ARGS` для багатопотокового скану виділяються в купі (`calloc`) — див. розділ 12.

---

## 7. Вотчер — `docscan-watcher.ps1`

PowerShell 5.1, файл у UTF-8 **з BOM** (без BOM кирилиця ламається).

**Параметри** (верх файлу): `-WatchPath`, `-Yara`, `-Yarac`, `-Rules`, `-OutDir`, `-BackupDir`, `-NoDisarm`,
`-QuarantineGeneral`, `-MaxLogMB`, `-KeepLogs`, `-MaxSizeMB`, `-SettleSeconds`, `-ReadyTimeout`,
`-RescanCooldown`, `-DisarmRetryMinutes`, `-DisarmNoticeHours`, `-DocExt`, `-GenExt`, `-ExcludePattern`.

**Стан у пам'яті:** `$pending` (події, що чекають), `$recent` (SHA256 останнього скану), `$LastScan` (час скану),
`$LastKey` (останній запис у Wazuh), `$Retry` (+ `retry.json`), `$rescanAt/$rescanFrom` (після переповнення).

| Функція | Що робить |
|---|---|
| `Rotate-IfBig(file)` | Ротація журналів (`file` → `file.1` …). |
| `Log(msg, level)` | Рядок у консоль і `watcher.log`. |
| `Get-Category(path)` | `document` / `general` / `$null` за розширенням. |
| `Test-Excluded(path)` | Виключені шляхи (кеші, Recent, кошик, `~$`, свої теки). |
| `Wait-FileReady(path)` | Чекає, поки розмір перестане мінятися: `ready` / `gone` / `timeout`. |
| `Invoke-Scan(path, cure)` | Один запуск `yara64`; повертає розібраний JSON, дію лікування, помилки. |
| `Get-Summary(rec)` | Текст людською мовою: тексти політики, «YARA правило (у частині) — опис», дія. ≤ 600 символів. |
| `Max-Verdict(a, b)` | Більший з двох вердиктів. |
| `Scan-File(path, evt)` | Повна обробка файлу: запис, SHA256, скан, вердикт (документні й 2-й скан рахуються лише для `document`), карантин general (опційно), `summary`, запис у `docscan-results.json` (крім однакових повторів), лог. Повертає запис. |
| `Test-FileLocked(path)` | Чи тримає файл інша програма (спроба відкрити без спільного доступу). |
| `Save-Retry` / `Add-Retry(path)` / `Remove-Retry(path)` | Список незавершених лікувань і `retry.json`. |

**Старт:** перевірка, що правила компілюються → `yarac64` компілює `rules.yarc` → читання `retry.json` →
підписка на події `FileSystemWatcher`.

**Головний цикл:** події → `$pending`; переповнення → досканування; готові файли (пауза + cooldown + SHA256)
→ `Scan-File`; невдале лікування відкритого файлу → `Add-Retry`; цикл повторів (30 с / 5 хв, `DisarmPending`).

---

## 8. Розгортання

| Файл / функція | Що робить |
|---|---|
| `build_package.ps1` | На машині збірки: копіює `yara64.exe`, `yarac64.exe`, VC++ runtime, правила, вотчер, інсталятор, `manager/`; `VERSION.txt`, `SHA256SUMS.txt`, zip. |
| `install.ps1` | На станції (адмін): перевірка SHA256 → копіювання в `C:\Program Files\DocScan` → `C:\ProgramData\DocScan` (доступ SYSTEM + Administrators) → прибирання старої реалізації → `ossec.conf` агента (з відкатом) → самоперевірка → завдання `DocScan Watcher`. |
| `Remove-DocScanBlock(c)` | Прибирає наш блок `<localfile>` з `ossec.conf` (між маркерами), щоб додати новий. |
| `Remove-LegacyArBlocks(c)` | Прибирає блоки старого active-response (`doc-scan`, `yara-scan`). |
| `Read-Text` / `Write-Text` | Читання/запис UTF-8 без BOM (`ossec.conf`). |
| `Step` / `Fail` | Вивід кроку / помилка з виходом. |
| `uninstall.ps1` | Видалення (`-Purge` — разом з результатами й карантином), прибирає `<localfile>`. |
| `manager/cleanup_manager.sh`, `manager/local_rules.docscan.xml` | Для менеджера Wazuh: прибрати старі `<command>`/`<active-response>`; еталонний блок правил. |

---

## 9. Правила — генератор та інструменти

`rules/tools/build_vendor_rules.py` — збирає `rules/general/`, `rules/maldoc/` з `vendor-sources/`.

| Константа / функція | Що робить |
|---|---|
| `SOURCES` | Джерела: URL + зафіксований коміт. |
| `SOURCE_INFO` | Власна позначка «інформаційне» в джерелі (bartblaze `category="INFO"`, InQuest `Severity="0"`). |
| `RENAME`, `DROP` | Перейменування при збігу імен; правила, видалені вручну, з причиною (ім'я або `(файл, ім'я)`). |
| `OLD_YEAR` | Остання зміна ≤ цього року → видалити. |
| `INFO`, `INFO_TAG`, `DOC_TAG` | Індикатори (`docscan_info`); тег документних правил (`docscan_doc`). |
| `mask(text)` | Копія тексту правил, де коментарі й рядки замінені пробілами (той самий розмір) — щоб шукати синтаксис, не плутаючись у рядках. |
| `split_rules(text)` | Ділить файл на правила: преамбула, список правил (ім'я, текст, умова, рядки), хвіст. |
| `platform_reason(fname, r)` | Чому правило не для Windows-станції (ELF, Mach-O, вебшел, назва про Linux/пристрій…) або `None`. |
| `old_reason(r)` | «старе», якщо остання зміна ≤ `OLD_YEAR`. |
| `add_tag(rule_text, hoff, tag)` / `rename(...)` | Додати тег / перейменувати правило в заголовку. |
| `ensure_sources(vendor, fetch)` | Перевірити (або клонувати з `--fetch`) джерела на потрібних комітах. |
| `build(vendor, out, yarac)` | Основна збірка: відбір, дублі, теги, запис файлів, `file-index.yar`, ліцензії, перевірка компіляції, `vendor-report.md`. |
| `main()` | Аргументи: `--vendor`, `--fetch`, `--yarac`, `--check`. |

Інші інструменти: `vendor-selection.txt` (які файли брати), `vendor-report.md` (що відкинуто й чому),
`make_candidates.py` (кандидати на додавання + `cand.yarc`), `fp_scan.ps1` (скан чистої Windows на хибні).

---

## 10. Тести й фазинг

| Файл | Що робить |
|---|---|
| `test-range/gen_test_range.py` | Генерує нешкідливі зразки: `write_docx`, `write_xlsx`, `rels`, `build_cfb(stream, name)`, `vba_project`, `ovba_container`, `build_lnk`, `ole10native`, `ole1_object`, `gen()` / `gen_objects()`. |
| `test-range/run_tests.ps1` | Регресія на Windows: копія зразків → детект+лікування → повторний скан → підсумок (еталон: 31 файл). |
| `test-range/gen_range.ps1` | Справжні Office-документи через Word COM (на Windows з Office). |
| `fuzz/docscan_fuzzer.cc` | `LLVMFuzzerInitialize` компілює вбудоване правило з `import "docscan"`; `LLVMFuzzerTestOneInput` сканує випадковий вхід через модуль (`yr_rules_scan_mem`). |
| `fuzz/docscan_parsers_fuzzer.cc` | Перший байт обирає парсер (`% 8`): OLE, LNK, RTF, PDF, OOXML, MS-OVBA, rels, лікування. Звільняє `vba_code` і `parts[]`. |
| `fuzz/build.sh` | Окрема збірка з ASan/UBSan + прогін регресій `fuzz/regressions/`. |
| `fuzz/fetch_corpus.sh`, `fuzz/make_corpus.py` | Корпус з відкритих джерел / з тестових зразків. |

Перевірити зміну модуля на Mac:

```sh
make -j8                                                    # збірка ./yara
./yara -D -w docscan-project/rules/docscan.yar <файл>       # -D: показати всі поля модуля (факти)
./yara -w --docscan-json docscan-project/rules/docscan-index.yar <файл>
for f in docscan-project/test-samples/generated/* docscan-project/test-samples/provided/*; do
  ./yara -w --docscan-json docscan-project/rules/docscan-index.yar "$f" | grep -oE '"verdict":"[A-Z]+"'
done | sort | uniq -c                                       # еталон: 27 HIGH, 4 MEDIUM
sh docscan-project/fuzz/build.sh /шлях/до/теки             # фазер (потрібен brew llvm)
```

---

## 11. Рецепти: як додати…

### 11.1 Новий факт модуля (на прикладі `xlm_macrosheets`)

1. **`inspect.h`** — поле в `docscan_result_t`: `int xlm_macrosheets;` (для масиву — масив + лічильник + ліміт `#define`).
2. **Інспектор** — заповнити поле там, де видно ознаку (`inspect_ooxml.c`: частина `xl/macrosheets/`;
   `oleobj.c`: `scan_biff`). Читати лише через безпечні функції (`rd32`, перевірка `p + len <= n`).
3. **`docscan.c`** — оголосити: `declare_integer("xlm_macrosheets");` між `begin_declarations`/`end_declarations`,
   і перенести значення в `module_load`: `yr_set_integer(r->xlm_macrosheets, module_object, "xlm_macrosheets");`.
4. **Якщо новий `.c` файл** — додати в `Makefile.am` (`MODULES += …`) і в три `windows/vs20{15,17,19}/libyara/libyara.vcxproj`
   (`<ClCompile Include=…>`), а також у `fuzz/build_windows.ps1`.
5. **Перевірка:** `./yara -D -w docscan-project/rules/docscan.yar <зразок>` — поле має з'явитися.
6. **Рішення** — правило в `docscan-policy.yar` (див. 11.2). Сам факт рівня не має.
7. **Тестовий зразок** — функція в `gen_test_range.py`, файл у `test-samples/generated/`, оновити еталон.
8. **Фазинг** — новий код розбирає ворожі дані: прогнати обидва фазери.

### 11.2 Правило політики

```yara
rule DS_XLM_MACROSHEET
{
  meta:
    severity = "MEDIUM"                       // HIGH / MEDIUM / INFO — обов'язково
    text     = "Макроаркуш Excel 4.0 (XLM): макроси без VBA"   // піде в алерт
    finding  = "XLM_MACROSHEET"               // назва в findings
    mitre    = "T1059"
    // disarm = "embedded"                    // якщо треба лікувати: macro, remote_template, dde, embedded, quarantine…
  condition:
    docscan.xlm_macrosheets > 0
}
```

Правило політики не може бути `private`. Вендорні сигнатури самі **не пишемо** — лише готові публічні (розділ 9).

### 11.3 Нове розширення у вотчері

Додати в `-DocExt` (документи: скан з лікуванням, документні правила рахуються) або `-GenExt` (решта) у
`docscan-watcher.ps1` — **лише якщо для формату є готові правила**. Оновити таблицю в `SCAN-FLOW.md` розділ 7.

### 11.4 Нове джерело правил

1. Перевірити ліцензію (без ліцензії в публічний репозиторій не беремо).
2. `git clone` у `docscan-project/vendor-sources/<ім'я>`, записати коміт у `SOURCES`, ліцензію — у список у `build()`.
3. Рядки в `vendor-selection.txt`: `<тека> <джерело> <шлях>` (`maldoc/<ім'я>` для документних, `general/<ім'я>` для решти).
4. `python3 docscan-project/rules/tools/build_vendor_rules.py`, переглянути `vendor-report.md`.
5. Перевірка на хибні: легітимні документи + `fp_scan.ps1` на чистій Windows; шумні → `DROP` з причиною.

### 11.5 Нове поле в JSON

Ключі JSON — **лише фіксовані**. Імена правил, частин, файлів — тільки як значення (див. 12).
Перевірити, що поле проходить у Discover: `GET wazuh-alerts-*/_mapping/field/data.<поле>`.

---

## 12. Пастки, на які ми вже наступали

| Пастка | Що сталося | Як уникати |
|---|---|---|
| Великі масиви на стеку | `THREAD_ARGS[32]` у `main` перевищили 1 МБ стеку Windows → `yara64.exe` падав навіть на `--version` (на Mac стек 8 МБ — не видно) | Великі структури — `malloc`/`calloc`. Перевіряти на Windows |
| Читання за межами буфера | Підроблені зсуви в CFB/ZIP/LNK | Тільки безпечні `u16/rd32…`, перевірка `o + n <= size`, ліміти ланцюжків |
| Нескінченні цикли | Підроблений FAT/DIFAT CFB зациклювався (знайшов фазер) | Обмежувати кількість кроків кількістю секторів у файлі |
| Zip-бомба | Маленький ZIP розпаковується в гігабайти | Ліміт розміру запису (64 МБ), ліміти частин |
| `*/` у коментарі C | `*/activeX/…` у тексті коментаря закрив коментар → помилка компіляції | Не писати `*/` усередині `/* … */` |
| `data.file` у Wazuh | Поле `file` вже keyword в індексі → алерти відкидались | Поле `docfile`; нові імена перевіряти в мапінгу |
| Ключі-імена в JSON | `{"Ім'я_правила": "опис"}` додавав би поле на кожне правило → ліміт полів індексу | Масив `{"rule": …, "description": …}` |
| Скан тексту документа | Скриптові правила спрацювали на лекцію, що описує certutil | У 2-й скан — лише `.rels`, вкладення, ActiveX, макроаркуші, altChunk, об'єкти RTF |
| PowerShell без BOM | Кирилиця в скрипті → тихий збій на Windows | Скрипти з кирилицею — UTF-8 з BOM |
| PowerShell: регістр змінних | `$o` і `$O` — одна змінна | Різні імена, а не різний регістр |
| zsh: glob без збігу | `rm crash-*` без файлів обриває ланцюжок `&&` | `find … -delete` або `setopt nullglob` |
| vcxproj | Файли з CRLF (як в upstream) | Не перезберігати з LF; додавати рядок, не переписуючи файл |
| `yr_object_get_string(m, "%s", field)` | Щоб прибрати попередження компілятора, обгорнули ім'я поля в `"%s"`. libyara розгортає `%s`/`%i` лише всередині `[...]` — шукалось поле з назвою «%s», усі докази в JSON стали порожні (вердикти — ні, тому регресія не помітила; помітили в описі алерту Wazuh) | Не «лагодити» попередження без розуміння API; перевіряти не лише вердикт, а й `evidence` |
| Файл відкритий у Word | Лікування не може підмінити файл | `failed:replace` + повтор у вотчері (`retry.json`) |

# DocScan — оновлення

**Стан (2026-11-22): зроблено.** Служба `DocScanUpdater` оновлює три компоненти — **програму** (пакет релізу
yara-docscan), **правила** (окремий репозиторій yara-docscan-rules; критичні правила — усередині пакета правил) і
**списки організації** (`whitelist.json` / `blacklist.json`). Розділ 0 — як це працює; розділ 1 — що з першого
дизайну (2026-11-18) не реалізовано і чим замінено; розділ 2 — відкриті питання.

## 0. Як працює оновлення

### 0.1. Програма

- **Служба `DocScanUpdater`** (`watcher-go/updater`, `updater\docscan-updater.exe` у пакеті) — ставить
  `install.ps1`, як і `DocScanWatcher` (автозапуск, SYSTEM, перезапуск після збою).
- **Як оновлюватися — конфіг `C:\ProgramData\DocScan\update\updater.json`** (пише інсталятор з `-UpdateMode`,
  `-UpdateMirror`, `-UpdateMarker`, `-UpdateEveryHours`, `-UpdateWindow`, `-ListsUrl` / `-ListsKey` /
  `-ListsEveryHours` / `-ListsToken`; лише коли їх задано, або на першому встановленні — `github`; далі можна
  правити, потім `Restart-Service DocScanUpdater`; доступ лише SYSTEM + адміністратори). Кожна організація вибирає
  сама — Wazuh не обов'язковий:

  | `mode` | що робить служба |
  |---|---|
  | `github` (типово) | раз на `check_every_hours` (6) — `releases/latest/download/manifest.json` |
  | `mirror` | те саме з `mirror.url`: тека з файлами релізу (`manifest.json`, `manifest.sig`, пакет) — http(s), шлях або UNC |
  | `marker` | чекає файл `marker.file` (типово `update\update.json`), який пише агент (Wazuh чи будь-який інший): `{"component": "program" \| "rules", "version": "v1.0.5", "source": "github" \| "mirror" \| "<адреса теки>", "sha256": "<sha256 manifest.json>", "request_id": "…"}` — усі поля необов'язкові; виконаний маркер перейменовується в `update.json.done` |
  | `off` | не оновлювати програму й правила (служба не ставиться, якщо не задано `lists.url`) |

  ```json
  {"mode": "github", "check_every_hours": 6, "github": {"repo": "rifatismailov/yara-docscan"},
   "mirror": {"url": ""}, "marker": {"file": "C:\\ProgramData\\DocScan\\update\\update.json"},
   "rules": {"off": false, "github": {"repo": "rifatismailov/yara-docscan-rules"}, "mirror": {"url": ""}},
   "lists": {"url": "", "check_every_hours": 24, "public_keys": []},
   "window": "", "extra_public_keys": []}
  ```
  `window` — напр. `"22:00-06:00"`: періодичні режими ставлять оновлення лише в цей час (маркер — одразу).
  `lists.token` (необов'язково) — токен лише для читання закритого дзеркала списків.
- **Довіра — лише підпис.** CI (`cirun publish`) кладе в реліз `manifest.json` (продукт, версія vX.Y.Z, збірка,
  коміт, пакет — розмір і sha256, sha256 кожного файлу) і `manifest.sig` (ed25519; приватний ключ — KeePassXC
  `CI/Release/signing-key`, секрет Forgejo `CI_SIGNING_KEY`; публічний — `watcher-go/manifest` `OfficialKeys`).
  Updater ставить лише підписане довіреним ключем (+ `extra_public_keys` організації), хоч із GitHub, хоч із
  дзеркала, хоч за адресою з маркера; лише новішу версію (на старішу — ніколи); пакет — розмір і sha256 з
  маніфесту, кожен файл — його sha256, зайвих немає.
- **Встановлює сам `install.ps1` нового пакета** з `-Reuse` (параметри ПК з `C:\ProgramData\DocScan\install.json`:
  `-DetectOnly`, `-WatchPath`, `-Workers`, `-NoCritical`, …) і `-ResultFile`. Пакет поточної і попередньої версії
  лишається в `update\packages\<версія>`. Не встановилось (інсталятор упав, watcher не стартував, версія не та) —
  updater ставить попередній пакет так само = **відкат**; невдалу версію періодична перевірка більше не пробує
  (маркер — може). Сам updater — частина пакета програми, його оновлює той самий `install.ps1`.
- **Звіт для агента** — `C:\ProgramData\DocScan\results\docscan-updates.json` (інсталятор додає його в `ossec.conf`
  поруч із `docscan-results.json`): `{"event": "Update", "update": {"status": "success" | "rollback" | "failed" |
  "current" | "error", "component": "program" | "rules" | "lists", "from", "to", "mode", "source", "request_id",
  "message"}}`. Журнал — `results\updater.log`.
- Перевірено на ВМ (2026-11-19, тестовий ключ у `extra_public_keys`): маркер → v9.0.1 → v9.0.2 (`success`); зламаний
  v9.0.3 (правила не компілюються) → відкат на v9.0.2 (`rollback`).

### 0.2. Правила (окремо від програми)

- Репозиторій **github.com/rifatismailov/yara-docscan-rules** (публічний); реліз правил vX.Y.Z (`cirun rules-release
  --dir <checkout> [--critical <checkout docscan-critical>]`): `DocScan-rules.zip` (правила + `critical/` +
  `VERSION.txt`), `rules-manifest.json` / `.sig` (продукт `docscan-rules`, той самий ключ CI),
  `DocScan-rules-bundle.zip` (ці три файли — для ручного встановлення). Перед пакуванням правила компілюються нашим
  `yarac`. З **v1.0.6 правил у пакеті програми немає** — `docscan-project/rules` прибрано з git (у `.gitignore`);
  CI бере підписаний реліз правил (`cirun/rulesrc`, вхід `rules` workflow) — у робочу теку і на стенди.
- **Встановлення:** правила завантажує той, хто ставить DocScan, **до встановлення**: `DocScan-Install.ps1 -Rules
  <файл | UNC | URL>` (або `install.ps1 -Rules`); `docscan-updater.exe -InstallRules` перевіряє підпис, кожен файл,
  компілює і кладе в `rules\`. Немає правил ніде — інсталятор не ставить DocScan. Окремі правила
  (`rules\VERSION.txt`) оновлення програми не чіпає.
- **Оновлення лише правил:** `DocScanUpdater` після перевірки програми перевіряє реліз правил
  (`rules.github.repo`; дзеркало — `rules.mirror.url`, порожньо — `rules-manifest.json` у теці дзеркала програми;
  маркер `{"component": "rules", …}`): підпис → пакет → пробна компіляція (основні й критичні правила) → зупинити
  watcher → `rules` → `rules.prev`, нові на місце → запуск, чекати `start: watching` → інакше відкат на
  `rules.prev`. Записи — `component: rules`. `rules.off: true` вимикає.
- **Watcher без правил не сканує і чекає** (`waiting for rules`), а не падає.
- Перевірено на ВМ: пакет програми без правил → відмова; `-Rules` з релізу v1.0.0 на GitHub → встановлено, HIT на
  `.docm`; маркер → правила v9.9.1 (тестовий ключ) — `success`, watcher перезапущено; правила, що не компілюються,
  — `failed`, не встановлені, watcher не чіпався; перевстановлення програми без `-Rules` правила лишило; без правил
  watcher чекав, з правилами — стартував.

### 0.3. Критичні правила (2026-11-22): у тому самому пакеті правил

Окремого пакета, маніфесту, ключа й дзеркала для критичних правил немає: `DocScan-rules.zip` містить
`critical/*.yar` (скільки завгодно файлів) з окремого репозиторію `docscan-critical` (приватний Forgejo:
`critical/`, `tests/match`, `tests/no-match`). Збирає і перевіряє один інструмент — `cirun rules-release --dir
<rules> --critical <docscan-critical> [--dry-run]` (задачі VS Code «Rules: check» / «Rules: release»); на ПК — як
усі правила (`<InstallDir>\rules\critical`, перевірка компіляції критичних правил перед заміною, відкат), третій
прохід — на всіх ПК, `-NoCritical` вимикає (зберігається при оновленнях через `install.json`). Старі
`install.ps1 -CriticalRules`, `DocScan-Install.ps1 -Critical` / `-CriticalToken` і окрема тека
`<InstallDir>\critical\` прибрані (інсталятор видаляє стару теку). Див. [CRITICAL-RULES.md](CRITICAL-RULES.md),
розділ 6.

### 0.4. Списки організації (2026-11-21)

`whitelist.json` / `blacklist.json` (`<DataDir>\lists\`) — третій компонент DocScanUpdater (`component: lists`,
`updater/lists.go`): `updater.json` → `"lists": {"url", "check_every_hours": 24, "public_keys", "token"}`
(`install.ps1 -ListsUrl / -ListsKey / -ListsEveryHours / -ListsToken`), у будь-якому режимі, і `off` теж; ставиться
лише список з підписом ключем організації (окремо від ключа релізів), правильного формату і з більшим `serial`;
попередній — `.prev`. Схеми — [LISTS-FLOW.md](LISTS-FLOW.md).

---

## 1. Перший дизайн (2026-11-18): що не реалізовано і чим замінено

Перша версія цього документа описувала інший механізм. Його **не реалізовано**; чинне — розділ 0.

| Було в дизайні | Що зроблено замість |
|---|---|
| Критичні правила — окремий **зашифрований** пакет (AES-256-GCM) з джерела організації, `critical-manifest.json` / `.sig`, ключ організації, ключ розшифрування через спільні файли Wazuh, `key_id` | частина звичайного пакета правил (`critical/` у `DocScan-rules.zip`), підпис CI, без шифрування (розділ 0.3; що можна класти в такі правила — CRITICAL-RULES.md, розділ 7) |
| `update-sources.json` з джерелами, ключами, `auth` (токен у DPAPI) | `updater.json` (розділ 0.1); токен закритого дзеркала списків — `lists.token` відкритим текстом у файлі з доступом лише SYSTEM + адміністратори |
| Параметри інсталятора `-Critical`, `-CriticalPublicKey`, `-CriticalKeyFrom`, `-CriticalToken`, `-RulesSource`, `-RulesPublicKey` | немає; свій репозиторій правил — `rules.github.repo` / `rules.mirror.url` в `updater.json`, свій ключ підпису — `extra_public_keys` |
| Оновлення лише за командою Wazuh; маркер без адрес і хешів; компоненти `rules · critical · watcher · engine · updater · all` | режими `github` / `mirror` (періодично) / `marker` / `off`; маркер може містити `source` і `sha256` (довіра — лише підпис); компоненти маркера — `program` · `rules` |
| Версії `2026.11.18-1` / `20261116-53e5ce45`; `min_engine`, `rules[]` з `remove` у маніфесті | версії vX.Y.Z; маніфест: продукт, версія, збірка, коміт, пакет, sha256 кожного файлу |
| Watcher стежить за маркером і запускає updater завданням планувальника; updater оновлює себе через `.new` | updater — окрема служба, сам стежить за маркером; оновлюється разом з пакетом програми (`install.ps1`) |
| `installed.json`; запис «Update» у `docscan-results.json` з `result` / `duration_s` | версії — `VERSION.txt` і `rules\VERSION.txt`; стан встановлення — `update\state.json`; записи — `docscan-updates.json` (розділ 0.1) |
| Щоденна перевірка правил з `ETag` / `304 Not Modified` | періодична перевірка раз на `check_every_hours` |
| Скрипт Active Response `docscan-update`, що пише маркер | у репозиторії немає; маркер може писати будь-який агент (режим `marker`) |

---

## 2. Відкриті питання

- **Правило Wazuh для подій `Update`** (`docscan-updates.json`) на менеджері — ще немає в
  `deploy/manager/local_rules.docscan.xml`.
- **CI репозиторію правил** (корпуси, `expected.txt` / `clean.txt`) перед кожним релізом правил — ще немає; зараз
  `rules-release` перевіряє компіляцію основних правил і тести критичних.
- **Паролі й логіни як критична інформація.** Правила за ознаками («пароль:», «login=», ключі API, рядки
  підключення, приватні ключі) — так, самі правила секретів не містять. Справжні паролі в правилах — ні: правило з
  конкретним паролем опиниться на кожному ПК з DocScan (а пакет правил публікується), тобто саме стане витоком. Для
  перевірки «чи не потрапив у документ наш справжній пароль» потрібен інший механізм — порівняння хешів на сервері,
  а не на ПК.

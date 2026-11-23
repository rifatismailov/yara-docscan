# CI для DocScan: одна кнопка → збірка і всі тести на macOS, Windows і Linux

Натискаєте **▷** або **Cmd+Shift+B** у VS Code — і `cirun` (Go, `docscan-project/ci/cirun/`). Два режими
(`pipeline.mode` у `config.yaml`): `local` (за замовчуванням у коді; усе з Мака, схема нижче) і `forgejo` (Мак перевіряє
macOS, далі стенди в Forgejo Actions — наступний розділ).

Режим `local`:

```
коміт локальних змін (перевірка безпеки, БЕЗ push)
        │
        ▼
хвиля 1 (паралельно):  macOS — цей Мак (local)          Windows — ВМ, інакше запасна машина (WinRM)
                       build → documents → critical →    checkout (git або zip) → build (Go-watcher + MSBuild) →
                       hostile → corpus → malware →       documents → confine → critical → assets →
                       fuzz → yara-*.tar.gz               hostile → corpus → malware → fuzz → DocScan-<версія>.zip
        │  обидві зелені?
        ▼
хвиля 2:               Linux — Ubuntu (SSH): те саме, що на macOS        (requires: [windows, macos])
        │  усе зелене?
        ▼
git push на GitHub (push.remote) — ЗАВЖДИ, від Forgejo не залежить
        │                (Forgejo, якщо увімкнено й доступний: mirror-sync і статуси cirun/<ОС>)
        ▼
з --release: реліз на GitHub (пакет + DocScan-Install.ps1) → RESULT
```

Отже, на GitHub потрапляє **лише протестований** коміт, а слухач на іншому сервері сам бачить його там і
запускає свої тести. Forgejo для цього не потрібен.

## CI/CD через Forgejo Actions (`pipeline.mode: forgejo`)

```
▷ (Мак)  коміт + перевірка безпеки → macOS: збірка й тести локально → macOS tar.gz у сховок → push у Forgejo
         → запуск .forgejo/workflows/pipeline.yml → кінець (RESULT: STARTED); далі Forgejo працює сам
         (--watch: ▷ чекає й друкує стан завдань і статус кожного стенда до кінця прогону)
Forgejo  prepare: вимкнена ВМ стенда (vm:) → start через API Proxmox (токен лише VM.PowerMgmt + VM.Audit), чекати
         WinRM / SSH; srv2019 (sessions:) — менше count RDP-сесій <prefix>01.. → відкрити їх зі стенда from (rds_connect.ps1
         завданням планувальника в інтерактивній сесії; на стенді from — автовхід); ВМ після прогону не вимикаються
         probe: які стенди доступні (недоступний → SKIPPED (host offline), прогін не падає)
         win11 (Windows 11):            MSBuild + Go-watcher, 42 зразки, пісочниця, пакет, установка + watcher
         srv2019 (Windows Server 2019): пакет win11, повний набір (третій прохід, ворожі файли, корпус,
         win10 (Windows 10)             шкідливе ПЗ — лише сканування, установка + watcher);
                                        srv2019 ще й навантажувальний тест термінального сервера (нижче)
         ubuntu (Ubuntu Server):        власна збірка, повний набір, фазинг
         report: [CI/CD] <стенд> -> OK | ERROR | SKIPPED, [RESULT] Verified on: ...
         лише без жодного ERROR: перевірка безпеки комітів → git push на GitHub → (з ▷) реліз vX.Y.Z:
         пакет Windows + DocScan-Install.ps1, yara-docscan-linux-x64.tar.gz, yara-docscan-macos-arm64.tar.gz,
         у описі — таблиця «Verified on»
```

- ▷ = з релізом; Cmd+Shift+B = без релізу (push на GitHub після зеленого прогону — так само). Обидва
  завершуються одразу після запуску прогону в Forgejo: стежити не треба, результат — у прогоні Forgejo і в
  статусах коміту (`cirun/<стенд>`, `cirun/result`, `cirun/publish`); реліз з'являється на GitHub сам.
  Задача «… wait for Forgejo (--watch)» — по-старому, з очікуванням і зведенням у терміналі.
- Раннер `lan` — у контейнері поруч з Forgejo; усі завдання прогону ділять теку `~/ci-art/<прогін>` на ньому,
  тож пакет win11 доходить до інших стендів без сторонніх сховищ.
- Адреси й облікові дані стендів — у секретах Forgejo: `CIRUN_CONFIG` (конфіг стендів з `env:`-посиланнями),
  `CI_WIN11_PASS`, `CI_SRV2019_PASS`, `CI_WIN10_PASS`, `CI_SSH_KEY`, `CI_KNOWN_HOSTS`, `CI_STORE_TOKEN`,
  `CI_GITHUB_TOKEN`, `CI_FORGEJO_TOKEN`. У публічному workflow нічого внутрішнього немає.
- Підкоманди для завдань workflow: `prepare` (`cirun/prepare.go`), `probe`, `stand`, `report`, `publish`
  (`cirun/pipeline.go`); ▷-частина — `cirun/forgejo_run.go`. Повернутися до старого режиму (усе з Мака): `pipeline.mode: local`.
- Proxmox вмикається вручну; стенди мають «Start at boot» (після Forgejo і файлового сервера), prepare — підстраховка,
  якщо якусь ВМ вимкнули (розділи `proxmox:` і `stands[].vm` / `stands[].sessions` конфігу). Секрети prepare:
  `CI_PROXMOX_TOKEN`, `CI_LT_PASS`. Секрет підпису релізу: `CI_SIGNING_KEY`. Значення всіх секретів — у KeePassXC.
- Стенди без Microsoft Defender (на тестових машинах він вимкнений політикою: забирав би тестові зразки).

## Що де лежить

| Файл | Що робить |
|---|---|
| `docscan-project/ci/config.yaml` | **налаштування** (не в git: внутрішні адреси); зразок — `config.example.yaml` |
| `docscan-project/ci/cirun/main.go` | прапорці, порядок: коміт → правила → збірка → push → реліз (режим `local`) або → Forgejo (`forgejo`) |
| `cirun/pipeline.go`, `prepare.go`, `forgejo_run.go` | конвеєр Forgejo: підкоманди завдань workflow і ▷-частина на Маку |
| `cirun/rules_release.go`, `cirun/rulesrc/` | `rules-release` — перевірка й реліз пакета правил; `rulesrc` — завантаження й перевірка підпису релізу правил для прогону |
| `cirun/config/` | розбір YAML (`config.go`), посилання на секрети `keepassxc:` / `hosts:` / `env:` (`secrets.go`) |
| `cirun/transport/` | інтерфейс `Transport` і підключення: `local.go`, `ssh.go` (known_hosts перевіряється), `winrm.go` |
| `cirun/platform/` | інтерфейс `Platform` (Prepare → SyncSource → Build → Test → FetchArtifacts); `unix.go` — macOS і Linux, `windows.go` |
| `cirun/orchestrator/` | хвилі з `requires`, хід і відсоток у терміналі, підсумок, push коміту на GitHub |
| `cirun/forgejo/` | необов'язково: доступність, mirror-sync / push у Forgejo, статуси коміту |
| `cirun/platform/gowatcher.go` | Go-watcher для пакета: `git archive` теки `watcher-go` точного коміту → `go vet` + `go test` → крос-збірка `docscan-watcher.exe` (windows/amd64) на Маку → у репозиторій на Windows-машині (крок build); на Windows Go не потрібен |
| `cirun/gitops/`, `cirun/deploy/` | коміт з перевіркою безпеки, `git archive`; реліз на GitHub (`release.go`, `manifest.go`, `version.go`), пакет правил (`rules.go`, критичні — `critical.go`) |
| `docscan-project/ci/build-test-unix.sh [all\|build\|test]` | збірка і тести на macOS / Linux (cirun кличе `build`, потім `test`) |
| `docscan-project/ci/check_verdicts.ps1` / `.py` | перевірка документів (Windows без Python / інші ОС) |
| `docscan-project/ci/expected-verdicts.tsv` | еталон для 42 зразків `test-samples/generated` (оновлювати свідомо: `check_verdicts.py --write`) |
| `.forgejo/workflows/pipeline.yml` | workflow конвеєра Forgejo: prepare + probe → win11 → srv2019 / win10, ubuntu → report + publish |
| `docscan-project/ci/install_smoke.ps1`, `combat_*.ps1`, `check_watcher.py`, `check_corpus.py`, `loadtest/` | установка + watcher на стенді, бойовий тест, перевірка корпусу / шкідливого ПЗ, навантажувальний тест |

Тести в кожному прогоні: **документи** (42 зразки, серед них 7 макросів VBA, 4 регресії хибних тривог / шифрування і 6 zip-архівів: вердикт, лікування,
повторний скан, оригінали не змінені), **пісочниця** (Windows, `confine`), **3-й прохід** (`test-critical/run_tests.py`,
299 перевірок), **ворожі файли** (35), **корпуси** (~4 000 документів), **шкідливе ПЗ** (949 файлів, лише сканування),
**фазинг** (ASan + UBSan; Мак — обидва фазери, Windows — фазер розборщиків). Повна таблиця — нижче.

## Запуск

Go ≥ 1.26 (`brew install go`). З кореня репозиторію (так роблять ▷, Cmd+Shift+B і задачі VS Code):

```sh
go run -C docscan-project/ci/cirun .                     # повний прогін
go run -C docscan-project/ci/cirun . --plan              # перевірити конфіг, секрети, машини, GitHub — без збірки
go run -C docscan-project/ci/cirun . --only macos        # лише ці платформи (через кому)
go run -C docscan-project/ci/cirun . --fuzz 0            # без фазингу
go run -C docscan-project/ci/cirun . --release           # після зеленого прогону — реліз на GitHub
go run -C docscan-project/ci/cirun . --no-push           # не пушити коміт на GitHub
go run -C docscan-project/ci/cirun . --push-only         # лише git push HEAD на GitHub (після зеленого прогону)
go run -C docscan-project/ci/cirun . --rules v1.2.3      # з цим релізом правил (за замовчуванням latest)
go run -C docscan-project/ci/cirun . --watch             # режим forgejo: чекати кінця прогону Forgejo і друкувати стан
go run -C docscan-project/ci/cirun . -h                  # усі прапорці
```

Хід видно одразу: машина кожної платформи, кожен крок з результатом і загальним відсотком
(`[windows <ip> (vm-win11)] build PASS (57s)   74%`), раз на 30 с — рядок стану. Підсумок і артефакти —
`ci-out/run-<час>/` (`macos/yara-darwin-arm64.tar.gz`, `windows/DocScan-<версія>.zip`, логи кроків, `summary.txt`).

Код виходу: **0** — усе зелене, коміт на GitHub (і набір викладено, якщо публікацію увімкнено); **1** — провал
(збірка, тести або публікація набору); **2** — зелене, але push на GitHub не вдався (повторити: `--push-only`).

## Конфіг і паролі (KeePassXC)

Паролів у `config.yaml` немає — лише посилання, які cirun розгортає під час запуску:

```yaml
password_ref: "keepassxc:CI/Windows/vm-win11"            # поле Password запису
user_ref:     "keepassxc:CI/Windows/vm-win11#UserName"   # інший атрибут: UserName, URL, Notes
token_ref:    "keepassxc:CI/Forgejo/api-token"
# також: "hosts:<профіль>[.<поле>]" (старий ~/.docscan/hosts.json), "env:<ЗМІННА>"
```

База — `~/Documents/docscan-ci.kdbx` (окрема, лише для CI; групи `CI/Windows`, `CI/Forgejo`, `CI/Deploy`,
`Infra`). Відкривається **один раз за запуск** (`keepassxc-cli export` у пам'ять; майстер-пароль — через stdin, не
аргументом). Режим `unlock`:

| `unlock` | Як |
|---|---|
| `keychain` (за замовчуванням) | майстер-пароль у Связці ключів macOS (`keychain_item: docscan-kdbx`); macOS один раз питає дозволу |
| `prompt` | cirun питає майстер-пароль у терміналі один раз за запуск |
| `key_file` | база відкривається лише файлом-ключем |

Відкрити базу в KeePassXC: майстер-пароль — у «Связці ключів» (Keychain Access) за назвою `docscan-kdbx`
або `security find-generic-password -s docscan-kdbx -w`. Новий пароль — новий запис у базі й посилання в конфігу.

## Платформи і підключення

| Платформа | Підключення | Звідки код |
|---|---|---|
| macOS | `local` (цей Мак, `workdir: .` — сам репозиторій) або `ssh` | local — робоча тека як є; ssh — `git archive` точного коміту |
| Windows | `winrm` (NTLM, 5985); `candidates` — перша доступна машина | zip точного коміту (git з Forgejo — лише якщо Forgejo увімкнено й машина його бачить) |
| Linux | `ssh` (ключ або пароль; ключ хоста перевіряється за `known_hosts`) | `git archive` точного коміту → чиста тека → повна збірка |

`requires: [windows, macos]` у Linux: він стартує лише тоді, коли обидві платформи **увімкнені в цьому прогоні й
зелені**; інакше — `skipped` з причиною, і прогін не зелений. Перед першим SSH-підключенням зайдіть на машину вручну
(`ssh user@host`), щоб її ключ потрапив у `~/.ssh/known_hosts`.

## Push на GitHub і Forgejo

- `push:` — головне: після зеленого прогону `git push <remote> <гілка>` на GitHub (`remote: docscan`). Від Forgejo
  не залежить. `push.tag` (напр. `ci/passed/{short}`) — тег на протестований коміт, якщо слухачу так зручніше.
- `forgejo:` — **необов'язково** (`enabled: false`). Якщо увімкнути: після push на GitHub, коли Forgejo доступний,
  `mode: mirror` викликає mirror-sync (дзеркало оновиться одразу, а не за розкладом), `mode: push` ще й пушить у
  Forgejo; `report.commit_status` — статуси `cirun/<ОС>`. Недоступний Forgejo — лише повідомлення в терміналі.

## Тести на кожній платформі

Кожен ▷ проганяє на кожній машині з `full_tests: true` (Мак, ВМ Windows, ВМ Linux) однаковий набір:

| Крок | Що | Звідки файли |
|---|---|---|
| documents | 42 неактивні зразки: вердикт, лікування, повторний скан (на Windows — через пісочницю) | git (`test-samples/generated`) |
| confine | лише Windows: `yara64 --docscan-confine-check` — воркер не може записати, прочитати приватний файл, запустити процес; брокер — job object, без привілеїв. `RESULT: CONFINED` | створює сам |
| critical | третій прохід, 299 перевірок | створює сам |
| hostile | 35 ворожих файлів (зламані, гігантські, глибока вкладеність) | з корпусу seeds |
| corpus | ~4 000 документів з публічних тестових корпусів | POI, pdf.js, plaso, LibreOffice RTF, LNK, Apache Tika, oletools |
| malware | **справжнє** шкідливе ПЗ — 949 зразків (майнер XMRig, EICAR, theZoo, InQuest, MalwareBazaar): лише сканування, ніколи не запускається | `~/docscan-ci/malware` |
| fuzz | регресійні файли знайдених падінь (`fuzz/regressions`) + фазинг `fuzz_seconds` с; база — **усі** тестові файли: корпуси, 42 згенеровані зразки, seeds (шкідливе ПЗ — ні). Мак/Linux — обидва фазери (модуль і розборщики); Windows — фазер розборщиків (усі парсери DocScan і лікування; clang-cl + libFuzzer + ASan, на ВМ потрібен LLVM: `choco install llvm`, інакше SKIP). Падіння (`crash-` / `timeout-` / `oom-` / `leak-`) → крок червоний, файли — `fuzz-crashes` в артефактах прогону; `slow-unit-*` (повільний запуск) лише показується в лозі й зберігається, помилкою не є | корпуси + git |

Запасна машина-робоча станція (`full_tests: false`) — лише збірка і documents (без корпусів і шкідливого ПЗ).

### Бойовий тест (`--combat`, лише Windows, ~2 год)

```sh
go run -C docscan-project/ci/cirun . --combat --only windows --fuzz 0
```

Перевіряє систему так, як вона працює на робочій станції, а не `yara64` напряму:

| Крок | Що |
|---|---|
| combat-setup | `combat_setup.ps1`: пакет цього коміту → `install.ps1` (оновлення: `C:\Program Files\DocScan`, `C:\ProgramData\DocScan`, служба Windows DocScanWatcher від SYSTEM; watcher стежить за `C:\Users` і тестовою текою `C:\ci\inbox`); тестові файли з **файлового сервера** (`fileserver` у config.yaml): `yara\corpus`, `yara\seeds`, `yara\malware\malware.zip` і `provided.zip` (пароль `infected`, розпаковуються лише в `C:\ci\combat`) + 42 зразки з git; знімок стану |
| combat-feed | `combat_feed.ps1` (окреме завдання SYSTEM): кладе файли в `C:\ci\inbox` партіями по 50 і чекає, поки watcher упорається; cirun раз на 30 с показує хід |
| combat | `check_watcher.py`: на кожен файл, який watcher має сканувати (за його списками розширень), є запис без `ERROR`; 42 зразки — вердикт, лікування і вердикт після лікування за еталоном; реальні зразки замовника — HIGH; шкідливе ПЗ — кожен шлях `expected.txt`, який watcher сканує, виявлений (решта — список «не сканується через розширення»); корпус — вердикт політики = прямому скану (крок corpus). Звіт — `combat-report.txt`, записи — `combat-records.json`, лог watcher-а — `combat-watcher.log` |
| combat-cleanup | `combat_cleanup.ps1` (завжди): тестові файли, розпаковане шкідливе ПЗ, бекапи й копії макросів, створені тестом, рядки тесту в черзі E5Search. DocScan лишається встановленим (оновленим до перевіреної збірки) |

**Звірка між платформами.** Вердикти корпусу (`corpus-verdicts.tsv`) кожної платформи порівнюються: рішення
DocScan (вердикт і знахідки) на тих самих файлах мають збігатися точно — інакше прогін не зелений.
Різниця лише у вендорних збігах — попередження (частина вендорних правил дивиться на шлях до файлу).

**Шкідливе ПЗ:** кожен файл з `expected.txt` (437 шляхів) має бути виявлений — збіг вендорного правила або
вердикт політики MEDIUM/HIGH; пропущений файл — `MISSED`, прогін червоний. Це регресія: правила й код не
мають втратити жодної вже наявної детекції. Склад `~/docscan-ci/malware`:

| Тека | Що | Звідки |
|---|---|---|
| корінь, `WindowsTask/`, `ReaItekHD/`, `Setup/`… | майнер XMRig (виявлений Wazuh), EICAR, EICAR у zip | інцидент; eicar.org |
| `archives/` | майнер у zip (перевірка сканування вмісту архівів) | зібрано з майнера |
| `thezoo/` | 42 родини (PE, документи) | ytisf/theZoo |
| `inquest/` | 495 шкідливих документів (OLE, OOXML, RTF, PDF) | InQuest/malware-samples |
| `benign/` | **чисті** документи з колишніх хибних тривог (див. `clean.txt` нижче) | ПК замовника |
| `bazaar/<тип>/` | 255 свіжих зразків за типами: doc docm xls xlsm rtf lnk one zip iso js hta vbs ps1 exe dll pdf msi xll | MalwareBazaar API (ключ — `keepassxc:CI/abuse.ch/auth-key`) |

Оновити `expected.txt` (після свідомої зміни правил): прогнати `check_corpus.py` по теці й записати всі
виявлені шляхи; старі шляхи не повинні зникнути — інакше це регресія, а не оновлення.

**Хибні спрацювання:** `clean.txt` поруч з `expected.txt` — навпаки, справжні чисті документи, на яких колись
була хибна тривога (`benign/<назва>/`). Кожен має лишатися INFO без вендорних збігів, інакше
`FALSE POSITIVE` і прогін червоний (`check_corpus.py` у кроці malware, `check_watcher.py` у бойовому тесті).
Це документи замовника — лише в цій теці й у запароленому `malware.zip` у приватному сховку, ніколи в git.
Зараз: 8 PDF, хибний `PDF_JS` 2026-11-16 (`/JS` як байти всередині стисненої картинки).
Додати новий випадок: файли в `benign/<назва>/`, шляхи в `clean.txt`.

### Навантажувальний тест (термінальний сервер)

**У конвеєрі** — стенд з розділом `load:` у конфігу (зараз srv2019), після повного набору, приблизно 45–60 хв:
`load-setup` (`rds_reset.ps1 -Package <пакет win11> -DetectOnly`: DocScan з нуля, стежить за `C:\Users`;
critical-правила — `<root>\critical-rules.yar` на сервері, не з git) → `load-run` (`rds_load.ps1` завданням
SYSTEM: 25 користувачів, сплеск 10 файлів на старті, далі дія кожні ~20 с протягом 20 хв, 5 користувачів з
поодинокими файлами; потім чекає, поки watcher дочитає) → `load` (`loadtest_report.py`: хоч один пропущений
файл — FAIL; звіт `load-report.txt` в артефактах) → `load-cleanup` (завжди: генератори, DocScan, файли тесту в
профілях; на сервері лишаються 5 останніх `C:\loadtest\runs\ci-*`). Сервер готується один раз вручну
(`rds_setup.ps1`, `rds_docs.ps1`, по одному входу кожного користувача — профілі); RDP-сесії перед прогоном відкриває
`cirun prepare` (розділ `sessions:` стенда).
Стрес-режими (`-All`, години) — лише вручну.

**Вручну**: окремий тестовий сервер Windows Server з роллю RD Session Host, N справжніх RDP-сесій
з іншої Windows-машини і генератор дій користувачів — `loadtest/` (опис файлів і результати —
[../watcher-go/README.md](../watcher-go/README.md) §2, §7, §9). Порядок: `rds_setup.ps1` (роль, користувачі) →
`rds_connect.ps1` на клієнті (сесії) → `rds_docs.ps1` (тестові набори) → `rds_reset.ps1 -DefenderOff` (DocScan
з нуля, Defender вимкнено, опційно Go-watcher) → `rds_load.ps1` (прогін; від SYSTEM через завдання планувальника, не з WinRM-сеансу)
→ `loadtest_report.py <тека прогону>`. Режими генератора: звичайний темп, `-Burst N`, `-All` (увесь набір
кожному користувачу), `-ProbeUsers` (поодинокі файли під час напливу — затримка, яку відчуває людина).

### Звідки беруться тестові файли поза git

```
Мак: fuzz/external (лише документи) + ~/docscan-ci/seeds ─► corpus.tar.gz ─┐
     ~/docscan-ci/malware (+ expected.txt) ─► malware.zip (пароль infected) ─┤
                                                                             ▼
          приватний сховок пакетів Forgejo (generic package docscan-tests, версія = хеш вмісту)
                                                                             │
          ВМ Windows: C:\ci\tests (виняток Defender)  ◄─────────────────────┤   завантажити → тести →
          ВМ Linux:   <workdir>/tests                 ◄─────────────────────┘   ВИДАЛИТИ (завжди)
```

- Архіви перезбираються лише коли файли змінилися; у сховок викладаються лише нові версії.
- Мак тестує розпаковану копію того самого архіву (`~/docscan-ci/assets/<версія>/unpacked`) — набір файлів
  на всіх платформах однаковий.
- Токен лише на пакети: `keepassxc:CI/Forgejo/package-token`. Сховок недоступний — Мак тестує локально,
  віддалені машини пропускають corpus / malware (попередження в терміналі).
- Корпуси: `docscan-project/fuzz/fetch_corpus.sh` (у git їх немає).
- Розмір: corpus.tar.gz — десятки МБ, malware.zip — ~1.1 ГБ. На ВМ Windows завантаження йде без смуги
  прогресу (`$ProgressPreference`), а malware.zip розпаковує `tar.exe --passphrase` (bsdtar; Python —
  лише запасний шлях, бо розшифровує ZipCrypto дуже повільно). Час кожної дії — у `windows-assets.log`;
  орієнтир: завантаження ~15 с, розпакування ~1 хв (було 24 хв).

### Шкідливе ПЗ — правила

- **Ніколи не запускати.** Лише сканування yara.
- Лише Мак і тестові ВМ; **ніколи на робочих станціях** (`full_tests: false`) і **ніколи в git**; на ВМ видаляється після кожного тесту.
- Вихідна копія — `~/docscan-ci/malware/` (лише на читання), список обов'язкових збігів — `expected.txt` там же.

### Що потрібно на ВМ Windows

Windows 10/11, WinRM (5985), VS Build Tools 2022 (C++), Git, Python 3 (справжній, не з Microsoft Store),
виняток Defender для `C:\ci`; для фазингу — LLVM (`choco install llvm`). Без LLVM крок fuzz — SKIP.

## Реліз на GitHub (розгортання)

DocScan поширюється **лише релізами GitHub** цього репозиторію; файлових серверів для розгортання немає.

```bash
go run -C docscan-project/ci/cirun . --release                       # прогін; зелений і запушений -> реліз
go run -C docscan-project/ci/cirun . --release --bump minor         # те саме, номер v1.1.0 замість v1.0.1
go run -C docscan-project/ci/cirun . --release-run ci-out/<прогін>   # реліз з уже зеленого запушеного прогону
```

**Номер релізу — `vX.Y.Z`** (SemVer; тег на протестований коміт, назва «DocScan vX.Y.Z»). GitHub сортує такі теги
за номером, тож найновіший реліз завжди вгорі (старі теги `docscan-<дата>-<коміт>` сортувалися за випадковим
хешем). cirun бере найбільший `v`-тег на GitHub і збільшує: `--bump patch` (за замовчуванням, v1.0.0 → v1.0.1),
`minor` (→ v1.1.0, помітні нові можливості), `major` (→ v2.0.0, несумісні зміни). Перший — **v1.0.0** (Go-watcher);
v0.x — колишні релізи `docscan-2026…` з PowerShell-watcher-ом. Якщо цей коміт уже випущено, береться його тег
(номер не плодиться). Збірка (`<дата>-<коміт>`) лишається в описі релізу і в першому рядку `VERSION.txt` пакета:
`DocScan v1.0.0 (build 20261118-1a2b3c4d)` (`SHA256SUMS.txt` перераховується).

Активи в `ci-out/<прогін>/release/`:

```
DocScan-windows-x64.zip + .sha256   пакет програми: bin\ (yara64, yarac64, рантайм VC++), watcher\, updater\, install.ps1 ... — БЕЗ правил
DocScan-Install.ps1                 єдиний скрипт для ПК
manifest.json + manifest.sig        підписаний маніфест (версія, sha256 пакета і кожного файлу в ньому) — для docscan-updater
```

У режимі `forgejo` реліз робить завдання report (`cirun publish --release`); до цих активів додаються
`yara-docscan-linux-x64.tar.gz` (стенд ubuntu) і `yara-docscan-macos-arm64.tar.gz` (▷ кладе його у сховок Forgejo),
в описі — таблиця «Verified on».

**Правила — не в цьому репозиторії** (github.com/rifatismailov/yara-docscan-rules). ▷ бере реліз правил
(`--rules latest` або `--rules vX.Y.Z`), перевіряє підпис і кожен файл (`cirun/rulesrc`), кладе в
`docscan-project/rules/` (у `.gitignore`) для macOS і передає ту саму версію стендам (вхід `rules` workflow):
Windows / Linux отримують `DocScan-rules.zip` у свій `docscan-project\rules` (тести) і `DocScan-rules-bundle.zip`
(smoke, навантажувальний і бойовий тести ставлять DocScan з `-Rules`, як справжній ПК). Пакет програми — без правил.

**Реліз правил** (окремий репозиторій github.com/rifatismailov/yara-docscan-rules, номер vX.Y.Z — свій). Один
інструмент перевіряє й збирає весь пакет правил — основні правила і критичні (третій прохід):

```bash
go run -C docscan-project/ci/cirun . rules-release --dir <checkout yara-docscan-rules> \
    --critical <checkout docscan-critical> [--yara ./yara] [--yarac ./yarac] [--bump minor] [--dry-run]
```
- Перевірка: основні правила компілюються нашим `yarac`; критичні (приватний репозиторій: `critical/*.yar` — будь-яка
  кількість файлів, `tests/match`, `tests/no-match`) — імена, компіляція і тести на документах нашим `yara`
  (документ з `tests/match` не знайдено — `NOT FOUND`, з `tests/no-match` знайдено — `FALSE ALARM`, реліз не робиться).
- Пакет: `DocScan-rules.zip` (основні правила + `critical/`), `rules-manifest.json` / `.sig`, `DocScan-rules-bundle.zip`
  (для `-Rules` інсталятора); підпис — той самий ключ. Критичні правила ставляться на **всі** ПК (на окремому ПК третій
  прохід вимикає `-NoCritical` інсталятора). Як писати критичні правила — [../CRITICAL-RULES.md](../CRITICAL-RULES.md).
- `--dry-run` — лише перевірка й пакет (`ci-out/rules-release-<тег>/`), без публікації. Обидва checkout-и мають бути
  чистими, коміт правил — уже на GitHub; реліз робиться на коміт репозиторію правил (змінилися лише критичні —
  спершу закомітити й запушити щось у репозиторій правил).
- VS Code: задачі «Rules: check …» (`--dry-run`) і «Rules: release …» (checkout-и `~/yara-docscan-rules` і
  `~/docscan-critical`).

**Підпис.** `cirun publish` / `--release` складає `manifest.json` і підписує його ключем ed25519
`release.signing_key_ref` (типово `keepassxc:CI/Release/signing-key`; на раннері — `env:CI_SIGNING_KEY`, секрет
Forgejo). Ключ має бути серед `OfficialKeys` у `watcher-go/manifest` — інакше реліз не випускається (ПК його не
прийняли б). Служба оновлення на ПК (`DocScanUpdater`, [../UPDATE-DESIGN.md](../UPDATE-DESIGN.md) §0) ставить лише
підписане. Новий ключ: спершу додати публічний у `OfficialKeys` і випустити реліз зі старим ключем, потім міняти.

- Імена активів однакові в усіх релізах — `releases/latest/download/<ім'я>` завжди дає найновіший (без GitHub API
  і його ліміту 60 запитів/год з однієї адреси).
- `gh release create` (gh на Маку, авторизований), потім пакет качається за публічною адресою і звіряється SHA256.
  Наявний реліз не перезаписується (якщо його пакет — саме ця збірка, це не помилка). Репозиторій —
  `release.repo` у `config.yaml`, порожньо — з адреси `push.remote`.
- На ПК: `DocScan-Install.ps1` качає пакет з релізу, звіряє SHA256, запускає `install.ps1` з пакета (той ще раз
  звіряє кожен файл з `SHA256SUMS.txt`). Правила (разом з критичними) — окремо: на новому ПК
  `DocScan-Install.ps1 -Rules <DocScan-rules-bundle.zip / UNC / URL>`, далі їх оновлює `DocScanUpdater`.
- Довіра: для `DocScan-Install.ps1` — обліковому запису GitHub (увімкнена 2FA обов'язкова); для автооновлення — лише
  ключу підпису CI (реліз, створений на GitHub без підпису, updater не поставить).
- Не зелений або не запушений прогін релізу не робить ніколи.

## Налаштування з нуля (покроково)

### 1. Forgejo (сервер) і раннер `lan`
1. Репозиторій у Forgejo для цього проєкту (у режимі `forgejo` ▷ сам пушить у нього коміт прогону; `forgejo.url` /
   `repo` / `token_ref` і розділ `pipeline:` у `config.yaml`).
2. Увімкнути **Дії** в репозиторії: *Налаштування → Розширені налаштування → «Дії»*.
3. **Секрети** (*Налаштування репозиторію → Дії → Секрети*) — ті, що читає `.forgejo/workflows/pipeline.yml`:

   | Секрет | Значення |
   |---|---|
   | `CIRUN_CONFIG` | конфіг cirun для раннера: розділи `stands:` (і `proxmox:`), паролі — `env:CI_...` (зразок — кінець `config.example.yaml`) |
   | `CI_WIN11_PASS`, `CI_SRV2019_PASS`, `CI_WIN10_PASS` | паролі облікових записів стендів Windows (WinRM) |
   | `CI_SSH_KEY`, `CI_KNOWN_HOSTS` | ключ SSH і `known_hosts` для стенда ubuntu |
   | `CI_STORE_TOKEN` | токен сховку пакетів Forgejo (тестові файли, macOS tar.gz) |
   | `CI_FORGEJO_TOKEN` | токен Forgejo: checkout коміту, статуси коміту |
   | `CI_GITHUB_TOKEN` | токен GitHub: push і реліз |
   | `CI_SIGNING_KEY` | ключ ed25519 підпису `manifest.json` релізу |
   | `CI_PROXMOX_TOKEN`, `CI_LT_PASS` | `cirun prepare`: токен API Proxmox (лише VM.PowerMgmt + VM.Audit), пароль користувачів навантажувального тесту |

4. Раннер з міткою **`lan`** (усі завдання workflow `runs-on: lan`), у мережі стендів; потрібні `git`, Go ≥ 1.26
   (workflow збирає cirun з коміту) і `gh`. Тека прогонів — `/home/runner/ci-art/<прогін>` (старші за 3 дні видаляються).
   Токен реєстрації: *Налаштування репозиторію → Дії → Виконавці → «Створити виконавця»*.

### 2. Мак (▷)
Go ≥ 1.26, `gh` (авторизований), KeePassXC CLI; для збірки — Xcode Command Line Tools,
`brew install autoconf automake libtool pkg-config`, для фазингу — `brew install llvm`. Конфіг — `config.yaml` з
`config.example.yaml`.

### 3. Windows 11 (без runner-а)
Встановлено: VS Build Tools 2022 (C++), Windows SDK, Git, Python 3, NuGet. WinRM (PowerShell від адміністратора):
```powershell
Enable-PSRemoting -Force -SkipNetworkProfileCheck
Set-ItemProperty HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System -Name LocalAccountTokenFilterPolicy -Value 1 -Type DWord
New-NetFirewallRule -Name WinRM-From-LAN -DisplayName "WinRM from LAN" -Protocol TCP -LocalPort 5985 -RemoteAddress <ваша мережа> -Action Allow -Profile Any
```
Windows має бачити Forgejo (порт 3000). Робоча тека CI — `C:\ci` (код у `C:\ci\yara`, пакет у `C:\ci\dist`).
`cirun` сам додає виняток Microsoft Defender для `C:\ci`: тестові зразки навмисно схожі на шкідливі
(без цього Defender блокує, наприклад, `lnk_lolbin.lnk` — Python бачить це як `Errno 22 Invalid argument`).

### 4. Ubuntu Server (стенд, SSH)
```sh
sudo apt install -y build-essential autoconf automake libtool pkg-config flex bison libssl-dev \
  libjansson-dev libmagic-dev clang llvm rsync git python3
```
Доступ — за ключем SSH (`CI_SSH_KEY`), ключ хоста — у `CI_KNOWN_HOSTS` (`known_hosts` перевіряється завжди).

### 5. VS Code
`.vscode/tasks.json` уже в репозиторії:
- **▷** (Code Runner, `.vscode/settings.json`) → `cirun --release`: прогін і після зеленого — push і реліз vX.Y.Z;
- **Cmd+Shift+B** → «DocScan CI»: той самий прогін без релізу (push на GitHub після зеленого — так само);
- *Terminal → Run Task…* → «DocScan CI + GitHub release …» (`--release`, `--bump minor`, `--watch`),
  «DocScan CI (no fuzzing)», «DocScan local: build + tests on this Mac (no push)», «Rules: check …», «Rules: release …».

Адресу Forgejo і токени `cirun` бере з `config.yaml` (розділи `forgejo`, `pipeline`, посилання на KeePassXC).

## Як користуватися
1. **▷ угорі праворуч** (при відкритому файлі проєкту; Code Runner, `.vscode/settings.json`) або **Cmd+Shift+B**.
2. Якщо є незакомічені зміни, скрипт сам робить `git add -A` і **один коміт** (повідомлення — `-m "…"` або
   автоматичне «ci: <файли>»); push — лише після зеленого прогону. Перед комітом — **перевірка для публічного репозиторію**: внутрішні
   IP, імена хостів/користувачів, паролі й токени в лапках, 40-символьні токени, файли > 5 МБ. Знайдено щось —
   нічого не комітиться, файли лишаються як є, у терміналі видно, де саме. Вимкнути автокоміт: `--no-commit`.
   Винятки — `skipChecks` у `gitops/git.go` (згенеровані vendor-правила; самі правила тепер у окремому репозиторії,
   а `docscan-project/rules/` — у `.gitignore`).
3. Далі в терміналі: машина кожної платформи, кожен крок з результатом і відсотком; режим `local` — після
   зеленого push на GitHub; режим `forgejo` — після зеленого macOS запуск прогону Forgejo і кінець (з `--watch` —
   очікування його результату).
4. Наприкінці — `RESULT: SUCCESS/FAILURE`, підсумок по системах і артефакти в `ci-out/run-<час>/`
   (`windows/DocScan-<дата>-<коміт>.zip` — готовий пакет; `macos/yara-darwin-arm64.tar.gz`; логи кроків).
5. Прогін Forgejo (режим `forgejo`) — Forgejo → репозиторій → **Дії** → прогін; статуси коміту `cirun/<стенд>`,
   `cirun/result`, `cirun/publish`.

Червоне — відкрити лог кроку (`<крок>.log` в артефактах або в Дії). Еталон документів змінюється лише
свідомо: `python3 docscan-project/ci/check_verdicts.py --yara ./yara --rules … --samples … --expected … --write`.

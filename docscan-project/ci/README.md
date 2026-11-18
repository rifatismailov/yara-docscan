# CI для DocScan: одна кнопка → збірка і всі тести на macOS, Windows і Linux

Натискаєте **▷** або **Cmd+Shift+B** у VS Code — і `cirun` (Go, `docscan-project/ci/cirun/`):

```
коміт локальних змін (перевірка безпеки, БЕЗ push)
        │
        ▼
хвиля 1 (паралельно):  macOS — цей Мак (local)          Windows — ВМ, інакше ПК 216 (WinRM)
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
         → запуск .forgejo/workflows/pipeline.yml → у терміналі: стан завдань і статус кожного стенда
Forgejo  probe: які стенди доступні (недоступний → SKIPPED (host offline), прогін не падає)
         win11 (Windows 11):            MSBuild + Go-watcher, 42 зразки, пісочниця, пакет, установка + watcher
         srv2019 (Windows Server 2019): пакет win11, повний набір (третій прохід, ворожі файли, корпус,
         win10 (Windows 10)             шкідливе ПЗ — лише сканування, установка + watcher)
         ubuntu (Ubuntu Server):        власна збірка, повний набір, фазинг
         report: [CI/CD] <стенд> -> OK | ERROR | SKIPPED, [RESULT] Verified on: ...
         лише без жодного ERROR: перевірка безпеки комітів → git push на GitHub → (з ▷) реліз vX.Y.Z:
         пакет Windows + DocScan-Install.ps1, yara-docscan-linux-x64.tar.gz, yara-docscan-macos-arm64.tar.gz,
         у описі — таблиця «Verified on»
```

- ▷ = з релізом; Cmd+Shift+B = без релізу (push на GitHub після зеленого прогону — так само).
- Раннер `lan` — у контейнері поруч з Forgejo; усі завдання прогону ділять теку `~/ci-art/<прогін>` на ньому,
  тож пакет win11 доходить до інших стендів без сторонніх сховищ.
- Адреси й облікові дані стендів — у секретах Forgejo: `CIRUN_CONFIG` (конфіг стендів з `env:`-посиланнями),
  `CI_WIN11_PASS`, `CI_SRV2019_PASS`, `CI_WIN10_PASS`, `CI_SSH_KEY`, `CI_KNOWN_HOSTS`, `CI_STORE_TOKEN`,
  `CI_GITHUB_TOKEN`, `CI_FORGEJO_TOKEN`. У публічному workflow нічого внутрішнього немає.
- Підкоманди для завдань workflow (`cirun/pipeline.go`): `probe`, `stand`, `report`, `publish`; ▷-частина —
  `cirun/forgejo_run.go`. Повернутися до старого режиму (усе з Мака): `pipeline.mode: local`.
- Стенди без Microsoft Defender (на тестових машинах він вимкнений політикою: забирав би тестові зразки).

## Що де лежить

| Файл | Що робить |
|---|---|
| `docscan-project/ci/config.yaml` | **налаштування** (не в git: внутрішні адреси); зразок — `config.example.yaml` |
| `docscan-project/ci/cirun/main.go` | прапорці, порядок: коміт → збірка → Forgejo → розгортання |
| `cirun/config/` | розбір YAML (`config.go`), посилання на секрети `keepassxc:` / `hosts:` / `env:` (`secrets.go`) |
| `cirun/transport/` | інтерфейс `Transport` і підключення: `local.go`, `ssh.go` (known_hosts перевіряється), `winrm.go` |
| `cirun/platform/` | інтерфейс `Platform` (Prepare → SyncSource → Build → Test → FetchArtifacts); `unix.go` — macOS і Linux, `windows.go` |
| `cirun/orchestrator/` | хвилі з `requires`, хід і відсоток у терміналі, підсумок, push коміту на GitHub |
| `cirun/forgejo/` | необов'язково: доступність, mirror-sync / push у Forgejo, статуси коміту |
| `cirun/platform/gowatcher.go` | Go-watcher для пакета: `git archive` теки `watcher-go` точного коміту → `go vet` + `go test` → крос-збірка `docscan-watcher.exe` (windows/amd64) на Маку → у репозиторій на Windows-машині (крок build); на Windows Go не потрібен |
| `cirun/gitops/`, `cirun/deploy/` | коміт з перевіркою безпеки, `git archive`; реліз на GitHub (`release.go`) |
| `docscan-project/ci/build-test-unix.sh [all\|build\|test]` | збірка і тести на macOS / Linux (cirun кличе `build`, потім `test`) |
| `docscan-project/ci/check_verdicts.ps1` / `.py` | перевірка документів (Windows без Python / інші ОС) |
| `docscan-project/ci/expected-verdicts.tsv` | еталон для 42 зразків `test-samples/generated` (оновлювати свідомо: `check_verdicts.py --write`) |
| `.forgejo/workflows/ci.yml` | Дія у Forgejo (нічний прогін); її завдання windows кличе `cirun windows` (змінні середовища) |

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
go run -C docscan-project/ci/cirun . -h                  # усі прапорці
```

Хід видно одразу: машина кожної платформи, кожен крок з результатом і загальним відсотком
(`[windows 10.0.0.5 (pc-216)] build PASS (57s)   74%`), раз на 30 с — рядок стану. Підсумок і артефакти —
`ci-out/run-<час>/` (`macos/yara-darwin-arm64.tar.gz`, `windows/DocScan-<версія>.zip`, логи кроків, `summary.txt`).

Код виходу: **0** — усе зелене, коміт на GitHub (і набір викладено, якщо публікацію увімкнено); **1** — провал
(збірка, тести або публікація набору); **2** — зелене, але push на GitHub не вдався (повторити: `--push-only`).

## Конфіг і паролі (KeePassXC)

Паролів у `config.yaml` немає — лише посилання, які cirun розгортає під час запуску:

```yaml
password_ref: "keepassxc:CI/Windows/pc-216"            # поле Password запису
user_ref:     "keepassxc:CI/Windows/pc-216#UserName"   # інший атрибут: UserName, URL, Notes
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

ПК 216 — робоча станція: `full_tests: false`, лише збірка і documents (без корпусів і шкідливого ПЗ).

### Бойовий тест (`--combat`, лише Windows, ~2 год)

```sh
go run -C docscan-project/ci/cirun . --combat --only windows --fuzz 0
```

Перевіряє систему так, як вона працює на робочій станції, а не `yara64` напряму:

| Крок | Що |
|---|---|
| combat-setup | `combat_setup.ps1`: пакет цього коміту → `install.ps1` (оновлення: `C:\Program Files\DocScan`, `C:\ProgramData\DocScan`, завдання «DocScan Watcher» від SYSTEM; watcher стежить за `C:\Users` і тестовою текою `C:\ci\inbox`); тестові файли з **файлового сервера** (`fileserver` у config.yaml): `yara\corpus`, `yara\seeds`, `yara\malware\malware.zip` і `provided.zip` (пароль `infected`, розпаковуються лише в `C:\ci\combat`) + 42 зразки з git; знімок стану |
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

### Навантажувальний тест (термінальний сервер, вручну)

Не входить у ▷: окремий тестовий сервер Windows Server з роллю RD Session Host, N справжніх RDP-сесій
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
- Лише Мак і тестові ВМ; **ніколи на 216** і **ніколи в git**; на ВМ видаляється після кожного тесту.
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
DocScan-windows-x64.zip + .sha256   повний пакет: bin\ (yara64, yarac64, рантайм VC++), rules\, watcher\, install.ps1 ...
DocScan-Install.ps1                 єдиний скрипт для ПК
```

- Імена активів однакові в усіх релізах — `releases/latest/download/<ім'я>` завжди дає найновіший (без GitHub API
  і його ліміту 60 запитів/год з однієї адреси).
- `gh release create` (gh на Маку, авторизований), потім пакет качається за публічною адресою і звіряється SHA256.
  Наявний реліз не перезаписується (якщо його пакет — саме ця збірка, це не помилка). Репозиторій —
  `release.repo` у `config.yaml`, порожньо — з адреси `push.remote`.
- На ПК: `DocScan-Install.ps1` качає пакет з релізу, звіряє SHA256, запускає `install.ps1` з пакета (той ще раз
  звіряє кожен файл з `SHA256SUMS.txt`). Правила E5Search у реліз не входять: `-Critical <файл / UNC / URL>`.
- Довіра — обліковому запису GitHub (увімкнена 2FA обов'язкова): хто може створити реліз, той ставить програму на ПК.
- Не зелений або не запушений прогін релізу не робить ніколи.

## Налаштування з нуля (покроково)

### 1. Forgejo (сервер)
1. Репозиторій-дзеркало GitHub: *Новий репозиторій → Міграція → Git*, адреса GitHub, «Дзеркало», інтервал 1 год.
2. Увімкнути **Дії** в репозиторії: *Налаштування → Розширені налаштування → «Дії»* (для дзеркал вимкнено за замовчуванням).
3. **Секрети** (*Налаштування репозиторію → Дії → Секрети*):

   | Секрет | Значення |
   |---|---|
   | `WIN11_HOST`, `WIN11_USER`, `WIN11_PASS` | адреса і обліковий запис Windows 11 з увімкненим WinRM |
   | `CI_GIT_TOKEN` | токен Forgejo лише з правом `read:repository` (Windows бере ним код) |

4. **Змінні** (*… → Дії → Змінні*):

   | Змінна | Значення |
   |---|---|
   | `WIN11` | `true` — запускати завдання Windows (поки ВМ вимкнена — не ставити) |
   | `LINUX_RUNNER` | `true` — коли є runner на Ubuntu |
   | `CI_SEEDS_MACOS`, `CI_SEEDS_LINUX` | тека з корпусом документів на runner-і (для ворожих файлів); порожньо — крок пропускається |

5. Токен реєстрації runner-а: *Налаштування репозиторію → Дії → Виконавці → «Створити виконавця»*.

### 2. Мак (runner `macos` + `winrm`)
```sh
brew install node forgejo-runner python go   # node — для actions/checkout і upload-artifact; go — для ci-run
mkdir -p ~/docscan-ci/runner && cd ~/docscan-ci/runner
forgejo-runner generate-config > config.yaml # у config.yaml: runner.capacity: 2
forgejo-runner register --no-interactive --instance http://<forgejo>:3000 \
  --token <токен реєстрації> --name mac-docscan --labels macos:host,winrm:host --config config.yaml
```
Автозапуск — `~/Library/LaunchAgents/org.forgejo.runner.docscan.plist` (`forgejo-runner daemon --config
~/docscan-ci/runner/config.yaml`, `PATH` з `/opt/homebrew/bin`, `RunAtLoad`, `KeepAlive`), потім
`launchctl load ~/Library/LaunchAgents/org.forgejo.runner.docscan.plist`. Лог — `~/docscan-ci/runner/runner.log`.
Для збірки на Маку потрібні Xcode Command Line Tools, `brew install autoconf automake libtool pkg-config`,
для фазингу — `brew install llvm`. Runner працює, поки ви увійшли в систему.

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

### 4. Ubuntu Server (runner `linux`, згодом і `winrm`)
```sh
sudo apt install -y build-essential autoconf automake libtool pkg-config flex bison libssl-dev \
  libjansson-dev libmagic-dev clang llvm rsync git python3 nodejs && sudo snap install go --classic   # Go ≥ 1.26
curl -Lo forgejo-runner https://code.forgejo.org/forgejo/runner/releases/download/v<версія>/forgejo-runner-<версія>-linux-amd64
sudo install -m 755 forgejo-runner /usr/local/bin/
forgejo-runner generate-config > config.yaml
forgejo-runner register --no-interactive --instance http://<forgejo>:3000 --token <токен> \
  --name ubuntu-docscan --labels linux:host,winrm:host --config config.yaml
```
Служба systemd: `forgejo-runner daemon --config /home/<user>/runner/config.yaml`. Потім змінна `LINUX_RUNNER = true`.

### 5. VS Code
`.vscode/tasks.json` уже в репозиторії:
- **Cmd+Shift+B** → «DocScan CI»: коміт → усі системи + фазинг 300 с → push, лише якщо зелене (реліз — лише з `--release`);
- *Terminal → Run Task…* → «DocScan CI (no fuzzing)», «DocScan local: build + tests on this Mac (no push)».

Адресу Forgejo і токени `cirun` бере з `config.yaml` (розділ `forgejo`, посилання на KeePassXC). Кнопка в рядку стану — розширення *Task Buttons*
(у `settings.json`: `"VsCodeTaskButtons.tasks": [{"label": "$(play) DocScan CI", "task": "DocScan CI"}]`).

## Як користуватися
1. **▷ угорі праворуч** (при відкритому файлі проєкту; Code Runner, `.vscode/settings.json`) або **Cmd+Shift+B**.
2. Якщо є незакомічені зміни, скрипт сам робить `git add -A` і **один коміт** (повідомлення — `-m "…"` або
   автоматичне «ci: <файли>»), потім push. Перед комітом — **перевірка для публічного репозиторію**: внутрішні
   IP, імена хостів/користувачів, паролі й токени в лапках, 40-символьні токени, файли > 5 МБ. Знайдено щось —
   нічого не комітиться, файли лишаються як є, у терміналі видно, де саме. Вимкнути автокоміт: `--no-commit`.
   Винятки (`skipChecks` у `gitops/git.go`): згенеровані vendor-правила (`rules/general/`, `rules/maldoc/`,
   `rules/LICENSE-*`) — чужий публічний текст із хешами комітів, SHA-1 зразків, назвами фірм із сертифікатів і
   рядками атакувальних інструментів — перевірку рядків не проходять (розмір файлу — так); у
   `build_vendor_rules.py` дозволені 40-символьні хеші закріплених комітів. Правила руками не редагуються.
3. Далі в терміналі: машина кожної платформи, кожен крок з результатом і відсотком; після зеленого — push на GitHub.
4. Наприкінці — `RESULT: SUCCESS/FAILURE`, підсумок по системах і артефакти в `ci-out/run-<час>/`
   (`windows/DocScan-<дата>-<коміт>.zip` — готовий пакет; `macos/yara-darwin-arm64.tar.gz`; логи кроків).
5. Нічна Дія у Forgejo (якщо увімкнено) — Forgejo → репозиторій → **Дії** → прогін.

Червоне — відкрити лог кроку (`<крок>.log` в артефактах або в Дії). Еталон документів змінюється лише
свідомо: `python3 docscan-project/ci/check_verdicts.py --yara ./yara --rules … --samples … --expected … --write`.

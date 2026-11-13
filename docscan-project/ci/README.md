# CI для DocScan: одна кнопка → збірка і всі тести на macOS, Windows і Linux

Натискаєте **▷** або **Cmd+Shift+B** у VS Code — і `cirun` (Go, `docscan-project/ci/cirun/`):

```
коміт локальних змін (перевірка безпеки, БЕЗ push)
        │
        ▼
хвиля 1 (паралельно):  macOS — цей Мак (local)          Windows — ВМ, інакше ПК 216 (WinRM)
                       build → documents → critical →    checkout (git або zip) → build (MSBuild) →
                       hostile → fuzz → yara-*.tar.gz     documents → critical → DocScan-<версія>.zip
        │  обидві зелені?
        ▼
хвиля 2:               Linux — Ubuntu (SSH): те саме, що на macOS        (requires: [windows, macos])
        │  усе зелене?
        ▼
git push на GitHub (push.remote) — ЗАВЖДИ, від Forgejo не залежить
        │                (Forgejo, якщо увімкнено й доступний: mirror-sync і статуси cirun/<ОС>)
        ▼
набір для розгортання → сервер (scp, sha256, DocScan-latest.txt) → RESULT
```

Отже, на GitHub потрапляє **лише протестований** коміт, а слухач на іншому сервері сам бачить його там і
запускає свої тести. Forgejo для цього не потрібен.

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
| `cirun/gitops/`, `cirun/deploy/` | коміт з перевіркою безпеки, `git archive`; набір для розгортання і публікація на сервер |
| `docscan-project/ci/build-test-unix.sh [all\|build\|test]` | збірка і тести на macOS / Linux (cirun кличе `build`, потім `test`) |
| `docscan-project/ci/check_verdicts.ps1` / `.py` | перевірка документів (Windows без Python / інші ОС) |
| `docscan-project/ci/expected-verdicts.tsv` | еталон для 41 зразка `test-samples/generated` (оновлювати свідомо: `check_verdicts.py --write`) |
| `.forgejo/workflows/ci.yml` | Дія у Forgejo (нічний прогін); її завдання windows кличе `cirun windows` (змінні середовища) |

Тести в кожному прогоні: **документи** (41 зразок, серед них 7 макросів VBA, 4 регресії хибних тривог / шифрування і 6 zip-архівів: вердикт, лікування,
повторний скан, оригінали не змінені), **3-й прохід** (`test-critical/run_tests.py`, 299 перевірок), **ворожі файли**
(35, якщо на машині є корпус `seeds`), **фазинг** (обидва фазери, ASan + UBSan; на Windows не запускається).

## Запуск

Go ≥ 1.26 (`brew install go`). З кореня репозиторію (так роблять ▷, Cmd+Shift+B і задачі VS Code):

```sh
go run -C docscan-project/ci/cirun .                     # повний прогін
go run -C docscan-project/ci/cirun . --plan              # перевірити конфіг, секрети, машини, GitHub — без збірки
go run -C docscan-project/ci/cirun . --only macos        # лише ці платформи (через кому)
go run -C docscan-project/ci/cirun . --fuzz 0            # без фазингу
go run -C docscan-project/ci/cirun . --no-publish        # без набору на сервер
go run -C docscan-project/ci/cirun . --no-push           # не пушити коміт на GitHub
go run -C docscan-project/ci/cirun . --push-only         # лише git push HEAD на GitHub (після зеленого прогону)
go run -C docscan-project/ci/cirun . -h                  # усі прапорці
```

Хід видно одразу: машина кожної платформи, кожен крок з результатом і загальним відсотком
(`[windows 10.0.0.5 (pc-216)] build PASS (57s)   74%`), раз на 30 с — рядок стану. Підсумок і артефакти —
`ci-out/run-<час>/` (`macos/yara-darwin-arm64.tar.gz`, `windows/DocScan-<версія>.zip`, логи кроків, `summary.txt`).

Код виходу: **0** — усе зелене, коміт на GitHub, набір викладено; **1** — провал (збірка, тести або
публікація набору); **2** — зелене, але push на GitHub не вдався (повторити: `--push-only`).

## Конфіг і паролі (KeePassXC)

Паролів у `config.yaml` немає — лише посилання, які cirun розгортає під час запуску:

```yaml
password_ref: "keepassxc:CI/Windows/pc-216"            # поле Password запису
user_ref:     "keepassxc:CI/Windows/pc-216#UserName"   # інший атрибут: UserName, URL, Notes
token_ref:    "keepassxc:CI/Forgejo/api-token"
# також: "hosts:<профіль>[.<поле>]" (старий ~/.docscan/hosts.json), "env:<ЗМІННА>"
```

База — `~/.docscan/docscan-ci.kdbx` (окрема, лише для CI; групи `CI/Windows`, `CI/Forgejo`, `CI/Deploy`,
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
| documents | 41 неактивний зразок: вердикт, лікування, повторний скан | git (`test-samples/generated`) |
| critical | третій прохід, 299 перевірок | створює сам |
| hostile | 35 ворожих файлів (зламані, гігантські, глибока вкладеність) | з корпусу seeds |
| corpus | ~4 000 документів з публічних тестових корпусів | POI, pdf.js, plaso, LibreOffice RTF, LNK, Apache Tika, oletools |
| malware | **справжнє** шкідливе ПЗ — 949 зразків (майнер XMRig, EICAR, theZoo, InQuest, MalwareBazaar): лише сканування, ніколи не запускається | `~/docscan-ci/malware` |
| fuzz | фазинг (на Windows — фазер розбору, clang-cl + ASan) | — |

ПК 216 — робоча станція: `full_tests: false`, лише збірка і documents (без корпусів і шкідливого ПЗ).

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
| `bazaar/<тип>/` | 255 свіжих зразків за типами: doc docm xls xlsm rtf lnk one zip iso js hta vbs ps1 exe dll pdf msi xll | MalwareBazaar API (ключ — `keepassxc:CI/abuse.ch/auth-key`) |

Оновити `expected.txt` (після свідомої зміни правил): прогнати `check_corpus.py` по теці й записати всі
виявлені шляхи; старі шляхи не повинні зникнути — інакше це регресія, а не оновлення.

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

## Набір для розгортання і публікація

Після **зеленого** прогону в `ci-out/<прогін>/deploy/` лежить усе для розгортання:

```
DocScan-<дата>-<коміт>.zip + .sha256     пакет
DocScan-latest.txt                       ім'я поточного пакета
DocScan-Install.ps1                      інсталятор з сервера
DocScan-Setup.ps1 / -Pilot / -Critical   завантажувачі для irm | iex (адреса сервера вже підставлена)
critical-rules.yar                       правила E5Search (якщо задано deploy.critical_rules у config.yaml)
```

**Публікація — за замовчуванням** (▷ / Cmd+Shift+B): набір іде на
сервер розгортання по ssh, звіряє SHA256 на сервері і лише тоді перемикає `DocScan-latest.txt` — з цього моменту
`irm http://<сервер>:8080/docscan/DocScan-Setup.ps1 | iex` ставить новий пакет. Не зелений прогін — не публікується.
Без публікації: `--no-publish` (*Run Task → «DocScan CI without publishing»*). Викласти готовий набір без збірки:
`go run -C docscan-project/ci/cirun . --publish-dir ci-out/<прогін>/deploy`.

Сервер розгортання — розділ `deploy` у `config.yaml` (`host`, `user_ref`, `password_ref`, `dir`, `url`,
`critical_rules`). Для нічної Дії у Forgejo (завдання windows → `cirun windows`) потрібні секрети Forgejo
`WIN11_*` / `WIN216_*` (`HOST`, `USER`, `PASS`) і `CI_GIT_TOKEN`.

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
- **Cmd+Shift+B** → «DocScan CI»: коміт → усі системи + фазинг 300 с → push і набір (якщо зелене);
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
3. Далі в терміналі: push → синхронізація → «run #N: <посилання>» → стан кожної системи.
3. Наприкінці — `RESULT: SUCCESS/FAILURE`, підсумок по системах і артефакти в `ci-out/run-<N>/`
   (`windows11/DocScan-<дата>-<коміт>.zip` — готовий пакет; `macos/yara-darwin-arm64.tar.gz`; логи кроків).
4. Те саме — у Forgejo → репозиторій → **Дії** → прогін (логи кожного кроку, кнопки завантаження артефактів).

Червоне — відкрити лог кроку (`<крок>.log` в артефактах або в Дії). Еталон документів змінюється лише
свідомо: `python3 docscan-project/ci/check_verdicts.py --yara ./yara --rules … --samples … --expected … --write`.

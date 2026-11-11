# CI для DocScan: одна кнопка → збірка і всі тести на macOS, Windows 11 і Linux

Натискаєте **Cmd+Shift+B** у VS Code (або «Запустити робочий процес» у Forgejo) — і:

```
VS Code ─► ci-run (Go): git push на GitHub → Forgejo оновлює дзеркало → запускає Дію "build-test"
                                                        │
          ┌─────────────────────────────────────────────┼──────────────────────────────────┐
          ▼                                             ▼                                  ▼
  runner на Маку (мітка macos)          runner з міткою winrm (Мак, згодом Ubuntu)   runner на Ubuntu (мітка linux)
  build-test-unix.sh:                   ci-run windows → WinRM → Windows 11:          build-test-unix.sh:
   збірка, документи, 3-й прохід,        git fetch коміту, MSBuild, документи,         те саме, що на Маку
   ворожі файли, фазинг                  3-й прохід, пакет DocScan-<версія>.zip
          └─────────────────────────────────────────────┼──────────────────────────────────┘
                                                        ▼
            Forgejo → Дії → прогін: ✅/❌ по кожній системі + артефакти (macos / windows11 / linux)
            ci-run показує хід у терміналі VS Code і забирає артефакти в ci-out/run-<N>/
```

## Що де лежить

| Файл | Де працює | Що робить |
|---|---|---|
| `.forgejo/workflows/ci.yml` | Forgejo | Опис конвеєра: три завдання (`macos`, `windows11`, `linux`), які runner-и їх беруть, секрети, артефакти, нічний прогін (фазинг 1 год) |
| `docscan-project/ci/build-test-unix.sh` | Мак, Ubuntu | Збірка → документи → 3-й прохід → ворожі файли (якщо задано `CI_SEEDS`) → фазинг (`FUZZ_SECONDS`) → `ci-out/artifacts` |
| `docscan-project/ci/cirun/windows.go` (`ci-run windows`) | runner з міткою `winrm` або Мак (локальний режим) | Вибирає Windows-машину (ВМ, інакше 216), точний коміт (git або zip), MSBuild, тести, `build_package.ps1`, забирає zip |
| `docscan-project/ci/check_verdicts.ps1` | Windows | Перевірка документів без Python (те саме, що `check_verdicts.py`) |
| `docscan-project/ci/check_verdicts.py` | усі ОС | Документи: копія → детект + лікування → повторний скан, порівняння з `expected-verdicts.tsv` |
| `docscan-project/ci/expected-verdicts.tsv` | — | Еталон для 24 зразків `test-samples/generated` (оновлювати свідомо: `check_verdicts.py --write`) |
| `docscan-project/ci/cirun/` (Go: `main.go`, `forgejo.go`) | ваш Мак | «Кнопка»: коміт змін (з перевіркою) → push → синхронізація дзеркала → запуск Дії → стеження → артефакти → набір для розгортання → публікація |
| `.vscode/tasks.json` | VS Code | Завдання «DocScan CI» (Cmd+Shift+B), «без фазингу», «локально на Маку без push» |

Тести в кожному прогоні: **документи** (24 зразки: вердикт, лікування, повторний скан, оригінали не змінені),
**3-й прохід** (`test-critical/run_tests.py`, 299 перевірок), **ворожі файли** (35, якщо на runner-і є корпус),
**фазинг** (обидва фазери, ASan + UBSan; на Windows не запускається — libFuzzer там лише через clang-cl).

## ci-run (Go)

Головний інструмент — програма на Go в `docscan-project/ci/cirun/` (Go ≥ 1.24, `brew install go`). Запуск з кореня
репозиторію (так роблять ▷, Cmd+Shift+B і задачі VS Code):

```sh
go run -C docscan-project/ci/cirun .                 # коміт, push, збірка + тести, публікація
go run -C docscan-project/ci/cirun . --no-publish    # без публікації на сервер
go run -C docscan-project/ci/cirun . --fuzz 0        # без фазингу
go run -C docscan-project/ci/cirun . --local         # без Forgejo, прямо з Мака
go run -C docscan-project/ci/cirun . -h              # усі прапорці
```

У локальному режимі хід видно одразу: на якій машині й IP іде кожна задача, кожен завершений крок з
результатом і загальним відсотком (`[windows 10.0.0.5 (fallback PC)] build PASS (57s)   74%`), а раз на 30 с —
рядок стану (`... macos: fuzz 95s/190s | windows: documents 40s   ~63%`). Відсоток — оцінка за звичайною
тривалістю кроків. Повні логи — `ci-out/local-<час>/macos.log` і `windows.log`.

`go run` сам компілює програму (перший раз — кілька секунд, потім із кешу). Python для оркестрації більше не
потрібен; тести (`check_verdicts.py`, `test-critical/*.py`) і далі на Python — їх запускає збірка.

## Режими і запасна Windows-машина

`ci-run` сам вибирає, як працювати:

| Що доступно | Що відбувається |
|---|---|
| **Forgejo** (Proxmox працює) | Дія `build-test` у Forgejo: Мак (`macos`), Windows (`windows`), Ubuntu (`linux`, коли буде) |
| **Forgejo недоступний** (або `--local`) | **Локальний режим** — те саме прямо з Мака: `build-test-unix.sh` тут, `ci-run windows` по WinRM |

Windows-машину `ci-run windows` вибирає сам: **ВМ Windows 11** (Proxmox), якщо відповідає, інакше
**запасний ПК** (профіль `216`). Якщо машина не бачить Forgejo, код потрапляє на неї zip-архівом точного коміту
(`git archive`, ~5 МБ) по WinRM. Перевірка документів на Windows — `check_verdicts.ps1` (Python не потрібен);
тести третього проходу — лише там, де є справжній Python (інакше `SKIP`, вони йдуть на macOS/Linux). Немає NuGet —
береться готовий кеш пакетів збірки (`C:\docscan-build\yara\windows\vs2019\packages`) або завантажується `nuget.exe` у `C:\ci\tools`.

## Набір для розгортання і публікація

Після **зеленого** прогону в `ci-out/<прогін>/deploy/` лежить усе для розгортання:

```
DocScan-<дата>-<коміт>.zip + .sha256     пакет
DocScan-latest.txt                       ім'я поточного пакета
DocScan-Install.ps1                      інсталятор з сервера
DocScan-Setup.ps1 / -Pilot / -Critical   завантажувачі для irm | iex (адреса сервера вже підставлена)
critical-rules.yar                       правила E5Search (якщо задано в hosts.json "fs".critical_rules)
```

**Публікація — за замовчуванням** (▷ / Cmd+Shift+B): набір іде на
сервер розгортання по ssh, звіряє SHA256 на сервері і лише тоді перемикає `DocScan-latest.txt` — з цього моменту
`irm http://<сервер>:8080/docscan/DocScan-Setup.ps1 | iex` ставить новий пакет. Не зелений прогін — не публікується.
Без публікації: `--no-publish` (*Run Task → «DocScan CI without publishing»*). Викласти готовий набір без збірки:
`go run -C docscan-project/ci/cirun . --publish-dir ci-out/<прогін>/deploy`.

Налаштування в `~/.docscan/hosts.json` (не в репозиторії): `forgejo` (`url`, `token`, `ci_checkout_token`),
`vm` і `216` (Windows-машини: `host`, `user`, `password`), `fs` (`host`, `user`, `password`, `deploy_dir`
= `scripts/docscan`, `deploy_url` = `http://<сервер>:8080/docscan`, `critical_rules`).
У Forgejo для запасного ПК потрібні ще секрети `WIN216_HOST`, `WIN216_USER`, `WIN216_PASS`.

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
`ci-run windows` сам додає виняток Microsoft Defender для `C:\ci`: тестові зразки навмисно схожі на шкідливі
(без цього Defender блокує, наприклад, `lnk_lolbin.lnk` — Python бачить це як `Errno 22 Invalid argument`).

### 4. Ubuntu Server (runner `linux`, згодом і `winrm`)
```sh
sudo apt install -y build-essential autoconf automake libtool pkg-config flex bison libssl-dev \
  libjansson-dev libmagic-dev clang llvm rsync git python3 nodejs && sudo snap install go --classic   # Go ≥ 1.24
curl -Lo forgejo-runner https://code.forgejo.org/forgejo/runner/releases/download/v<версія>/forgejo-runner-<версія>-linux-amd64
sudo install -m 755 forgejo-runner /usr/local/bin/
forgejo-runner generate-config > config.yaml
forgejo-runner register --no-interactive --instance http://<forgejo>:3000 --token <токен> \
  --name ubuntu-docscan --labels linux:host,winrm:host --config config.yaml
```
Служба systemd: `forgejo-runner daemon --config /home/<user>/runner/config.yaml`. Потім змінна `LINUX_RUNNER = true`.

### 5. VS Code
`.vscode/tasks.json` уже в репозиторії:
- **Cmd+Shift+B** → «DocScan CI»: push + усі системи + фазинг 300 с;
- *Terminal → Run Task…* → «DocScan CI (no fuzzing)», «DocScan local: build + tests on this Mac (no push)».

`ci-run` бере адресу Forgejo і токен з `~/.docscan/hosts.json` (профіль `forgejo`: `url`, `token`) або зі
змінних середовища `FORGEJO_URL` / `FORGEJO_TOKEN`. Кнопка в рядку стану — розширення *Task Buttons*
(у `settings.json`: `"VsCodeTaskButtons.tasks": [{"label": "$(play) DocScan CI", "task": "DocScan CI"}]`).

## Як користуватися
1. **▷ угорі праворуч** (при відкритому файлі проєкту; Code Runner, `.vscode/settings.json`) або **Cmd+Shift+B**.
2. Якщо є незакомічені зміни, скрипт сам робить `git add -A` і **один коміт** (повідомлення — `-m "…"` або
   автоматичне «ci: <файли>»), потім push. Перед комітом — **перевірка для публічного репозиторію**: внутрішні
   IP, імена хостів/користувачів, паролі й токени в лапках, 40-символьні токени, файли > 5 МБ. Знайдено щось —
   нічого не комітиться, файли лишаються як є, у терміналі видно, де саме. Вимкнути автокоміт: `--no-commit`.
3. Далі в терміналі: push → синхронізація → «run #N: <посилання>» → стан кожної системи.
3. Наприкінці — `RESULT: SUCCESS/FAILURE`, підсумок по системах і артефакти в `ci-out/run-<N>/`
   (`windows11/DocScan-<дата>-<коміт>.zip` — готовий пакет; `macos/yara-darwin-arm64.tar.gz`; логи кроків).
4. Те саме — у Forgejo → репозиторій → **Дії** → прогін (логи кожного кроку, кнопки завантаження артефактів).

Червоне — відкрити лог кроку (`<крок>.log` в артефактах або в Дії). Еталон документів змінюється лише
свідомо: `python3 docscan-project/ci/check_verdicts.py --yara ./yara --rules … --samples … --expected … --write`.

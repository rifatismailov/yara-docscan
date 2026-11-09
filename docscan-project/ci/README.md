# CI для DocScan: одна кнопка → збірка і всі тести на macOS, Windows 11 і Linux

Натискаєте **Cmd+Shift+B** у VS Code (або «Запустити робочий процес» у Forgejo) — і:

```
VS Code ─► ci-run.py: git push на GitHub → Forgejo оновлює дзеркало → запускає Дію "build-test"
                                                        │
          ┌─────────────────────────────────────────────┼──────────────────────────────────┐
          ▼                                             ▼                                  ▼
  runner на Маку (мітка macos)          runner з міткою winrm (Мак, згодом Ubuntu)   runner на Ubuntu (мітка linux)
  build-test-unix.sh:                   windows-remote.py → WinRM → Windows 11:       build-test-unix.sh:
   збірка, документи, 3-й прохід,        git fetch коміту, MSBuild, документи,         те саме, що на Маку
   ворожі файли, фазинг                  3-й прохід, пакет DocScan-<версія>.zip
          └─────────────────────────────────────────────┼──────────────────────────────────┘
                                                        ▼
            Forgejo → Дії → прогін: ✅/❌ по кожній системі + артефакти (macos / windows11 / linux)
            ci-run.py показує хід у терміналі VS Code і забирає артефакти в ci-out/run-<N>/
```

## Що де лежить

| Файл | Де працює | Що робить |
|---|---|---|
| `.forgejo/workflows/ci.yml` | Forgejo | Опис конвеєра: три завдання (`macos`, `windows11`, `linux`), які runner-и їх беруть, секрети, артефакти, нічний прогін (фазинг 1 год) |
| `docscan-project/ci/build-test-unix.sh` | Мак, Ubuntu | Збірка → документи → 3-й прохід → ворожі файли (якщо задано `CI_SEEDS`) → фазинг (`FUZZ_SECONDS`) → `ci-out/artifacts` |
| `docscan-project/ci/windows-remote.py` | runner з міткою `winrm` | Керує Windows по WinRM: точний коміт з Forgejo, MSBuild, ті самі тести, `build_package.ps1`, забирає zip |
| `docscan-project/ci/check_verdicts.py` | усі ОС | Документи: копія → детект + лікування → повторний скан, порівняння з `expected-verdicts.tsv` |
| `docscan-project/ci/expected-verdicts.tsv` | — | Еталон для 24 зразків `test-samples/generated` (оновлювати свідомо: `check_verdicts.py --write`) |
| `docscan-project/ci/ci-run.py` | ваш Мак | «Кнопка»: коміт змін (з перевіркою) → push → синхронізація дзеркала → запуск Дії → стеження → артефакти |
| `.vscode/tasks.json` | VS Code | Завдання «DocScan CI» (Cmd+Shift+B), «без фазингу», «локально на Маку без push» |

Тести в кожному прогоні: **документи** (24 зразки: вердикт, лікування, повторний скан, оригінали не змінені),
**3-й прохід** (`test-critical/run_tests.py`, 299 перевірок), **ворожі файли** (35, якщо на runner-і є корпус),
**фазинг** (обидва фазери, ASan + UBSan; на Windows не запускається — libFuzzer там лише через clang-cl).

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
brew install node forgejo-runner python      # node — для actions/checkout і upload-artifact
pip3 install --user pywinrm                  # для windows-remote.py (якщо ще немає)
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
`windows-remote.py` сам додає виняток Microsoft Defender для `C:\ci`: тестові зразки навмисно схожі на шкідливі
(без цього Defender блокує, наприклад, `lnk_lolbin.lnk` — Python бачить це як `Errno 22 Invalid argument`).

### 4. Ubuntu Server (runner `linux`, згодом і `winrm`)
```sh
sudo apt install -y build-essential autoconf automake libtool pkg-config flex bison libssl-dev \
  libjansson-dev libmagic-dev clang llvm rsync git python3 python3-winrm nodejs
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

`ci-run.py` бере адресу Forgejo і токен з `~/.docscan/hosts.json` (профіль `forgejo`: `url`, `token`) або зі
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

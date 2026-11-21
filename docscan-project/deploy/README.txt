DocScan — встановлення на Windows 10/11 (x64)
=============================================

DocScan стежить за новими файлами, перевіряє документи (макроси, DDE, віддалені шаблони, вкладені об'єкти…)
і vendor-правилами, лікує заражені документи, зберігає код макросів і пише результат для агента Wazuh.
На вибраних ПК (юрист, бухгалтер, кадровик) — ще й ставить документи з критичною інформацією в чергу E5Search.

1. З релізу GitHub (PowerShell від адміністратора)
--------------------------------------------------
     [Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12   # GitHub - лише TLS 1.2
     $f = "$env:TEMP\DocScan-Install.ps1"
     irm https://github.com/rifatismailov/yara-docscan/releases/latest/download/DocScan-Install.ps1 -OutFile $f
     powershell -ExecutionPolicy Bypass -File $f                          # звичайний ПК (детект + лікування)
     powershell -ExecutionPolicy Bypass -File $f -DetectOnly              # пілот: лише детект і алерти
     powershell -ExecutionPolicy Bypass -File $f -Critical <файл|URL>     # ПК юриста / бухгалтера / кадровика
                                                                          # (+ третій прохід, черга E5Search)
   Ті самі команди й оновлюють: береться останній реліз (конкретний - -Version 20261116-7b6f6764).
   Успіх - рядок "Done." у кінці.

   У релізі GitHub (vX.Y.Z, напр. v1.0.0) - усе, файлових серверів немає:
     DocScan-windows-x64.zip + .sha256   пакет: bin\ (yara64.exe, yarac64.exe, рантайм VC++), rules\, watcher\,
                                         install.ps1, uninstall.ps1, SHA256SUMS.txt, VERSION.txt
     DocScan-Install.ps1                 качає пакет, звіряє SHA256, запускає install.ps1 з пакета
   Правила E5Search (critical-rules.yar) у реліз НЕ входять (чутливі): -Critical бере їх з локального файлу,
   UNC-шляху або URL (приватний URL - -CriticalToken або змінна DOCSCAN_CRITICAL_TOKEN).
   ПК потрібен доступ до github.com і objects.githubusercontent.com (TLS 1.2).
   Білий / чорний списки організації: -Whitelist / -Blacklist <файл | UNC | URL> (приватний URL - -ListsToken або
   DOCSCAN_LISTS_TOKEN), -NoWhitelist / -NoBlacklist; щоденно з дзеркала - -ListsUrl + -ListsKey. Див. нижче.
   Інші параметри DocScan-Install.ps1: -NoCritical (вимкнути третій прохід), -MacroUpload <url> (копії коду
   макросів на колектор; без нього код лишається на ПК), -WatchPath, -NoAvExclusion, -QuarantineGeneral.
   Нова версія: cirun --release (після зеленого прогону; номер +1: v1.0.1, --bump minor -> v1.1.0).
   Конкретна версія на ПК: DocScan-Install.ps1 -Version v1.0.0.

2. Вручну з розпакованого пакета
--------------------------------
     cd C:\Temp\DocScan
     powershell -ExecutionPolicy Bypass -File .\install.ps1
   Параметри install.ps1:
     -WatchPath 'C:\Users','D:\Shares'   теки для спостереження (за замовчуванням C:\Users)
     -DetectOnly                         пілот: файли НЕ змінюються й не переносяться в карантин
                                         (увімкнути лікування — запустити install.ps1 ще раз без -DetectOnly)
     -MacroUpload http://<сервер>:8080   копії коду макросів на сервер (POST)
     -CriticalRules <файл.yar>           третій прохід: правила E5Search -> C:\Program Files\DocScan\critical\
     -NoCritical                         вимкнути третій прохід і видалити його правила
     -Whitelist / -Blacklist <файл.json> білий / чорний списки -> C:\ProgramData\DocScan\lists\ (див. нижче)
     -NoWhitelist / -NoBlacklist         прибрати список
     -ListsUrl <https://...|\\сервер\шара>  дзеркало організації з підписаними списками (щодня); -ListsToken - для закритого;
                                         -ListsKey ed25519:...
                                         - її публічний ключ; -ListsEveryHours 24
     -NoAvExclusion                      не додавати винятки Microsoft Defender
     -Workers 8                          фіксована кількість паралельних сканів (за замовчуванням — автоматично
                                         від 2 до кількості CPU, за чергою і навантаженням CPU)
     -WatcherEngine ps                   старий PowerShell-watcher (один скан за раз) замість docscan-watcher.exe
     -Rules <DocScan-rules-bundle.zip | URL>  ОБОВ'ЯЗКОВО на новому ПК: пакет правил з релізу
                                         github.com/rifatismailov/yara-docscan-rules (у пакеті програми правил немає;
                                         завантажити ДО встановлення; інсталятор перевіряє підпис CI і кожен файл).
                                         Оновлення вже встановленого ПК — без -Rules: правила лишаються, їх оновлює DocScanUpdater
     -UpdateMode github|mirror|marker|off  автооновлення (служба DocScan Updater), за замовчуванням github
     -UpdateMirror <https://...|\\сервер\шара>   mode mirror: тека з файлами релізу (manifest.json, manifest.sig, пакет)
     -UpdateMarker <файл>                mode marker: файл, який пише агент (за замовчуванням ...\update\update.json)
     -UpdateEveryHours 6                 github / mirror: як часто перевіряти
     -UpdateWindow 22:00-06:00           ставити оновлення лише в цей час
   Без -CriticalRules уже встановлені правила E5Search лишаються (звичайне оновлення їх не прибирає).

   Білий і чорний списки (C:\ProgramData\DocScan\lists\whitelist.json, blacklist.json). Організація веде їх сама.
   Watcher звіряє з ними кожен новий файл ДО сканування:
     1) чорний список, запис з sha256  -> HIGH, карантин (відомий шкідливий файл блокується завжди)
     2) білий список                   -> файл НЕ сканується (INFO "Дозволено білим списком організації")
     3) чорний список, path / lnk_target -> HIGH, карантин
     4) інакше                         -> звичайна перевірка yara64
   Так своя програма з sha256 у білому проходить навіть з теки, де *.exe заборонені, а відомий шкідливий - ніколи.
   Формат обох файлів (JSON, UTF-8; у JSON кожен \ подвоюється):
       whitelist.json
       {
         "schema": 1,
         "description": "Програми організації",
         "entries": [
           {"path": "C:\\Users\\*\\Desktop\\App*.lnk", "lnk_target": "\\\\fileserver\\BIN\\",
            "comment": "бухгалтерська програма з файлового сервера", "added": "2026-11-21", "by": "admin"},
           {"sha256": "<64 hex>", "comment": "наша внутрішня програма"}
         ]
       }
       blacklist.json
       {
         "schema": 1,
         "entries": [
           {"path": "C:\\Users\\*\\Downloads\\*.exe", "comment": "інсталятори не з Завантажень"},
           {"sha256": "<64 hex>", "comment": "відомий шкідливий файл"},
           {"lnk_target": "\\\\evil-srv\\", "comment": "заборонений сервер"}
         ]
       }
   Поля запису - хоча б одне; якщо кілька, файл має збігтися з УСІМА:
     path        де лежить файл: повний шлях з маскою; * - будь-що в межах однієї теки, ** - будь-яка глибина,
                 ? - один символ. Регістр не важливий. Змінних (%USERPROFILE%) немає - лише маски.
     lnk_target  куди веде ярлик (.lnk): мережева тека \\сервер\шара\ (у чорному можна й увесь сервер \\сервер\).
                 Ціль ярлика знає модуль docscan: ярлик спершу сканується без лікування, ціль береться зі звіту.
     sha256      вміст файлу (Get-FileHash <файл>): саме цей файл, хоч як його перейменуй; нова версія = новий хеш.
     comment / added / by - для людей (навіщо, коли, хто).
   Для ярлика на свою шару краще path + lnk_target разом: лише маска пропустить і чужий ярлик з такою назвою. У
   білому списку не можна дозволити «всі файли теки» (*.*) чи цілий сервер. Перевіряються лише типи файлів, за якими
   стежить watcher (документи, ярлики, exe / dll / скрипти / архіви...).
   Неправильний файл: install.ps1 його не ставить; зіпсований уже на ПК - watcher лишає попередню справну версію і
   пише ERROR у watcher.log; перечитує список, щойно він змінився (перезапуск не потрібен). Перевірити заздалегідь:
       docscan-updater.exe -CheckList white|black <файл>
   Ставити: DocScan-Install.ps1 -Whitelist <файл> -Blacklist <файл> (попередня версія - <файл>.prev). Оновлення
   програми й правил списки не чіпає; у публічні релізи вони не потрапляють.

   Списки з дзеркала організації (необов'язково; інакше - вручну). Служба DocScanUpdater раз на добу бере
   whitelist.json і blacklist.json разом з <файл>.sig з -ListsUrl і ставить лише список, що підписаний ключем
   організації і має "serial" більший за встановлений (старий підписаний список повторно не підсунути). Інакше
   лишається поточний, у docscan-updates.json - "error" (component "lists") -> Wazuh. Попередня версія - <файл>.prev.
     один раз:   docscan-updater.exe -NewListKey -Out org-lists.key   (секрет - у сейф; виведений ed25519:... - на ПК)
     щоразу:     docscan-updater.exe -SignList whitelist.json -Kind white -Key org-lists.key
                 (новий serial + whitelist.json.sig; обидва файли - на дзеркало)
     на ПК:      DocScan-Install.ps1 ... -ListsUrl https://lists.org.local/docscan/ -ListsKey ed25519:...
                 закрите дзеркало (Forgejo з входом, приватний репозиторій) - ще -ListsToken <токен лише для читання>
                 (у updater.json - lists.token; DocScanUpdater шле "Authorization: token ..."). Для Forgejo / Gitea
                 адреса теки - .../<власник>/<репозиторій>/raw/branch/main
   Ключ списків окремий від ключа релізів DocScan. Служба DocScanUpdater працює і з -UpdateMode off, якщо є -ListsUrl.
   Параметри встановлення запам'ятовуються (C:\ProgramData\DocScan\install.json): автооновлення зберігає режим ПК.

   Автооновлення (служба "DocScan Updater", DocScanUpdater): ставить лише релізи, підписані CI DocScan, і лише
   новішу версію; якщо нова версія не запустилась — сама повертає попередню. Як оновлюватися — у
   C:\ProgramData\DocScan\update\updater.json (можна правити, потім Restart-Service DocScanUpdater):
     github   раз на 6 год перевіряє останній реліз на GitHub;
     mirror   те саме з вашого сервера / шари (копія файлів релізу);
     marker   чекає, поки агент (Wazuh чи інший) запише update.json, напр.
              {"version": "v1.0.5", "source": "github", "request_id": "job-42"}  (усі поля необов'язкові);
     off      не оновлювати.
   Результати — C:\ProgramData\DocScan\results\docscan-updates.json (подія "Update" для Wazuh), журнал — updater.log.

3. Антивірус
------------
   Microsoft Defender: install.ps1 сам додає винятки для C:\Program Files\DocScan і C:\ProgramData\DocScan
   (якщо Defender керується GPO/Intune — додайте їх у політиці). ESET: з локального скрипта не налаштовується —
   ті самі винятки політикою в ESET PROTECT. Без винятків антивірус видалятиме бекапи з карантину і тексти
   шкідливих макросів (там оригінали шкідливих документів).

4. Wazuh
--------
   Агент: install.ps1 додає в ossec.conf <localfile> (json) на results\docscan-results.json і перезапускає
   WazuhSvc (при помилці конфігурації — відкат). Стара реалізація (active-response doc-scan / yara-scan)
   прибирається повністю, старий карантин переноситься в C:\ProgramData\DocScan\quarantine\legacy.
   На МЕНЕДЖЕРІ (root), один раз:
     1) sh manager/cleanup_manager.sh          — прибирає <command>/<active-response> doc-scan/yara-scan
     2) блок manager/local_rules.docscan.xml → /var/ossec/etc/rules/local_rules.xml
     3) /var/ossec/bin/wazuh-analysisd -t && systemctl restart wazuh-manager
   Подробиці — SCAN-FLOW.md, розділ 12.

5. Після встановлення
---------------------
   програма:    C:\Program Files\DocScan  (bin\yara64.exe, rules\, watcher\, critical\ — лише з третім проходом)
   результати:  C:\ProgramData\DocScan\results\docscan-results.json   (JSON, рядок на файл — для Wazuh)
                C:\ProgramData\DocScan\results\watcher.log          (лог для людини)
   карантин:    C:\ProgramData\DocScan\quarantine                   (оригінали вилікуваних / видалених файлів)
   макроси:     C:\ProgramData\DocScan\macros                       (код VBA документів, 90 днів / 500 МБ)
   черга:       C:\ProgramData\DocScan\critical\critical.json       (лише третій прохід; забирає інший watcher)
   Усе в C:\ProgramData\DocScan доступне лише SYSTEM і адміністраторам.
   Служба Windows "DocScan Watcher" (DocScanWatcher): стартує з Windows від SYSTEM; після збою Windows сама
   перезапускає її (через 10 с / 10 с / 60 с); зупинка й збої видно в журналі System (події 7036, 7031).
   Лікування (якщо не -DetectOnly): документи з HIGH-вектором лікуються за політикою (rules\docscan-policy.yar);
   LNK, небезпечні PDF, старі .doc/.xls з макросами, RTF з вкладеним об'єктом — у карантин.
   Файл, відкритий у Word, лікується, щойно його закриють (повтор переживає перезавантаження).

6. Перевірка й обслуговування
-----------------------------
   Get-Service DocScanWatcher, DocScanUpdater    (або services.msc -> "DocScan Watcher", "DocScan Updater")
   Get-Content "C:\Program Files\DocScan\VERSION.txt" -TotalCount 1
   Get-Content C:\ProgramData\DocScan\results\watcher.log -Encoding UTF8 -Wait
   Режим: Get-Content C:\ProgramData\DocScan\results\watcher.log -Encoding UTF8 | Select-String "start:|critical:" | Select -Last 2
     (disarm=True — лікування, disarm=False — лише детект; "critical: off" — третій прохід вимкнений)

   Змінити політику: відредагуйте C:\Program Files\DocScan\rules\docscan-policy.yar, потім
     Restart-Service DocScanWatcher
   Видалення: powershell -ExecutionPolicy Bypass -File "C:\Program Files\DocScan\uninstall.ps1" [-Purge]

Вимоги: Windows 10/11 x64, PowerShell 5.1 (є в системі), права адміністратора. Вивід усіх скриптів —
англійською (ASCII), тож кодування консолі й irm не заважають. Повна документація: docscan-project/SCAN-FLOW.md.

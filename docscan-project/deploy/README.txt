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

DocScan — встановлення на Windows 10/11 (x64)
=============================================

Найпростіше — з HTTP-сервера одним рядком (PowerShell від адміністратора):
     irm http://<сервер>:8080/DocScan-Setup.ps1 | iex          # повний режим (детект + лікування)
     irm http://<сервер>:8080/DocScan-Setup-Pilot.ps1 | iex    # пілот: лише детект і алерти
   DocScan-Setup.ps1 — маленький ASCII-завантажувач: бере DocScan-Install.ps1 і запускає його в окремому
   powershell.exe (помилка не закриває вікно). DocScan-Install.ps1 сам завантажує пакет, звіряє SHA256,
   запускає install.ps1. Напряму:
     powershell -ExecutionPolicy Bypass -File .\DocScan-Install.ps1 -BaseUrl http://<сервер>:8080 [-DetectOnly]
   На сервері поруч мають лежати: DocScan-Setup.ps1 і DocScan-Setup-Pilot.ps1 (з адресою сервера в $BaseUrl;
   у пілотній копії $InstallArg = @('-DetectOnly')), DocScan-Install.ps1, DocScan-<версія>.zip,
   DocScan-<версія>.zip.sha256 і DocScan-latest.txt (один рядок — ім'я поточного пакета).
   Нова версія: покласти zip + .sha256 і змінити DocScan-latest.txt; скрипти не міняються.
   Вивід усіх скриптів PowerShell — англійською (ASCII: без проблем з кодуванням консолі та irm).

Вручну:
1. Розпакуйте DocScan-<версія>.zip у будь-яку теку (напр. C:\Temp\DocScan).
2. Відкрийте PowerShell ВІД ІМЕНІ АДМІНІСТРАТОРА і виконайте:

     cd C:\Temp\DocScan
     powershell -ExecutionPolicy Bypass -File .\install.ps1

   Інші теки для спостереження:
     powershell -ExecutionPolicy Bypass -File .\install.ps1 -WatchPath 'C:\Users','D:\Shares'

   Пілот (лише детект і алерти, файли користувачів НЕ змінюються й не переносяться в карантин):
     powershell -ExecutionPolicy Bypass -File .\install.ps1 -DetectOnly
   Увімкнути лікування після пілоту — запустити install.ps1 ще раз без -DetectOnly.

   Антивірус. Microsoft Defender: install.ps1 сам додає винятки для
     C:\Program Files\DocScan   і   C:\ProgramData\DocScan
   (якщо Defender керується централізовано — GPO/Intune — додайте їх у політиці; -NoAvExclusion не додає).
   ESET: з локального скрипта не налаштовується — додайте ті самі винятки політикою в ESET PROTECT.
   Без винятків антивірус може видаляти бекапи з карантину DocScan (там оригінали шкідливих документів).

Стара реалізація (Wazuh active-response) прибирається автоматично і повністю:
  doc-scan.ps1, doc-scan.cmd, ossec-agent\tmp\docscan, старий YARA (active-response\bin\yara, yara-scan.*).
  Старий карантин (ossec-agent\quarantine) переноситься в C:\ProgramData\DocScan\quarantine\legacy.
  ossec.conf агента: додається <localfile> (json) на results\docscan-results.json, WazuhSvc перезапускається.
  На МЕНЕДЖЕРІ Wazuh (root), один раз:
    1) sh manager/cleanup_manager.sh          — прибирає <command>/<active-response> doc-scan/yara-scan
    2) блок manager/local_rules.docscan.xml → /var/ossec/etc/rules/local_rules.xml
    3) /var/ossec/bin/wazuh-analysisd -t && systemctl restart wazuh-manager
  Подробиці й перевірка — SCAN-FLOW.md, розділ 12.

Після встановлення:
  - програма:   C:\Program Files\DocScan  (bin\yara64.exe, rules\, watcher\)
  - результати: C:\ProgramData\DocScan\results\docscan-results.json  (JSON, один рядок на файл)
                C:\ProgramData\DocScan\results\watcher.log         (лог для людини)
  - карантин:   C:\ProgramData\DocScan\quarantine   (оригінали вилікуваних/видалених файлів)
  - завдання планувальника "DocScan Watcher": стартує з Windows від SYSTEM, перезапускається при збої.
  - Лікування увімкнене (якщо не -DetectOnly): документи з HIGH-вектором лікуються за політикою
    (rules\docscan-policy.yar), LNK/небезпечні PDF/старі .doc,.xls з макросами — у карантин.
    Файл, відкритий у Word, лікується, щойно його закриють (повтор, переживає перезавантаження).

Перевірити стан:
  Get-ScheduledTask "DocScan Watcher"
  Get-Content C:\ProgramData\DocScan\results\watcher.log -Encoding UTF8 -Wait

Змінити політику: відредагуйте C:\Program Files\DocScan\rules\docscan-policy.yar, потім
  Restart-ScheduledTask "DocScan Watcher"

Оновлення: розпакуйте новий пакет і знову запустіть install.ps1 (попередні правила -> rules.prev\).
Видалення: powershell -ExecutionPolicy Bypass -File "C:\Program Files\DocScan\uninstall.ps1" [-Purge]

Режим зараз: Get-Content C:\ProgramData\DocScan\results\watcher.log -Encoding UTF8 | Select-String "старт:" | Select -Last 1
  (disarm=True — лікування, disarm=False — лише детект)

Вимоги: Windows 10/11 x64, PowerShell 5.1 (є в системі), права адміністратора. Інтернет не потрібен.
Повна документація: docscan-project/SCAN-FLOW.md у репозиторії.

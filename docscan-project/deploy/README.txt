DocScan — встановлення на Windows 10/11 (x64)
=============================================

1. Розпакуйте DocScan-<версія>.zip у будь-яку теку (напр. C:\Temp\DocScan).
2. Відкрийте PowerShell ВІД ІМЕНІ АДМІНІСТРАТОРА і виконайте:

     cd C:\Temp\DocScan
     powershell -ExecutionPolicy Bypass -File .\install.ps1

   Інші теки для спостереження:
     powershell -ExecutionPolicy Bypass -File .\install.ps1 -WatchPath 'C:\Users','D:\Shares'

Після встановлення:
  - програма:   C:\Program Files\DocScan  (bin\yara64.exe, rules\, watcher\)
  - результати: C:\ProgramData\DocScan\results\docscan-results.json  (JSON, один рядок на файл)
                C:\ProgramData\DocScan\results\watcher.log         (лог для людини)
  - карантин:   C:\ProgramData\DocScan\quarantine   (оригінали вилікуваних/видалених файлів)
  - завдання планувальника "DocScan Watcher": стартує з Windows від SYSTEM, перезапускається при збої.
  - Лікування увімкнене: документи з HIGH-вектором лікуються за політикою (rules\docscan-policy.yar),
    LNK/небезпечні PDF/старі .doc,.xls з макросами — у карантин.

Перевірити стан:
  Get-ScheduledTask "DocScan Watcher"
  Get-Content C:\ProgramData\DocScan\results\watcher.log -Encoding UTF8 -Wait

Змінити політику: відредагуйте C:\Program Files\DocScan\rules\docscan-policy.yar, потім
  Restart-ScheduledTask "DocScan Watcher"

Оновлення: розпакуйте новий пакет і знову запустіть install.ps1 (попередні правила -> rules.prev\).
Видалення: powershell -ExecutionPolicy Bypass -File "C:\Program Files\DocScan\uninstall.ps1" [-Purge]

Вимоги: Windows 10/11 x64, PowerShell 5.1 (є в системі), права адміністратора. Інтернет не потрібен.
Повна документація: docscan-project/SCAN-FLOW.md у репозиторії.

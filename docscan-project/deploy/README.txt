DocScan — встановлення на Windows 10/11 (x64)
=============================================

DocScan стежить за новими файлами, перевіряє документи (макроси, DDE, віддалені шаблони, вкладені об'єкти…)
і vendor-правилами, лікує заражені документи, зберігає код макросів і пише результат для агента Wazuh.
На вибраних ПК (юрист, бухгалтер, кадровик) — ще й ставить документи з критичною інформацією в чергу E5Search.

1. З HTTP-сервера одним рядком (PowerShell від адміністратора)
--------------------------------------------------------------
     irm http://<сервер>:8080/docscan/DocScan-Setup.ps1 | iex            # звичайний ПК (детект + лікування)
     irm http://<сервер>:8080/docscan/DocScan-Setup-Pilot.ps1 | iex      # пілот: лише детект і алерти
     irm http://<сервер>:8080/docscan/DocScan-Setup-Critical.ps1 | iex   # ПК юриста / бухгалтера / кадровика
                                                                          # (+ третій прохід, черга E5Search)
   Той самий рядок і оновлює: береться пакет, назва якого в DocScan-latest.txt.
   Успіх — рядок "Done." у кінці.

   Що лежить на сервері (тека scripts/docscan/, URL http://<сервер>:8080/docscan/):
     DocScan-Setup.ps1, DocScan-Setup-Pilot.ps1, DocScan-Setup-Critical.ps1   маленькі ASCII-завантажувачі
                                       ($BaseUrl = адреса сервера; $InstallArg = @() / @('-DetectOnly') / @('-Critical'))
     DocScan-Install.ps1               завантажує пакет, звіряє SHA256, запускає install.ps1
     DocScan-<версія>.zip + .sha256    пакет
     DocScan-latest.txt                один рядок — ім'я поточного пакета
     critical-rules.yar                правила E5Search для третього проходу (беруться лише з -Critical)
   Нова версія: покласти zip + .sha256 і змінити DocScan-latest.txt; скрипти не міняються.

   Напряму, без irm:
     powershell -ExecutionPolicy Bypass -File .\DocScan-Install.ps1 -BaseUrl http://<сервер>:8080/docscan [-DetectOnly] [-Critical]
   Інші параметри DocScan-Install.ps1: -NoCritical (вимкнути третій прохід), -NoMacroUpload (код макросів —
   лише на ПК), -WatchPath, -NoAvExclusion, -QuarantineGeneral.

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
   Без -CriticalRules уже встановлені правила E5Search лишаються (звичайне оновлення їх не прибирає).

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
   Завдання планувальника "DocScan Watcher": стартує з Windows від SYSTEM, перезапускається при збої.
   Лікування (якщо не -DetectOnly): документи з HIGH-вектором лікуються за політикою (rules\docscan-policy.yar);
   LNK, небезпечні PDF, старі .doc/.xls з макросами, RTF з вкладеним об'єктом — у карантин.
   Файл, відкритий у Word, лікується, щойно його закриють (повтор переживає перезавантаження).

6. Перевірка й обслуговування
-----------------------------
   Get-ScheduledTask "DocScan Watcher"
   Get-Content "C:\Program Files\DocScan\VERSION.txt" -TotalCount 1
   Get-Content C:\ProgramData\DocScan\results\watcher.log -Encoding UTF8 -Wait
   Режим: Get-Content C:\ProgramData\DocScan\results\watcher.log -Encoding UTF8 | Select-String "start:|critical:" | Select -Last 2
     (disarm=True — лікування, disarm=False — лише детект; "critical: off" — третій прохід вимкнений)

   Змінити політику: відредагуйте C:\Program Files\DocScan\rules\docscan-policy.yar, потім
     Restart-ScheduledTask "DocScan Watcher"
   Видалення: powershell -ExecutionPolicy Bypass -File "C:\Program Files\DocScan\uninstall.ps1" [-Purge]

Вимоги: Windows 10/11 x64, PowerShell 5.1 (є в системі), права адміністратора. Вивід усіх скриптів —
англійською (ASCII), тож кодування консолі й irm не заважають. Повна документація: docscan-project/SCAN-FLOW.md.

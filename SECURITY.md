Reporting security issues
=========================

This repository is a fork of [VirusTotal/yara](https://github.com/VirusTotal/yara) that adds the
`docscan` module and its tooling (DocScan).

**Please do not open a public GitHub issue for a security vulnerability** — everybody would see it
before it is fixed.

Where to report
---------------

| The problem is in… | Report it to |
|---|---|
| DocScan: the `docscan` module (`libyara/modules/docscan/`), the DocScan parts of `cli/yara.c` (`--docscan-*`, `--file-vars`, `--critical-*`), the Windows sandbox (`cli/docscan_sandbox.c`), disarm, the watcher, the updater, the installer, the rule tooling (`docscan-project/`) | this repository, privately: **Security → Report a vulnerability** ([direct link](https://github.com/rifatismailov/yara-docscan/security/advisories/new)) |
| YARA itself (the scanning engine, other modules, upstream code) | the YARA maintainers, as described in the [upstream security policy](https://github.com/VirusTotal/yara/security/policy) |

If you are not sure which one it is, report it here; it will be forwarded upstream if needed.

What to include
---------------

- the commit or package version (`VERSION.txt` in a DocScan package);
- what happens and what you expected;
- a way to reproduce it — a minimal input file if possible. Please do not attach live malware;
  a description or a hash is enough, a safe sample can be arranged privately.

The local web interface
-----------------------

`docscan-web.exe` (service `DocScanWeb`) listens only on `127.0.0.1` over HTTPS. It checks the `Host` header
against DNS rebinding. Sign-in is the `admin` account; the password is generated at install and must be changed at
the first sign-in. Every form needs a CSRF token, and every action is audited to Wazuh. It never scans or deletes
anything itself: it writes settings and request files into `C:\ProgramData\DocScan`, which only SYSTEM and
Administrators can access, and the services act on them. Anything that lets a non-administrator or another machine
reach it, or act through it, is a vulnerability — please report it as above.

Third-party rules
-----------------

The vendor YARA rules (`general/`, `maldoc/` of [yara-docscan-rules](https://github.com/rifatismailov/yara-docscan-rules)) come from public
sources (signature-base, Elastic, Yara-Rules, bartblaze, InQuest, ditekSHen, ReversingLabs, YARA-Forge). A false positive or a
broken rule there is not a vulnerability: open a normal issue, and for problems in a rule itself
consider reporting it to its source as well.

---

**Українською.** Про вразливості в DocScan (модуль `docscan`, пісочниця, вотчер, служба оновлення,
інсталятор, інструменти правил) повідомляйте приватно: вкладка **Security → Report a vulnerability** цього репозиторію. Не відкривайте
публічний issue. Вразливості в самій YARA — авторам YARA за їхньою політикою безпеки.

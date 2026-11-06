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
| DocScan: the `docscan` module (`libyara/modules/docscan/`), the DocScan parts of `cli/yara.c` (`--docscan-*`, `--file-vars`), disarm, the watcher, the installer, the rule tooling (`docscan-project/`) | this repository, privately: **Security → Report a vulnerability** ([direct link](https://github.com/rifatismailov/yara-docscan/security/advisories/new)) |
| YARA itself (the scanning engine, other modules, upstream code) | the YARA maintainers, as described in the [upstream security policy](https://github.com/VirusTotal/yara/security/policy) |

If you are not sure which one it is, report it here; it will be forwarded upstream if needed.

What to include
---------------

- the commit or package version (`VERSION.txt` in a DocScan package);
- what happens and what you expected;
- a way to reproduce it — a minimal input file if possible. Please do not attach live malware;
  a description or a hash is enough, a safe sample can be arranged privately.

Third-party rules
-----------------

The vendor YARA rules under `docscan-project/rules/general/` and `rules/maldoc/` come from public
sources (signature-base, Elastic, Yara-Rules, bartblaze, InQuest, ditekSHen). A false positive or a
broken rule there is not a vulnerability: open a normal issue, and for problems in a rule itself
consider reporting it to its source as well.

---

**Українською.** Про вразливості в DocScan (модуль `docscan`, вотчер, інсталятор, інструменти правил)
повідомляйте приватно: вкладка **Security → Report a vulnerability** цього репозиторію. Не відкривайте
публічний issue. Вразливості в самій YARA — авторам YARA за їхньою політикою безпеки.

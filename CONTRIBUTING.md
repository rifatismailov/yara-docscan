Contributing to DocScan
=======================

This repository is a fork of [VirusTotal/yara](https://github.com/VirusTotal/yara) with the `docscan`
module and its tooling. Contributions here are about DocScan; changes to YARA itself belong upstream.

Questions, bugs, ideas
----------------------

Open a [GitHub issue](https://github.com/rifatismailov/yara-docscan/issues). For a bug, include the
version (commit or `VERSION.txt` of the package), what happened, what you expected and how to reproduce
it. Do not attach live malware — a description or a hash is enough.

Security vulnerabilities: **not** in issues — see [SECURITY.md](SECURITY.md).

Pull requests
-------------

Before you start, read:

- [`docscan-project/SCAN-FLOW.en.md`](docscan-project/SCAN-FLOW.en.md) — architecture and behaviour;
- [`docscan-project/CODE-GUIDE.md`](docscan-project/CODE-GUIDE.md) — code walkthrough and "how to add"
  recipes (Ukrainian).

Ground rules:

- **The module reports facts; the policy rules decide.** A new detection is usually a new fact in the
  module plus a rule in `docscan-project/rules/docscan-policy.yar`, not a hard-coded verdict in C.
- **We do not write our own vendor YARA signatures.** Third-party rules come only from public sources
  with a clear license, through `docscan-project/rules/tools/build_vendor_rules.py` (pinned commits,
  per-rule filter, every drop recorded with a reason). Do not edit generated files under
  `rules/general/` and `rules/maldoc/` by hand.
- **Untrusted input.** Every parser reads attacker-controlled bytes: bounds-check every read, cap every
  loop and allocation, keep large structures off the stack (Windows main-thread stack is 1 MB).
- **Tests.** Run the regression (`run_tests.ps1` on Windows or the loop in `CODE-GUIDE.md` §10) and, for
  parser changes, the libFuzzer targets (`docscan-project/fuzz/build.sh`). Add an inert sample to
  `docscan-project/test-range/gen_test_range.py` for a new detection.
- **Builds.** A new `.c` file goes into `Makefile.am` and the three `windows/vs20*/libyara/libyara.vcxproj`
  (keep their CRLF line endings).
- **Documentation.** Update `SCAN-FLOW.md` and `SCAN-FLOW.en.md` (both languages) with the change.
- Never commit live samples, internal hostnames, IP addresses or credentials — the repository is public.

License
-------

DocScan code is under the same BSD 3-Clause license as YARA ([COPYING](COPYING)). Third-party rules keep
their own licenses (`docscan-project/rules/LICENSE-*`).

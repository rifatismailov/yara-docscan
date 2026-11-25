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

- [`docscan-project/DOCSCAN.md`](docscan-project/DOCSCAN.md) (Ukrainian) — architecture, behaviour, the code walkthrough and "how to add"
  recipes (Ukrainian).

Ground rules:

- **The module reports facts; the policy rules decide.** A new detection is usually a new fact in the
  module plus a rule in `docscan-policy.yar` of [yara-docscan-rules](https://github.com/rifatismailov/yara-docscan-rules), not a hard-coded verdict in C.
- **We do not write our own vendor YARA signatures.** Third-party rules come only from public sources
  with a clear license, through `tools/build_vendor_rules.py` of [yara-docscan-rules](https://github.com/rifatismailov/yara-docscan-rules) (pinned commits,
  per-rule filter, every drop recorded with a reason). Do not edit the generated `general/` and
  `maldoc/` folders of that repository by hand. Critical-information rules (pass 3) are written by each
  organisation for itself ([`DOCSCAN.md`, third pass](docscan-project/DOCSCAN.md#critical), Ukrainian)
  and are not part of this repository.
- **Untrusted input.** Every parser reads attacker-controlled bytes: bounds-check every read, cap every
  loop and allocation, keep large structures off the stack (Windows main-thread stack is 1 MB).
- **Tests.** Run the regression (`docscan-project/test-range/run_tests.ps1` on Windows,
  `sh docscan-project/ci/build-test-unix.sh` on macOS / Linux, or the loop in `DOCSCAN.md`, section Code → tests and fuzzing) and, for
  parser changes, the libFuzzer targets (`docscan-project/fuzz/build.sh`). Add an inert sample to
  `docscan-project/test-range/gen_test_range.py` for a new detection and update
  `docscan-project/ci/expected-verdicts.tsv` deliberately (`check_verdicts.py --write`). The tests expect
  the rules in `docscan-project/rules/` (git-ignored): `cirun` puts a release of yara-docscan-rules there.
- **Builds.** A new `.c` file goes into `Makefile.am` and the three `windows/vs20*/libyara/libyara.vcxproj`
  (keep their CRLF line endings).
- **Documentation.** Update `docscan-project/DOCSCAN.md` with the change - one document, no copies elsewhere.
- Never commit live samples, internal hostnames, IP addresses or credentials — the repository is public.

License
-------

DocScan code is under the same BSD 3-Clause license as YARA ([COPYING](COPYING)). Third-party rules keep
their own licenses (`LICENSE-*` in [yara-docscan-rules](https://github.com/rifatismailov/yara-docscan-rules)).

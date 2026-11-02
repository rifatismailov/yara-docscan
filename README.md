# YARA + DocScan

> [!NOTE]
> This is a **fork of [VirusTotal/yara](https://github.com/VirusTotal/yara) 4.6.0** that adds a new
> module, **`docscan`**, for detecting and disarming weaponised documents. Everything else is
> upstream YARA, unchanged. See [About YARA](#about-yara) below.
>
> 📖 **Full documentation:** [English](docscan-project/SCAN-FLOW.en.md) · [Українська](docscan-project/SCAN-FLOW.md)

## What DocScan adds

`docscan` looks inside a document's **structure** (not its extension and not just raw bytes) and
reports the attack vector, the evidence and a verdict. Detection, a second pass of vendor rules
over the extracted macro, and remediation all live in the same `yara64.exe` binary.

| Vector | Field | Verdict |
|---|---|---|
| Remote template injection (`attachedTemplate` → URL, T1221) | `remote_template` | HIGH |
| Follina / protocol handlers (`ms-msdt:`, `search-ms:` …) | `protocol_handler` | HIGH |
| `DDEAUTO` fields (T1559.002) | `dde_auto` | HIGH |
| Suspicious VBA macros (CFB + MS-OVBA decompression) | `macro_suspicious` / `macro_present` | HIGH / MEDIUM |
| Embedded PE or LNK in `oleObject` | `embedded_pe` / `embedded_lnk` | HIGH |
| RTF `\objupdate` | `rtf_objupdate` | HIGH |
| PDF auto-JavaScript with dangerous APIs, `/Launch` | `pdf_js_auto` / `pdf_launch` | HIGH |
| Malicious LNK (URL / obfuscated args, LOLBin target) | `lnk_url_args` / `lnk_obfuscated` / `lnk_lolbin` | HIGH / MEDIUM |

File types are recognised by magic bytes: OOXML (docx/xlsx/pptx…), OLE (doc/xls/ppt), RTF, PDF, LNK.

### Detection policy lives in YARA rules

The module only parses documents and exposes **facts** (`docscan.vba_code`, `docscan.external_rels[]`,
`docscan.dde[]`, `docscan.embedded[]`, `docscan.entries[]`, `docscan.lnk_target`/`lnk_args`, …).
What counts as HIGH or MEDIUM, how a finding is named and what gets disarmed is decided by ordinary
rules in [`docscan-project/rules/docscan-policy.yar`](docscan-project/rules/docscan-policy.yar):

```yara
rule DS_REMOTE_TEMPLATE
{
  meta:
    severity = "HIGH"                 // HIGH / MEDIUM / INFO
    finding  = "REMOTE_TEMPLATE"      // name in the JSON
    disarm   = "remote_template"      // what --docscan-disarm removes (optional)
  condition:
    for any rel in docscan.external_rels : (
      rel.type iendswith "/attachedTemplate" and
      rel.target matches /^((https?|s?ftps?):\/\/|\\\\|file:\/\/([^\/]|\/\/))/i )
}
```

Edit the policy to fit your organisation — no rebuild needed. The table above is the default policy.

### New command-line flags

| Flag | What it does |
|---|---|
| `--docscan-json` | Prints one JSON line: `ftype`, `findings` and `verdict` (from the policy rules), `evidence` (URLs defanged), `yara_file_matches` (other rules on the raw file), `yara_matches` (the same rules re-run over the **decompressed VBA**) and `details` |
| `--docscan-disarm` | After the scan, cures the file in place as the matching policy rules say (`meta.disarm`; backup → `<file>.docscan-bak`): strips the macro / external relationship / DDE / embeddings, breaks `\objupdate`, deletes malicious LNK |
| `--docscan-extract=FILE` | Writes the decompressed VBA to `FILE` |

```console
$ yara64 -w --docscan-json --docscan-disarm docscan-project/rules/docscan-index.yar invoice.docm
{"ftype":"ooxml","findings":["MACRO_PRESENT","MACRO_SUSPICIOUS","MACRO_AUTOEXEC"],"verdict":"HIGH",
 "evidence":{"vba_evidence":"powershell | Shell | DownloadFile | AutoOpen"},
 "yara_matches":["VBA_AutoExec_DownloadCradle"],
 "yara_file_matches":["Contains_VBA_macro_code","office_document_vba"],"details":[…]}
docscan-disarm: invoice.docm -> removed:vbaProject.bin
```

The module fields can also be used directly in rules:

```yara
import "docscan"

rule weaponised_document
{
    condition:
        docscan.remote_template or docscan.protocol_handler or docscan.dde_auto or
        docscan.macro_suspicious or docscan.embedded_pe
}
```

### File watcher

`docscan-project/watcher/docscan-watcher.ps1` (Windows, PowerShell) watches folders with
`FileSystemWatcher`, scans every new file with a single `yara64 --docscan-json` run (docscan policy +
vendor rules on the raw bytes and on the decompressed VBA), and appends one JSON line per file to
`results\docscan-results.json`, ready to be shipped by a SIEM agent (e.g. Wazuh `localfile` /
`log_format json`).

### Where things are

| Path | Contents |
|---|---|
| `libyara/modules/docscan/` | the module: type detection, OOXML/ZIP (miniz), CFB, MS-OVBA, VBA, RTF, PDF, LNK inspectors, `disarm.c` |
| `cli/yara.c` | the three `--docscan-*` flags, JSON output, VBA re-scan, disarm hook |
| `docscan-project/rules/` | `docscan-policy.yar` (the policy), `docscan.yar`, `docscan-index.yar`, `file-index.yar`, vendor rule subsets (signature-base, community) |
| `docscan-project/fuzz/` | libFuzzer harness (ASan + UBSan), corpus tools, regression inputs |
| `docscan-project/watcher/` | the file watcher |
| `docscan-project/test-range/`, `test-samples/generated/` | regression test script and safe, inert test documents (one per vector) |
| **[`docscan-project/SCAN-FLOW.en.md`](docscan-project/SCAN-FLOW.en.md)** · [українською](docscan-project/SCAN-FLOW.md) | **full documentation**: architecture diagram, every function, behaviour, build, tests, limitations |

### Building

Same as upstream YARA — the module is compiled in by default.

```sh
# macOS / Linux
./bootstrap.sh && ./configure && make
```
```powershell
# Windows (VS Build Tools 2022)
nuget restore windows\vs2019\yara.sln
msbuild windows\vs2019\yara.sln /t:yara /p:Configuration=Release /p:Platform=x64 /p:PlatformToolset=v143
```

### Licensing

The fork keeps YARA's BSD-3-Clause license (`COPYING`). Bundled third-party pieces keep their own
terms: miniz (public domain / MIT), signature-base rules (Detection Rule License 1.1), community
maldoc rules (GPLv2) — see the headers in each rule file.

---

## About YARA

YARA is a pattern-matching tool for identifying and classifying malware: rules describe
families by textual or binary patterns plus a boolean condition. See the
[upstream repository](https://github.com/VirusTotal/yara) and the
[documentation](https://yara.readthedocs.io/) for the rule language and API.

> [!IMPORTANT]
> Upstream YARA is in maintenance mode; new development happens in
> [YARA-X](https://virustotal.github.io/yara-x/). This fork is based on YARA 4.6.0.

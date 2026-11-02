# YARA + DocScan

> [!NOTE]
> This is a **fork of [VirusTotal/yara](https://github.com/VirusTotal/yara) 4.6.0** that adds a new
> module, **`docscan`**, for detecting and disarming weaponised documents. Everything else is
> upstream YARA, unchanged. The upstream README follows [below](#original-yara-readme).

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

### New command-line flags

| Flag | What it does |
|---|---|
| `--docscan-json` | Prints one JSON line: `ftype`, `findings`, `verdict`, `evidence` (URLs defanged), and `yara_matches` — the loaded rules re-run over the **decompressed VBA** |
| `--docscan-disarm` | After the scan, cures the file in place if a HIGH vector was found (backup → `<file>.docscan-bak`): strips the macro / external relationship / DDE / embeddings, breaks `\objupdate`, deletes malicious LNK |
| `--docscan-extract=FILE` | Writes the decompressed VBA to `FILE` |

```console
$ yara64 --docscan-json --docscan-disarm docscan-project/rules/docscan-index.yar invoice.docm
{"ftype":"ooxml","findings":["MACRO_SUSPICIOUS","MACRO_PRESENT"],"verdict":"HIGH",
 "evidence":{"vba_evidence":"powershell | Shell | DownloadFile | AutoOpen"},
 "yara_matches":["gen_macro_ShellExecute_action"]}
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
`FileSystemWatcher`, scans every new document with `docscan` plus vendor rules on the raw bytes
(and executables/scripts/archives with vendor rules only), and appends one JSON line per file to
`results\docscan-results.json`, ready to be shipped by a SIEM agent (e.g. Wazuh `localfile` /
`log_format json`).

### Where things are

| Path | Contents |
|---|---|
| `libyara/modules/docscan/` | the module: type detection, OOXML/ZIP (miniz), CFB, MS-OVBA, VBA, RTF, PDF, LNK inspectors, `disarm.c` |
| `cli/yara.c` | the three `--docscan-*` flags, JSON output, VBA re-scan, disarm hook |
| `docscan-project/rules/` | `docscan.yar`, `docscan-index.yar`, `file-index.yar`, vendor rule subsets (signature-base, community) |
| `docscan-project/watcher/` | the file watcher |
| `docscan-project/test-range/`, `test-samples/generated/` | regression test script and safe, inert test documents (one per vector) |
| **[`docscan-project/SCAN-FLOW.md`](docscan-project/SCAN-FLOW.md)** | **full documentation** (Ukrainian): architecture diagram, every function, behaviour, build, tests, limitations |

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

# Original YARA README

> [!IMPORTANT]
> This project is in maintenance mode. More info: https://virustotal.github.io/yara-x/blog/yara-x-is-stable/


## YARA in a nutshell

YARA is a tool aimed at (but not limited to) helping malware researchers to
identify and classify malware samples. With YARA you can create descriptions of
malware families (or whatever you want to describe) based on textual or binary
patterns. Each description, a.k.a. rule, consists of a set of strings and a
boolean expression which determine its logic. Let's see an example:

```yara
rule silent_banker : banker
{
    meta:
        description = "This is just an example"
        threat_level = 3
        in_the_wild = true

    strings:
        $a = {6A 40 68 00 30 00 00 6A 14 8D 91}
        $b = {8D 4D B0 2B C1 83 C0 27 99 6A 4E 59 F7 F9}
        $c = "UVODFRYSIHLNWPEJXQZAKCBGMT"

    condition:
        $a or $b or $c
}
```

The above rule is telling YARA that any file containing one of the three strings
must be reported as *silent_banker*. This is just a simple example, more
complex and powerful rules can be created by using wild-cards, case-insensitive
strings, regular expressions, special operators and many other features that
you'll find explained in [YARA's documentation](https://yara.readthedocs.org/).

YARA is multi-platform, running on Windows, Linux and Mac OS X, and can be used
through its command-line interface or from your own Python scripts with the
yara-python extension.

## Additional resources

Do you use GitHub for storing your YARA rules? [YARA-CI](https://yara-ci.cloud.virustotal.com)
may be a useful addition to your toolbelt. This is GitHub application that provides
continuous testing for your rules, helping you to identify common mistakes and
false positives.

If you plan to use YARA to scan compressed files (.zip, .tar, etc) you should
take a look at [yextend](https://github.com/BayshoreNetworks/yextend), a very
helpful extension to YARA developed and open-sourced by Bayshore Networks.

Additionally, the guys from [InQuest](https://inquest.net/) have curated an
awesome list of [YARA-related stuff](https://github.com/InQuest/awesome-yara).

## Who's using YARA

* [0x101 Cyber Security](https://0x101-cyber-security.de)
* [Adlice](https://www.adlice.com/)
* [AlienVault](https://otx.alienvault.com/)
* [Avast](https://www.avast.com/)
* [BAE Systems](https://www.baesystems.com/home?r=ai)
* [Bayshore Networks, Inc.](https://www.bayshorenetworks.com)
* [Binalyze](https://www.binalyze.com/)
* [BinaryAlert](https://github.com/airbnb/binaryalert)
* [Blueliv](https://www.blueliv.com)
* [Cado Security](https://docs.cadosecurity.com/cado-response/investigate/detections#setting-up-detections)
* [Cisco Talos Intelligence Group](https://talosintelligence.com/)
* [Cloudina Security](https://cloudina.co.uk)
* [Cofense](https://cofense.com)
* [Conix](https://www.conix.fr)
* [Corelight](https://corelight.com/products/yara)
* [CounterCraft](https://www.countercraft.eu)
* [Cuckoo Sandbox](https://github.com/cuckoosandbox/cuckoo)
* [Cyber Triage](https://www.cybertriage.com)
* [Cybereason](https://www.cybereason.com)
* [Digita Security](https://digitasecurity.com/product/uxprotect)
* [Dragos Platform](https://dragos.com/platform/)
* [Dtex Systems](https://dtexsystems.com)
* [ESET](https://www.eset.com)
* [ESTsecurity](https://www.estsecurity.com)
* [Elastic Security](https://github.com/elastic/protections-artifacts)
* [FactorX.ai](https://factorx.ai)
* [Fidelis XPS](https://www.fidelissecurity.com/network-security-appliance/Fidelis-XPS)
* [FireEye, Inc.](https://www.fireeye.com)
* [Forcepoint](https://www.forcepoint.com)
* [Fox-IT](https://www.fox-it.com)
* [FSF](https://github.com/EmersonElectricCo/fsf)
* [Guidance Software](https://www.guidancesoftware.com/endpointsecurity)
* [Heroku](https://heroku.com)
* [Hornetsecurity](https://www.hornetsecurity.com/en/)
* [ICS Defense](https://icsdefense.net/)
* [InQuest](https://www.inquest.net/)
* [IntelOwl](https://github.com/intelowlproject/IntelOwl)
* [Joe Security](https://www.joesecurity.org)
* [Kaspersky Lab](https://www.kaspersky.com)
* [KnowBe4](https://www.knowbe4.com)
* [Koodous](https://koodous.com/)
* [Laika BOSS](https://github.com/lmco/laikaboss)
* [Lastline, Inc.](https://www.lastline.com)
* [libguestfs](https://www.libguestfs.org/)
* [LimaCharlie](https://limacharlie.io/)
* [Malpedia](https://malpedia.caad.fkie.fraunhofer.de/)
* [Malwation](https://malwation.com/)
* [McAfee Advanced Threat Defense](https://mcafee.com/atd)
* [Metaflows](https://www.metaflows.com)
* [NBS System](https://www.nbs-system.com/)
* [ndaal](https://ndaal.eu)
* [NetLock](https://netlockendpoint.com)
* [Nextron Systems](https://www.nextron-systems.com)
* [Nozomi Networks](https://www.nozominetworks.com)
* [osquery](https://www.osquery.io)
* [Payload Security](https://www.payload-security.com)
* [PhishMe](https://phishme.com/)
* [Picus Security](https://www.picussecurity.com/)
* [Radare2](https://rada.re)
* [RedSocks Security](https://redsocks.eu/)
* [ReversingLabs](https://reversinglabs.com)
* [Scanii](https://scanii.com)
* [SecondWrite](https://www.secondwrite.com)
* [SonicWall](https://www.sonicwall.com/)
* [SpamStopsHere](https://www.spamstopshere.com)
* [Spyre](https://github.com/spyre-project/spyre)
* [stoQ](https://stoq.punchcyber.com)
* [Sublime Security](https://sublime.security)
* [SumoLogic](https://sumologic.com)
* [Tanium](https://www.tanium.com/)
* [Tenable Network Security](https://www.tenable.com/)
* [Tenzir](https://tenzir.com)
* [The DigiTrust Group](https://www.digitrustgroup.com/)
* [ThreatConnect](https://www.threatconnect.com/)
* [ThreatStream, Inc.](https://www.threatstream.com)
* [Thug](https://github.com/buffer/thug)
* [Threat.Zone](https://threat.zone)
* [TouchWeb](https://www.touchweb.fr)
* [Trend Micro](https://www.trendmicro.com)
* [UnpacMe](https://www.unpac.me)
* [UpSight Security Inc.](https://upsight.ai/)
* [Uptycs Inc](https://www.uptycs.com/)
* [Veeam](https://www.veeam.com/)
* [Verisys Antivirus API](https://www.ionxsolutions.com/products/verisys-virus-api)
* [VirusTotal Intelligence](https://www.virustotal.com/intelligence/)
* [VMRay](https://www.vmray.com/)
* [Volexity](https://www.volexity.com/products-overview/volcano/)
* [We Watch Your Website](https://www.wewatchyourwebsite.com/)
* [x64dbg](https://x64dbg.com)
* [YALIH](https://github.com/Masood-M/YALIH)

Are you using it? Want to see your site listed here?

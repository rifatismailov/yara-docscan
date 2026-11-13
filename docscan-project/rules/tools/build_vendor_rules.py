#!/usr/bin/env python3
"""Build DocScan's vendor rule set (rules/general, rules/maldoc/<source>, rules/file-index.yar).

Source files come from upstream repositories pinned in SOURCES; which files are used is listed
in tools/vendor-selection.txt. Each selected file is then filtered PER RULE:

  * dropped  - rules that can never fire on a Windows workstation (ELF/Linux, Mach-O/macOS,
               Android, PHP/JSP/ASPX webshells) and rules listed in DROP;
  * renamed  - RENAME resolves identifier clashes between files, so nothing has to be excluded;
  * info     - rules listed in INFO get the tag `docscan_info`: yara64 reports them in
               "yara_info_matches" and they do NOT raise the verdict (indicators, not detections).

Private/global rules are always kept (other rules may depend on them); a dropped rule that a kept
rule references is kept too. The result is compiled with yarac; the build fails on any error.

  python3 build_vendor_rules.py [--vendor DIR] [--fetch] [--yarac PATH] [--check]

--check: build into a temp dir and only report whether rules/ is up to date.
"""
import argparse, os, re, shutil, subprocess, sys, tempfile
from collections import OrderedDict
from pathlib import Path

HERE = Path(__file__).resolve().parent
RULES = HERE.parent
DEFAULT_VENDOR = RULES.parent / "vendor-sources"   # git clones of the sources (not in git)

SOURCES = {
    "signature-base": ("https://github.com/Neo23x0/signature-base.git",
                       "94a1c48d7ab499879287ff611dfe7f9c56376030"),
    "yara-rules-community": ("https://github.com/Yara-Rules/rules.git",
                             "0f93570194a80d2f2032869055808b0ddcdfb360"),
    "protections-artifacts": ("https://github.com/elastic/protections-artifacts.git",
                              "ce99f77ba7cc2e442589d49e01b9db262d31ae91"),
    "bartblaze": ("https://github.com/bartblaze/Yara-rules.git",
                  "5cc871d82361de8a80d387ec8bbd01fe4258b4a9"),
    "inquest": ("https://github.com/InQuest/yara-rules.git",
                "922e6a8a24027152935b1a1ec8f07912a57dbf2b"),
    "ditekshen": ("https://github.com/ditekshen/detection.git",
                  "e76c93dcdedff04076380ffc60ea54e45b313635"),
    # ReversingLabs: Windows malware families (MIT)
    "reversinglabs": ("https://github.com/reversinglabs/reversinglabs-yara-rules.git",
                      "e0a0be54aa1e11ccfd6854e4f19e9476f328fd84"),
    # YARA-Forge: a curated, validated aggregate of public rule sets - a RELEASE zip, not a git repo.
    # Only the sources in FORGE_SOURCES are taken (the others are already DocScan sources or have no
    # licence that allows redistribution).
    "yara-forge": ("https://github.com/YARAHQ/yara-forge/releases/download/20261108/yara-forge-rules-core.zip",
                   "release:20261108"),
}

# YARA-Forge sources that are taken (repo of the rule's source_url -> licence). Not taken: signature-base,
# ditekshen, elastic, bartblaze, InQuest, Yara-Rules (already sources here, maintained upstream) and
# sources without a licence file or with a non-commercial one (malpedia CC BY-NC-SA, StrangerealIntel,
# RussianPanda95, HarfangLab, avast, embee-research, SIFalcon, mikesxrs, ...).
FORGE_SOURCES = {
    "SEKOIA-IO/Community": "DRL-1.1", "mandiant/red_team_tool_countermeasures": "BSD-2-Clause",
    "volexity/threat-intel": "BSD-2-Clause", "kevoreilly/CAPEv2": "GPL-3.0", "chronicle/GCTI": "Apache-2.0",
    "eset/malware-ioc": "BSD-2-Clause", "advanced-threat-research/Yara-Rules": "Apache-2.0",
    "WithSecureLabs/iocs": "BSD-2-Clause", "elceef/yara-rulz": "MIT", "cod3nym/detection-rules": "DRL-1.1",
    "craiu/yararules": "GPL-3.0", "dr4k0nia/yara-rules": "DRL-1.1", "synacktiv/synacktiv-rules": "DRL-1.1",
    "deadbits/yara-rules": "Unlicense",
}
_FORGE_SRC = re.compile(r'source_url\s*=\s*"https?://github\.com/([^/"]+/[^/"]+)')


def forge_reason(src, r):
    """YARA-Forge: keep a rule only if it comes from a source in FORGE_SOURCES (None = keep)."""
    if src != "yara-forge":
        return None
    m = _FORGE_SRC.search(r['text'][r['hoff']:])
    repo = m.group(1) if m else "?"
    return None if repo in FORGE_SOURCES else f"yara-forge: source {repo} not taken (already a source here / licence)"

# the source's OWN classification of a rule as informational -> docscan_info
# (bartblaze: meta category = "INFO"; InQuest: meta Severity = "0")
SOURCE_INFO = {
    "bartblaze": re.compile(r'\bcategory\s*=\s*"INFO"'),
    "inquest": re.compile(r'\bSeverity\s*=\s*"0"'),
}

# identifier clashes: (source path, rule) -> new name
RENAME = {}

# rules removed on purpose (besides the automatic platform filter): name or (source path, name) -> reason
_OLD = "older copy of the signature-base rule of the same name (kept there, maintained)"
DROP = {
    ("maldocs/Maldoc_APT19_CVE-2017-0199.yar", "FE_LEGALSTRIKE_MACRO"): _OLD,
    ("maldocs/Maldoc_APT19_CVE-2017-0199.yar", "FE_LEGALSTRIKE_RTF"): _OLD,
    ("maldocs/Maldoc_CVE_2017_8759.yar", "CVE_2017_8759_Mal_Doc"): _OLD,
    ("maldocs/Maldoc_CVE_2017_8759.yar", "CVE_2017_8759_WSDL_in_RTF"): _OLD,
    ("maldocs/Maldoc_malrtf_ole2link.yar", "malrtf_ole2link"): _OLD,
    # FP on a clean Windows Server 2022: inbox Microsoft drivers (csc.sys, SmSerl64.sys)
    "Windows_VulnDriver_Csc_856c8393": "FP: matches the inbox Microsoft driver csc.sys",
    "Windows_VulnDriver_SmSerl64_00319890": "FP: matches the inbox Microsoft driver SmSerl64.sys",
    "Windows_VulnDriver_Ksld_c608656e": "FP: matches KslD.sys of Microsoft Defender (found on a clean workstation)",
    # FP on clean Office files (Apache POI / Tika test documents): the strings are searched in the whole
    # .rels part, not in one relationship - a LOCAL embedded object (chart, Excel table) plus any ordinary
    # hyperlink matches. The policy rule EXTERNAL_OLE checks the same relationship, remote targets only.
    "INDICATOR_OLE_RemoteTemplate": "FP: local embedded OLE object + any hyperlink in the same .rels (policy EXTERNAL_OLE covers it)",
    # hunting rule (meta category = "hunting"): an OOXML embedded as an OLE object always has a header in
    # front, so every embedded docx/pptx seen by the 2nd pass (document parts) matched
    "Brooxml_Hunting": "FP: hunting rule, matches every OOXML embedded as an OLE object (header in front)",
    # exact duplicates (same strings and condition under another name)
    ("maldocs/Maldoc_Dridex.yar", "PHISH_02Dez2015_dropped_p0o6543f"): "duplicate of signature-base PHISH_02Dez2015_dropped_p0o6543f_1",
    ("maldocs/maldoc_somerules.yar", "office_document_vba"): "duplicate of Contains_VBA_macro_code",
    ("yara/indicator_office.yar", "INDICATOR_RTF_MalVer_Objects"): "duplicate of signature-base SUSP_INDICATOR_RTF_MalVer_Objects (same rule, commented copy)",
    # variants: same strings + an extra condition -> fire only where the base rule already fires
    "PAExec_Cloaked": "variant of PAExec (adds a file-name check)",
    "SUSP_VULN_DRV_PROCEXP152_Renamed_May23": "variant of SUSP_VULN_DRV_PROCEXP152_May23 (adds a file-name check)",
    "Windows_VulnDriver_MyPortIO_37c35201": "variant of Windows_VulnDriver_MyPortIO_bab77af0 (adds a header check)",
    "EquationGroup_Toolset_Apr17_msgks_mskgu": "variant of EquationGroup_EquationDrug_Gen_3 (smaller filesize limit)",
    # obsolete technology: Flash is end-of-life (2020) and blocked in Office (2021)
    "Flash_in_LNK": "obsolete: Adobe Flash",
    "crime_ole_loadswf_cve_2018_4878": "obsolete: Adobe Flash",
    # slow: YARA warns these strings slow down scanning
    "Hex_Encoded_Powershell": "slow (YARA: unbounded regex)",
    "FE_LEGALSTRIKE_MACRO_2": "slow (YARA: unbounded regex)",
    "Contains_VBE_File": "slow (YARA: unbounded regex)",
    "MIME_MSO_ActiveMime_base64": "slow (YARA: unbounded regex)",
    "invalid_trailer_structure": "slow (YARA: unbounded regex)",
    "invalid_xref_numbers": "slow (YARA: unbounded regex)",
    "multiple_filtering": "slow (YARA: unbounded regex)",
    "possible_exploit": "slow (YARA: unbounded regex)",
    "suspicious_obfuscation": "slow (YARA: unbounded regex)",
    "Maldoc_Suspicious_OLE_target": "slow (YARA: unbounded regex)",
    "maldoc_indirect_function_call_2": "slow (YARA: string may slow down scanning)",
    "maldoc_indirect_function_call_3": "slow (YARA: string may slow down scanning)",
    "MC_Office_DDE_Command_Execution": "slow (YARA: unbounded regex)",
    "INDICATOR_OLE_ObjectPool_Embedded_Files": "slow (YARA: strings may slow down scanning)",
}

# rules whose last change (meta modified / last_modified, else date / creation_date) is this year
# or older are dropped: written for samples and campaigns of that time
OLD_YEAR = 2016

# indicators, not detections: reported in yara_info_matches, never raise the verdict.
# Most duplicate what the docscan policy already decides with proper severity.
INFO = {
    # PDF structure / metadata oddities (common in legitimate generator/scanner output)
    "suspicious_version", "suspicious_creation", "suspicious_title",
    "suspicious_author", "suspicious_producer", "suspicious_creator", "multiple_versions",
    "js_wrong_version", "JBIG2_wrong_version", "FlateDecode_wrong_version", "embed_wrong_version",
    "header_evasion",
    # PDF features the policy grades itself (PDF_JS*, PDF_LAUNCH, PDF_EMBEDDED, PDF_OPENACTION)
    "suspicious_js", "suspicious_launch_action", "suspicious_embed",
    # "a macro exists" / generic macro strings (policy: MACRO_PRESENT / MACRO_AUTOEXEC / MACRO_SUSPICIOUS)
    "macrocheck", "SUSP_WordDoc_VBA_Macro_Strings", "SUSP_VBA_FileSystem_Access",
    # bare keyword / container format
    "powershell", "Word_2007_XML_Flat_OPC",
}
INFO_TAG = "docscan_info"
# every rule under maldoc/ is a document rule: yara64 reports its matches in "yara_doc_matches" and the
# watcher counts them only for its document category. Shellcode patterns such as getEIP / PEB access
# are strong in a document but ordinary machine code in any binary.
DOC_TAG = "docscan_doc"

HEADER = re.compile(r'(?m)^[ \t]*((?:private|global)[ \t]+)*rule[ \t]+([A-Za-z0-9_]+)[ \t\r\n]*(:[^{]*)?\{')


def mask(text):
    """Same-length copy with comments and string literals blanked (keeps offsets)."""
    out = list(text); i = 0; n = len(text)
    while i < n:
        c = text[i]
        if c == '"':
            j = i + 1
            while j < n and text[j] != '"' and text[j] != '\n':
                j += 2 if text[j] == '\\' else 1
            for k in range(i + 1, min(j, n)):
                out[k] = ' '
            i = j + 1; continue
        if text.startswith('//', i):
            j = text.find('\n', i); j = n if j < 0 else j
            for k in range(i, j): out[k] = ' '
            i = j; continue
        if text.startswith('/*', i):
            j = text.find('*/', i + 2); j = n if j < 0 else j + 2
            for k in range(i, j):
                if out[k] != '\n': out[k] = ' '
            i = j; continue
        i += 1
    return ''.join(out)


def split_rules(text):
    """-> preamble, [ {name, private, start, end, text, cond} ] ; rule text includes its leading comments."""
    m = mask(text)
    hs = list(HEADER.finditer(m))
    if not hs:
        return text, [], ""
    rules = []
    for k, h in enumerate(hs):
        nxt = hs[k + 1].start() if k + 1 < len(hs) else len(m)
        end = m.rfind('}', h.end() - 1, nxt) + 1
        rules.append(dict(name=h.group(2), private=bool(h.group(1)), hstart=h.start(), hend=h.end(), end=end))
    pre = text[:rules[0]['hstart']]
    prev = rules[0]['hstart']
    for r in rules:
        r['text'] = text[prev:r['end']]          # leading comments + rule
        r['hoff'] = r['hstart'] - prev
        body = m[r['hend']:r['end']]
        cm = re.search(r'\bcondition\s*:(.*)$', body, re.S)
        r['cond'] = cm.group(1) if cm else ''
        sm = re.search(r'\bstrings\s*:(.*?)\bcondition\s*:', text[r['hend']:r['end']], re.S)
        r['strings'] = sm.group(1) if sm else ''
        prev = r['end']
    tail = text[prev:]
    return pre, rules, tail


def platform_reason(fname, r):
    """Why a rule cannot fire on a Windows workstation (None = keep)."""
    # Decided by the CONDITION; the file name alone never drops a rule.
    c = re.sub(r'\s+', '', r['cond'].lower()); s = r['strings'].lower(); n = r['name'].lower()
    # a condition that can accept a PE or a ZIP/JAR/Office container can fire here -> keep
    pe_ok = re.search(r'uint16\(0\)==0x5a4d|uint16be\(0\)==0x4d5a|\bpe\.', c)
    zip_ok = re.search(r'uint16\(0\)==0x4b50|uint32\(0\)==0x04034b50|uint32be\(0\)==0x504b0304', c) or 'jar' in n
    if pe_ok or zip_ok:
        return None
    elf = re.search(r'==0x464c457f|==0x7f454c46|\belf\.', c)
    macho = re.search(r'==0xfeedfac[ef]|==0xcffaedfe|==0xcefaedfe|uint16\(0\)==0xfacf|\bmacho\.', c)
    cafebabe = re.search(r'==0xbebafeca|==0xcafebabe|uint16\(0\)==0xfeca', c)   # Mach-O fat OR Java .class — neither is scanned
    if cafebabe and not elf and not macho:
        return "Java .class / Mach-O fat only (not scanned)"
    if elf and macho:
        return "ELF/Mach-O only"
    if elf:
        return "ELF only"
    if macho:
        return "Mach-O only"
    if re.search(r'\bdex\.', c) or 'android' in n:
        return "Android"
    # no file-type check: the rule NAME says it is for Linux/ESXi/macOS scripts or files
    if re.search(r'(^|_)(lnx|linux|elf|esxi|esxiargs|macos|osx|sh|py)(_|$)', n):
        return "Linux/ESXi/macOS (by rule name)"
    if ('webshell' in n or re.search(r'<\?php|<%@|<%=|runat=|\$_(post|get|request)\[', s)) and 'compiled' not in n:
        return "webshell source (PHP/JSP/ASPX; not scanned on workstations)"
    # no PE check and the rule / file NAME says it is for another platform, a network appliance or
    # server software, or for scripts the watcher never scans
    hay = n + "_" + fname.lower().rsplit('.', 1)[0]
    m = re.search(r'(^|_)(lnx|linux|unix|solaris|aix|freebsd|bsd|esx|vcenter|vmware|macos|osx|ios|'
                  r'cisco|asa|juniper|junos|fortinet|fortigate|fortios|ivanti|pulse|citrix|netscaler|'
                  r'confluence|jira|atlassian|barracuda|esg|zimbra|moveit|sonicwall|paloalto|panos|'
                  r'globalprotect|f5|bigip|mikrotik|router|iot|php|jsp|java|tomcat|weblogic|perl|python|'
                  r'bash|nginx|apache)(_|$)', hay)
    if m:
        return f"not a Windows workstation file ({m.group(2)}, no PE check)"
    return None


def old_reason(r):
    """Rule last changed in OLD_YEAR or before (None = keep; no date = keep)."""
    meta = r['text'][r['hoff']:]
    m = (re.search(r'\b(?:modified|last_modified|updated_date)\s*=\s*"(\d{4})', meta)
         or re.search(r'\b(?:date|creation_date|first_imported|created)\s*=\s*"(\d{4})', meta))
    if m and int(m.group(1)) <= OLD_YEAR:
        return f"old: last change {m.group(1)}"
    return None


def add_tag(rule_text, hoff, tag):
    """Insert `tag` into the rule header (rule X : a b {  /  rule X {)."""
    m = HEADER.match(mask(rule_text), hoff)
    head = rule_text[hoff:m.end()]
    if m.group(3):  # existing tags
        new = head[:-1].rstrip() + " " + tag + " {"
    else:
        new = re.sub(r'([A-Za-z0-9_]+)[ \t\r\n]*\{$', lambda x: x.group(1) + " : " + tag + " {", head)
    return rule_text[:hoff] + new + rule_text[m.end():]


def rename(rule_text, hoff, old, new):
    m = HEADER.match(mask(rule_text), hoff)
    head = rule_text[hoff:m.end()]
    return rule_text[:hoff] + re.sub(r'\brule([ \t]+)' + old + r'\b', 'rule\\g<1>' + new, head, count=1) + rule_text[m.end():]


def ensure_sources(vendor, fetch):
    for name, (url, commit) in SOURCES.items():
        d = vendor / name
        if commit.startswith("release:"):   # a release zip: unpacked into vendor/<name>, pinned by tag
            mark = d / ".release"
            if fetch and (not mark.exists() or mark.read_text().strip() != commit):
                d.mkdir(parents=True, exist_ok=True)
                z = d / os.path.basename(url)
                subprocess.run(["curl", "-fsSL", "-o", str(z), url], check=True)
                subprocess.run(["unzip", "-o", "-q", str(z), "-d", str(d)], check=True)
                mark.write_text(commit)
            if not mark.exists() or mark.read_text().strip() != commit:
                sys.exit(f"{name}: release {commit} not in {d} (use --fetch)")
            continue
        if not d.exists():
            if not fetch:
                sys.exit(f"missing {d} (run with --fetch to clone {url})")
            subprocess.run(["git", "clone", "-q", url, str(d)], check=True)
        if fetch:
            subprocess.run(["git", "-C", str(d), "fetch", "-q", "origin", commit], check=False)
            subprocess.run(["git", "-C", str(d), "checkout", "-q", commit], check=True)
        head = subprocess.run(["git", "-C", str(d), "rev-parse", "HEAD"], capture_output=True, text=True).stdout.strip()
        if head != commit:
            sys.exit(f"{name}: HEAD {head[:12]} != pinned {commit[:12]} (use --fetch)")


def build(vendor, out, yarac):
    sel = []
    for line in (HERE / "vendor-selection.txt").read_text().splitlines():
        line = line.split('#', 1)[0].strip()
        if line:
            od, src, rel = line.split()
            sel.append((od, src, rel))
    report = OrderedDict(dropped=[], duplicates=[], renamed=[], info=[], doc=[], files_skipped=[])
    seen = {}; bodies = {}; clashes = []
    index = []
    for od, src, rel in sel:
        text = (vendor / src / rel).read_text(encoding="utf-8", errors="replace")
        pre, rules, tail = split_rules(text)
        fname = os.path.basename(rel)
        keep = []
        for r in rules:
            why = None
            if not r['private']:
                why = (DROP.get(r['name']) or DROP.get((rel, r['name'])) or forge_reason(src, r)
                       or platform_reason(fname, r) or old_reason(r))
            r['drop'] = why
        kept_conds = " ".join(r['cond'] for r in rules if not r['drop'])
        for r in rules:
            if r['drop'] and re.search(r'\b%s\b' % r['name'], kept_conds):
                r['drop'] = None  # referenced by a kept rule
        for r in rules:
            if r['drop']:
                report['dropped'].append(f"{src}/{rel}: {r['name']} — {r['drop']}")
                continue
            t, name = r['text'], r['name']
            if (rel, name) in RENAME:
                new = RENAME[(rel, name)]
                t = rename(t, r['hoff'], name, new); name = new
                report['renamed'].append(f"{src}/{rel}: {r['name']} -> {new}")
            src_info = src in SOURCE_INFO and SOURCE_INFO[src].search(r['text'][r['hoff']:])
            if name in INFO or src_info:
                t = add_tag(t, r['hoff'], INFO_TAG)
                report['info'].append(f"{src}/{rel}: {name}" + (" (source: informational)" if src_info else ""))
            elif od.startswith("maldoc") and not r['private']:
                t = add_tag(t, r['hoff'], DOC_TAG)
                report['doc'].append(f"{src}/{rel}: {name}")
            body = re.sub(r'\s+', ' ', (r['strings'] + ' ' + r['cond'])).strip()
            if name in seen and not r['private']:
                if bodies[name] == body:   # same rule shipped twice (another repo / file): keep the first
                    report['duplicates'].append(f"{src}/{rel}: {name} — same as {seen[name]}")
                    continue
                clashes.append(f"{name}: {seen[name]} vs {src}/{rel}")
                continue
            seen[name] = f"{src}/{rel}"; bodies[name] = body
            keep.append(t)
        if not any(not r['drop'] and not r['private'] for r in rules):
            report['files_skipped'].append(f"{src}/{rel} — no rule left")
            continue
        dst = out / od / fname
        dst.parent.mkdir(parents=True, exist_ok=True)
        hdr = (f"// GENERATED by rules/tools/build_vendor_rules.py — do not edit.\n"
               f"// source: {SOURCES[src][0]} @ {SOURCES[src][1][:12]} : {rel}\n")
        dst.write_text(hdr + pre + "".join(keep) + tail, encoding="utf-8")
        index.append(f"{od}/{fname}")
    if clashes:
        sys.exit("rule name clashes (different rules, same name) — add RENAME entries:\n  " + "\n  ".join(clashes))
    # licenses of the sources
    for src, lic in (("signature-base", "LICENSE"), ("yara-rules-community", "LICENSE"), ("protections-artifacts", "LICENSE.txt"),
                     ("bartblaze", "LICENSE"), ("inquest", "LICENSE"), ("ditekshen", "LICENSE.txt"),
                     ("reversinglabs", "LICENSE")):
        p = vendor / src / lic
        if p.exists():
            shutil.copy(p, out / f"LICENSE-{src}")
    # YARA-Forge: one file with the licence of every source that is taken (DRL / BSD ask to keep it)
    lic_dir = vendor / "yara-forge" / "licenses"
    parts = ["Rules in general/yara-rules-core.yar come from YARA-Forge (https://yarahq.github.io/), release "
             + SOURCES["yara-forge"][1].split(":", 1)[1] + ". Each rule keeps its author / reference / source_url "
             "meta. Only these sources are taken; their licences follow.\n"]
    for repo, spdx in sorted(FORGE_SOURCES.items()):
        f = lic_dir / (repo.replace("/", "_") + ".txt")
        parts.append("=" * 78 + f"\n{repo} ({spdx}) - https://github.com/{repo}\n" + "=" * 78 + "\n"
                     + (f.read_text(errors="replace") if f.exists() else f"see https://github.com/{repo}\n"))
    (out / "LICENSE-yara-forge").write_text("\n".join(parts), encoding="utf-8")
    idx = ["// GENERATED by rules/tools/build_vendor_rules.py from tools/vendor-selection.txt — do not edit.",
           "// Vendor rules (no meta.severity) for docscan: applied to the raw file -> yara_file_matches,",
           "// and to decompressed VBA -> yara_matches. Rules tagged docscan_info -> yara_info_matches",
           "// (indicators: reported, never raise the verdict). See tools/vendor-report.md.", ""]
    idx += [f'include "{p}"' for p in index]
    idx += ["", "// DocScan's own rules", 'include "maldoc/vba_plaintext.yar"', ""]
    (out / "file-index.yar").write_text("\n".join(idx), encoding="utf-8")
    shutil.copy(RULES / "maldoc" / "vba_plaintext.yar", out / "maldoc" / "vba_plaintext.yar") if out != RULES else None
    # compile check
    # THOR/LOKI externals: yara64 declares and sets them per file (--file-vars, implied by --docscan-json)
    ext = sum((["-d", v + "="] for v in ("filename", "filepath", "extension", "filetype", "owner")), [])
    r = subprocess.run([yarac, "-w", *ext, str(out / "file-index.yar"), os.devnull], capture_output=True, text=True)
    if r.returncode != 0:
        sys.exit("COMPILE FAILED:\n" + (r.stderr or r.stdout)[:3000])
    nrules = len(seen)
    lines = ["# Vendor rules — build report", "",
             "Generated by `rules/tools/build_vendor_rules.py`. Sources:", ""]
    lines += [f"- {k}: {u} @ `{c[:12]}`" for k, (u, c) in SOURCES.items()]
    lines += ["", f"Files: {len(index)}, rules kept: {nrules}, dropped: {len(report['dropped'])}, "
              f"duplicates skipped: {len(report['duplicates'])}, renamed: {len(report['renamed'])}, info: {len(report['info'])}, doc: {len(report['doc'])}", ""]
    for k, title in (("dropped", "Dropped (cannot fire on a Windows workstation / DROP list)"),
                     ("duplicates", "Duplicates skipped (identical rule already taken from another file)"),
                     ("files_skipped", "Files with no rule left"),
                     ("renamed", "Renamed (identifier clashes)"),
                     ("info", f"Tagged `{INFO_TAG}` (indicators, do not raise the verdict)"),
                     ("doc", f"Tagged `{DOC_TAG}` (document rules: indicators only on non-documents)")):
        lines += [f"## {title} ({len(report[k])})", ""] + [f"- {x}" for x in report[k]] + [""]
    (out / "tools").mkdir(exist_ok=True)
    (out / "tools" / "vendor-report.md").write_text("\n".join(lines), encoding="utf-8")
    return len(index), nrules, report


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--vendor", type=Path, default=DEFAULT_VENDOR)
    ap.add_argument("--fetch", action="store_true")
    ap.add_argument("--yarac", default=str(RULES.parents[1] / "yarac"))
    ap.add_argument("--check", action="store_true")
    a = ap.parse_args()
    ensure_sources(a.vendor, a.fetch)
    if a.check:
        with tempfile.TemporaryDirectory() as t:
            t = Path(t); (t / "maldoc").mkdir()
            build(a.vendor, t, a.yarac)
            r = subprocess.run(["diff", "-rq", "-x", "tools", "-x", "docscan*", "-x", ".DS_Store", str(t), str(RULES)], capture_output=True, text=True)
            print(r.stdout or "rules/ is up to date"); sys.exit(1 if r.stdout else 0)
    # rebuild in place: wipe generated dirs first
    for d in ("general", "maldoc/signature-base", "maldoc/community", "maldoc/bartblaze", "maldoc/inquest", "maldoc/ditekshen"):
        shutil.rmtree(RULES / d, ignore_errors=True)
    for f in RULES.glob("LICENSE-*"):
        f.unlink()
    n, nr, rep = build(a.vendor, RULES, a.yarac)
    print(f"files {n}, rules {nr}, dropped {len(rep['dropped'])}, renamed {len(rep['renamed'])}, info {len(rep['info'])}")


if __name__ == "__main__":
    main()

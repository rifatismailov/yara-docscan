package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"
)

// ---- the record written to docscan-results.json (one JSON per line, read by the Wazuh agent) ----
// Field order and the "no null values" rule are those of the PowerShell watcher: the Wazuh json decoder turns
// null into the string "null", and the first such event of a day would map data.docscan / data.macro /
// data.critical as keyword in the daily index - every later alert with an object there is then rejected.

type DocFile struct {
	Path   string `json:"path"`
	Name   string `json:"name"`
	Ext    string `json:"ext"`
	Size   *int64 `json:"size,omitempty"`
	Sha256 string `json:"sha256,omitempty"`
}

type MacroInfo struct {
	File     string `json:"file"`
	Size     int64  `json:"size"`
	Uploaded bool   `json:"uploaded"`
}

type CritInfo struct {
	Queued    bool     `json:"queued"`
	Fragments int      `json:"fragments"`
	Rules     []string `json:"rules"`
}

type Record struct {
	Timestamp string `json:"timestamp"`
	Source    string `json:"source"`
	Host      string `json:"host"`
	Event     string `json:"event"`
	Category  string `json:"category"`
	// NOT 'file': in the Wazuh indices data.file is a keyword, the indexer rejects an object there
	DocFile         DocFile         `json:"docfile"`
	Verdict         string          `json:"verdict"`
	Docscan         json.RawMessage `json:"docscan,omitempty"`
	YaraFileMatches []string        `json:"yara_file_matches"`
	Disarm          string          `json:"disarm,omitempty"`
	Macro           *MacroInfo      `json:"macro,omitempty"`
	Critical        *CritInfo       `json:"critical,omitempty"`
	List            *ListHit        `json:"list,omitempty"` // decided by the white / black list (lists.go)
	Scan            string          `json:"scan,omitempty"` // id of the on-demand / USB scan (scanjob.go)
	Summary         string          `json:"summary"`        // for the Wazuh alert description
	Errors          []string        `json:"errors"`

	ds     *dsResult `json:"-"`
	detect bool      `json:"-"` // this file: report only (scanOpts.detect)
}

// scanOpts - a file of an on-demand / USB scan (scanjob.go): the cache of clean files, report only
type scanOpts struct {
	scan   string
	detect bool
}

// noDisarmFor - report only for this record: the whole DocScan in detect-only mode, or this scan / medium
func (w *Watcher) noDisarmFor(r *Record) bool { return r.detect || w.noDisarm() }

// the parts of the docscan JSON the watcher needs (the whole object goes into the record as it is)
type dsResult struct {
	Ftype    string `json:"ftype"`
	Evidence struct {
		LnkTarget string `json:"lnk_target"`
	} `json:"evidence"`
	Verdict         string   `json:"verdict"`
	Findings        []string `json:"findings"`
	FindingsText    []string `json:"findings_text"`
	YaraMatches     []string `json:"yara_matches"`
	YaraFileMatches []string `json:"yara_file_matches"`
	YaraDocMatches  []string `json:"yara_doc_matches"`
	YaraPartMatches []struct {
		Part  string   `json:"part"`
		Rules []string `json:"rules"`
	} `json:"yara_part_matches"`
	YaraDescriptions []struct {
		Rule        string `json:"rule"`
		Description string `json:"description"`
	} `json:"yara_descriptions"`
}

func nowStamp() string { return time.Now().Format("2006-01-02T15:04:05.000-07:00") }

func fileSHA256(p string) (string, error) {
	f, err := os.Open(p)
	if err != nil {
		return "", err
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

// a file is ready when it can be opened for reading and its size does not change
func waitFileReady(p string, timeout time.Duration) string {
	deadline := time.Now().Add(timeout)
	last := int64(-1)
	for time.Now().Before(deadline) {
		if !isFile(p) {
			return "gone"
		}
		if f, err := os.Open(p); err == nil {
			st, serr := f.Stat()
			f.Close()
			if serr == nil {
				if st.Size() == last {
					return "ready"
				}
				last = st.Size()
			}
		}
		time.Sleep(500 * time.Millisecond)
	}
	return "timeout"
}

// openOnce - can the file be read now (on-demand scan): ready | gone | locked:<error>
func openOnce(p string) string {
	f, err := os.Open(p)
	if err != nil {
		if !isFile(p) {
			return "gone"
		}
		return "locked:" + err.Error()
	}
	f.Close()
	return "ready"
}

var (
	reDisarm = regexp.MustCompile(`^docscan-disarm: .* -> `)
	reCrit   = regexp.MustCompile(`fragments=(\d+) rules=(\S*)`)
	reErr    = regexp.MustCompile(`(?i)^error`)
)

type scanOut struct {
	raw      json.RawMessage
	ds       *dsResult
	disarm   string
	errors   []string
	critical *CritInfo
}

// One yara64 run: JSON (policy + vendor) and, for documents, the disarm action. For a document the decompressed
// VBA is written to macroTmp (yara writes it only when there are macros, before any disarm), and with the
// critical check the text goes to critTmp: a private queue file of this worker, appended to the real queue by
// the caller (several yara64 appending to one file at once could interleave their lines).
func (w *Watcher) invokeScan(path string, cure, extract, critical bool, macroTmp, critTmp string) scanOut {
	args := []string{"-w", "--docscan-json"}
	if cure {
		args = append(args, "--docscan-disarm", "--docscan-backup-dir="+w.c.BackupDir)
	}
	if extract {
		os.Remove(macroTmp)
		args = append(args, "--docscan-extract="+macroTmp)
	}
	if extract && w.criticalOn && critical {
		os.Remove(critTmp)
		args = append(args, "--critical-rules="+w.c.CriticalRules, "--critical-out="+critTmp)
	}
	args = append(args, w.ruleArgs...)
	args = append(args, path)

	ctx, cancel := context.WithTimeout(context.Background(), w.c.ScanTimeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, w.c.Yara, args...)
	hideWindow(cmd)
	out, _ := cmd.CombinedOutput() // yara64 output is UTF-8; stdout + stderr like 2>&1
	var so scanOut
	if ctx.Err() == context.DeadlineExceeded {
		so.errors = append(so.errors, fmt.Sprintf("yara64 did not finish in %s - killed", w.c.ScanTimeout))
	}
	var jsonLine, act, critLine string
	for _, l := range strings.Split(string(out), "\n") {
		l = strings.TrimRight(l, "\r")
		switch {
		case jsonLine == "" && strings.HasPrefix(l, "{"):
			jsonLine = l
		case act == "" && strings.HasPrefix(l, "docscan-disarm:"):
			act = l
		case critLine == "" && strings.HasPrefix(l, "docscan-critical: queued"):
			critLine = l
		}
		if reErr.MatchString(l) || strings.HasPrefix(l, "docscan-critical: could not") ||
			strings.HasPrefix(l, "docscan-critical: invalid") {
			so.errors = append(so.errors, l)
		}
	}
	if m := reCrit.FindStringSubmatch(critLine); m != nil {
		n, _ := strconv.Atoi(m[1])
		rules := []string{}
		for _, r := range strings.Split(m[2], ",") {
			if r != "" {
				rules = append(rules, r)
			}
		}
		so.critical = &CritInfo{Queued: true, Fragments: n, Rules: rules}
	}
	if jsonLine != "" {
		var ds dsResult
		var buf bytes.Buffer
		if err := json.Unmarshal([]byte(jsonLine), &ds); err != nil || json.Compact(&buf, []byte(jsonLine)) != nil {
			so.errors = append(so.errors, "bad docscan json: "+jsonLine)
		} else {
			so.ds, so.raw = &ds, buf.Bytes()
		}
	}
	if act != "" {
		so.disarm = reDisarm.ReplaceAllString(act, "")
	}
	return so
}

var rank = map[string]int{"INFO": 0, "MEDIUM": 1, "HIGH": 2}

func maxVerdict(a, b string) string {
	if rank[b] > rank[a] {
		return b
	}
	return a
}

func uniq(v []string) []string {
	seen := map[string]bool{}
	o := []string{}
	for _, s := range v {
		if s != "" && !seen[s] {
			seen[s] = true
			o = append(o, s)
		}
	}
	return o
}

// Human-readable description: policy rule texts, vendor rule descriptions, rules on the VBA code, the disarm
// action. Capped at 600 characters (Wazuh alert description).
func (w *Watcher) summary(r *Record) string {
	var p []string
	ds := r.ds
	if r.Event == "DisarmPending" {
		p = append(p, fmt.Sprintf("Disarm not done in %g h: the file is still open in another program - manual check needed", w.c.DisarmNoticeHours))
	}
	if ds != nil {
		p = append(p, ds.FindingsText...)
	}
	where := map[string]string{}
	if ds != nil {
		for _, pm := range ds.YaraPartMatches {
			for _, rl := range pm.Rules {
				if where[rl] == "" {
					where[rl] = pm.Part
				}
			}
		}
		for _, rl := range ds.YaraMatches {
			if rl != "" && where[rl] == "" {
				where[rl] = "macro code"
			}
		}
	}
	for _, m := range r.YaraFileMatches {
		t := "YARA " + m
		if where[m] != "" {
			t += " (in " + where[m] + ")"
		}
		if ds != nil {
			for _, d := range ds.YaraDescriptions {
				if d.Rule == m && d.Description != "" {
					t += " - " + d.Description
					break
				}
			}
		}
		p = append(p, t)
	}
	if lh := r.List; lh != nil {
		t := map[string]string{"white": "Дозволено білим списком організації", "black": "Файл у чорному списку організації"}[lh.List]
		t += fmt.Sprintf(" (запис %d: %s", lh.Entry+1, lh.By)
		if lh.Comment != "" {
			t += ", " + lh.Comment
		}
		p = append(p, t+")")
	}
	if r.Disarm != "" {
		p = append(p, "action: "+r.Disarm)
	}
	if r.Verdict == "SKIPPED" || r.Verdict == "ERROR" {
		p = append(p, strings.Join(r.Errors, "; "))
	}
	t := strings.Join(p, " | ")
	if rs := []rune(t); len(rs) > 600 {
		t = string(rs[:597]) + "..."
	}
	return t
}

// scanFile: one file, the PowerShell watcher's Scan-File. Runs in a worker; shared state (critical queue,
// macro store) is guarded inside the helpers. Returns nil when the file is gone before the scan.
func (w *Watcher) scanFile(path, evt string, wk *worker, o scanOpts) *Record {
	cat := w.category(path)
	var state string
	if o.scan != "" {
		state = openOnce(path) // a file already on the disk: nobody is writing it, no 0.5 s+ wait per file
	} else {
		state = waitFileReady(path, w.c.ReadyTimeout)
	}
	if state == "gone" {
		w.log.Log("WARN", "gone before scan: %s", path)
		return nil
	}
	ext := strings.ToLower(filepath.Ext(path))
	r := &Record{
		Timestamp: nowStamp(), Source: "docscan", Host: w.host, Event: evt, Category: cat,
		DocFile: DocFile{Path: path, Name: filepath.Base(path), Ext: ext},
		Verdict: "INFO", YaraFileMatches: []string{}, Errors: []string{}, Scan: o.scan, detect: o.detect,
	}
	if state == "timeout" {
		r.Errors = append(r.Errors, fmt.Sprintf("file still being written after %ds", int(w.c.ReadyTimeout.Seconds())))
	}
	if strings.HasPrefix(state, "locked:") { // on-demand scan: held by the system (pagefile.sys) or another program
		r.Errors = append(r.Errors, "cannot open: "+strings.TrimPrefix(state, "locked:"))
		r.Verdict = "ERROR"
		r.Summary = w.summary(r)
		return r
	}
	func() {
		st, err := os.Stat(path)
		if err != nil {
			r.Errors = append(r.Errors, err.Error())
			return
		}
		size := st.Size()
		r.DocFile.Size = &size
		if size > int64(w.c.MaxSizeMB)*1024*1024 {
			// too big to scan, but the lists by path / shortcut target still apply (a banned installer of 200 MB
			// must not slip through); sha256 entries need the hash - not computed for such files
			if w.applyLists(r, path, "", wk) {
				return
			}
			r.Verdict = "SKIPPED"
			r.Errors = append(r.Errors, fmt.Sprintf("size > %dMB", w.c.MaxSizeMB))
			return
		}
		sha, err := fileSHA256(path)
		if err != nil {
			r.Errors = append(r.Errors, err.Error())
			return
		}
		r.DocFile.Sha256 = sha
		// white / black lists of the organisation decide BEFORE the scan (lists.go)
		if w.applyLists(r, path, sha, wk) {
			return
		}
		if o.scan != "" && w.cache.has(sha) { // on-demand / USB scan: already found clean with these rules
			r.Verdict = "CACHED"
			return
		}

		// vendor rules see the bytes BEFORE disarm: yara collects the matches before --docscan-disarm.
		// The same content goes to the E5Search queue once (disarm retries / DisarmPending rescan it).
		critNew := cat == "document" && w.criticalOn && w.critClaim(sha)
		// a .zip is a "general" file, but the module inspects the documents inside it: disarm (= quarantine of
		// the whole archive when a document inside is dangerous) and the macro copy apply to it too; the
		// critical-information check does not (it is for documents themselves)
		isZip := ext == ".zip"
		doc := cat == "document"
		so := w.invokeScan(path, !w.noDisarmFor(r) && (doc || isZip), doc || isZip, critNew && doc, wk.macroTmp, wk.critTmp)
		r.Errors = append(r.Errors, so.errors...)
		if critNew && so.ds == nil && so.critical == nil {
			w.critRelease(sha) // yara64 did not run properly: the check did not happen
		}
		if so.critical != nil {
			if err := w.critAppend(wk.critTmp, sha); err != nil {
				r.Errors = append(r.Errors, "critical queue: "+err.Error())
			} else {
				r.Critical = so.critical
			}
		}
		if doc {
			if mc := w.saveMacro(sha, r, so.ds, wk.macroTmp); mc != nil {
				mc.Uploaded = w.sendMacro(mc.File)
				r.Macro = mc
			}
		}
		if so.ds != nil {
			r.Docscan, r.ds, r.Disarm = so.raw, so.ds, so.disarm
			r.YaraFileMatches = append([]string{}, so.ds.YaraFileMatches...)
			// document rules (tag docscan_doc) - detection only for documents; the same for the second pass:
			// matches in the extracted document parts and in the macro code. A .zip too: its parts are the
			// files inside the archive (an exe or a miner packed into a zip is found only there)
			if doc || isZip {
				r.YaraFileMatches = append(r.YaraFileMatches, so.ds.YaraDocMatches...)
				for _, pm := range so.ds.YaraPartMatches {
					r.YaraFileMatches = append(r.YaraFileMatches, pm.Rules...)
				}
				r.YaraFileMatches = append(r.YaraFileMatches, so.ds.YaraMatches...)
			}
			r.YaraFileMatches = uniq(r.YaraFileMatches)
			r.Verdict = so.ds.Verdict
		}
		// vendor rule on the file itself: document - at least MEDIUM, general - HIGH
		if len(r.YaraFileMatches) > 0 {
			if doc {
				r.Verdict = maxVerdict(r.Verdict, "MEDIUM")
			} else {
				r.Verdict = "HIGH"
			}
		}
		// general file matching vendor rules: optional quarantine (copy -> BackupDir, the original is deleted)
		if w.c.QuarantineGeneral && !w.noDisarmFor(r) && cat == "general" && len(r.YaraFileMatches) > 0 {
			if err := quarantine(path, w.c.BackupDir); err != nil {
				r.Errors = append(r.Errors, "quarantine failed: "+err.Error())
				r.Disarm = "failed:quarantine"
			} else {
				r.Disarm = "quarantined"
			}
		}
		// an archive under another name (a ZIP called soy.exe): yara64 recognises it by its content (ftype
		// "zip") and checks the files inside - a vendor rule on a file inside gives MEDIUM (reported only)
		if so.ds != nil && so.ds.Ftype == "zip" && !doc && !isZip {
			var inner []string
			for _, pm := range so.ds.YaraPartMatches {
				inner = append(inner, pm.Rules...)
			}
			if inner = uniq(inner); len(inner) > 0 {
				r.YaraFileMatches = uniq(append(r.YaraFileMatches, inner...))
				r.Verdict = maxVerdict(r.Verdict, "MEDIUM")
			}
		}
	}()
	if len(r.Errors) > 0 && r.ds == nil && len(r.YaraFileMatches) == 0 && r.Verdict == "INFO" {
		r.Verdict = "ERROR"
	}
	r.Summary = w.summary(r)
	return r
}

func quarantine(path, dir string) error {
	var dst string
	for i := 0; ; i++ {
		dst = filepath.Join(dir, fmt.Sprintf("%s.%d.docscan-bak", filepath.Base(path), i))
		if !exists(dst) {
			break
		}
	}
	in, err := os.Open(path)
	if err != nil {
		return err
	}
	out, err := os.OpenFile(dst, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		in.Close()
		return err
	}
	_, err = io.Copy(out, in)
	in.Close()
	if cerr := out.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		os.Remove(dst)
		return err
	}
	return os.Remove(path)
}

// log line of a scan: "<verdict> <category> <path>  <what>" (the CI checks and the load-test report parse it)
func (w *Watcher) logScan(r *Record, repeat bool) {
	var what []string
	if r.ds != nil {
		what = append(what, strings.Join(r.ds.Findings, ","))
	}
	if len(r.YaraFileMatches) > 0 {
		what = append(what, "yara:"+strings.Join(r.YaraFileMatches, ","))
	}
	if r.Disarm != "" {
		what = append(what, "disarm:"+r.Disarm)
	}
	if r.Critical != nil {
		what = append(what, "critical:"+strings.Join(r.Critical.Rules, ","))
	}
	lvl := "OK"
	switch r.Verdict {
	case "HIGH", "MEDIUM":
		lvl = "HIT"
	case "ERROR":
		lvl = "ERROR"
	case "SKIPPED":
		lvl = "WARN"
	}
	if repeat {
		what = append(what, "(unchanged - not written for Wazuh)")
	}
	w.log.Log(lvl, "%-7s %-8s %s  %s", r.Verdict, r.Category, r.DocFile.Path, strings.Join(what, " | "))
}

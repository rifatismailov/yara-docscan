package main

// Опис: docscan-project/DOCSCAN.md#watcher — сховище макросів і черга третього проходу.

import (
	"bytes"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"
	"unicode/utf8"
)

// ---- critical-information queue (E5Search) ----
// yara64 writes the matched document text to the worker's private file (critTmp); here it is appended to the
// real queue by one writer at a time. The reader (E5Search) takes the queue by renaming it, so every append
// opens the file anew.

type critState struct {
	mu   sync.Mutex
	seen map[string]bool // sha256 of documents checked (this run): the same content is checked once
}

// critClaim: true for the first worker that checks this content. Claimed BEFORE the scan: the same document
// copied into many profiles is scanned by several workers at once, and checking "already queued" after the
// scan let each of them queue it (load test: 443 queue lines instead of ~322). The same content gives the
// same result, so a claimed content without a match is not checked again either.
func (w *Watcher) critClaim(sha string) bool {
	w.crit.mu.Lock()
	defer w.crit.mu.Unlock()
	if w.crit.seen[sha] {
		return false
	}
	if len(w.crit.seen) > 20000 {
		w.crit.seen = map[string]bool{}
	}
	w.crit.seen[sha] = true
	return true
}

// critRelease: the check did not run (scan error) - another copy may try again
func (w *Watcher) critRelease(sha string) {
	w.crit.mu.Lock()
	delete(w.crit.seen, sha)
	w.crit.mu.Unlock()
}

func (w *Watcher) critAppend(tmp, sha string) error {
	data, err := os.ReadFile(tmp)
	os.Remove(tmp)
	if err != nil {
		return err
	}
	if len(data) == 0 {
		return fmt.Errorf("yara64 reported a queued document, but its queue file is empty")
	}
	if data[len(data)-1] != '\n' {
		data = append(data, '\n')
	}
	w.crit.mu.Lock()
	defer w.crit.mu.Unlock()
	f, err := os.OpenFile(w.c.CriticalOut, os.O_WRONLY|os.O_CREATE|os.O_APPEND, 0o600)
	if err != nil {
		return err
	}
	_, err = f.Write(data)
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	return err
}

// ---- macro store: <MacroDir>\<document sha256>.vba.txt (one file per document content) ----
// The file starts with a short header (VBA comment lines, UTF-8): host, document path, sha256, findings, time -
// so a copy on the collector is self-describing. Then the VBA code as yara extracted it. Sent files are listed
// in <MacroDir>\sent.txt (one sha256 per line); the rest is retried hourly by syncMacros.

type macroState struct {
	mu      sync.Mutex // store files + sent set
	sent    map[string]bool
	sentF   string
	syncing sync.Mutex
}

var reSha = regexp.MustCompile(`^[0-9a-f]{64}$`)

func (w *Watcher) loadMacroSent() {
	m := &w.macro
	m.sent = map[string]bool{}
	m.sentF = filepath.Join(w.c.MacroDir, "sent.txt")
	if data, err := os.ReadFile(m.sentF); err == nil {
		for _, l := range strings.Split(string(data), "\n") {
			if l = strings.TrimSpace(l); reSha.MatchString(l) {
				m.sent[l] = true
			}
		}
		return
	}
	// first start after the oldest watcher versions: files they already sent (Archive cleared) count as sent
	if ents, err := os.ReadDir(w.c.MacroDir); err == nil {
		for _, e := range ents {
			if strings.HasSuffix(e.Name(), ".vba.txt") && !archiveBit(filepath.Join(w.c.MacroDir, e.Name())) {
				m.sent[strings.TrimSuffix(e.Name(), ".vba.txt")] = true
			}
		}
	}
	w.writeSent()
}

func (w *Watcher) writeSent() {
	var b strings.Builder
	for k := range w.macro.sent {
		b.WriteString(k + "\r\n")
	}
	os.WriteFile(w.macro.sentF, []byte(b.String()), 0o600)
}

func (w *Watcher) saveMacro(sha string, r *Record, ds *dsResult, tmp string) *MacroInfo {
	st, err := os.Stat(tmp)
	if err != nil {
		return nil
	}
	defer os.Remove(tmp)
	if st.Size() == 0 {
		return nil
	}
	dst := filepath.Join(w.c.MacroDir, sha+".vba.txt")
	w.macro.mu.Lock()
	defer w.macro.mu.Unlock()
	if !exists(dst) {
		var findings []string
		if ds != nil {
			findings = ds.Findings
		}
		hdr := "' DocScan macro\r\n' host: " + w.host + "\r\n' file: " + r.DocFile.Path + "\r\n' sha256: " + sha +
			"\r\n' findings: " + strings.Join(findings, ", ") + "\r\n' saved: " + time.Now().Format("2006-01-02T15:04:05-07:00") + "\r\n'\r\n"
		raw, err := os.ReadFile(tmp)
		if err != nil {
			return nil
		}
		// the VBA source is in the project's ANSI code page (e.g. Windows-1251), the header is UTF-8: valid UTF-8
		// (or plain ASCII) is kept as it is, anything else is decoded with this PC's ANSI code page
		code := string(raw)
		if !utf8.Valid(raw) {
			code = ansiToUTF8(raw)
		}
		if err := os.WriteFile(dst, []byte(hdr+code), 0o600); err != nil {
			return nil
		}
	}
	return &MacroInfo{File: dst, Size: st.Size()}
}

// POST the stored file (header + code) to the collector, e.g. http://<server>:8080/
func (w *Watcher) sendMacro(file string) bool {
	if w.c.MacroUpload == "" {
		return false
	}
	sha := strings.TrimSuffix(filepath.Base(file), ".vba.txt")
	w.macro.mu.Lock()
	done := w.macro.sent[sha]
	w.macro.mu.Unlock()
	if done {
		return true
	}
	data, err := os.ReadFile(file)
	if err != nil {
		return false
	}
	cl := &http.Client{Timeout: 15 * time.Second}
	resp, err := cl.Post(w.c.MacroUpload+"/", "application/octet-stream", bytes.NewReader(data))
	if err == nil {
		resp.Body.Close()
		if resp.StatusCode >= 300 {
			err = fmt.Errorf("HTTP %d", resp.StatusCode)
		}
	}
	if err != nil {
		w.log.Log("WARN", "macro upload failed (will retry): %s - %v", filepath.Base(file), err)
		return false
	}
	w.macro.mu.Lock()
	w.macro.sent[sha] = true
	if f, err := os.OpenFile(w.macro.sentF, os.O_WRONLY|os.O_CREATE|os.O_APPEND, 0o600); err == nil {
		f.WriteString(sha + "\r\n")
		f.Close()
	}
	w.macro.mu.Unlock()
	return true
}

// retention + upload retry: at start and then once an hour (in its own goroutine: uploads may be slow)
func (w *Watcher) syncMacros() {
	if !w.macro.syncing.TryLock() {
		return
	}
	defer w.macro.syncing.Unlock()
	type fi struct {
		path string
		name string
		size int64
		mod  time.Time
	}
	var files []fi
	if ents, err := os.ReadDir(w.c.MacroDir); err == nil {
		for _, e := range ents {
			if !strings.HasSuffix(e.Name(), ".vba.txt") {
				continue
			}
			if inf, err := e.Info(); err == nil && inf.Mode().IsRegular() {
				files = append(files, fi{filepath.Join(w.c.MacroDir, e.Name()), e.Name(), inf.Size(), inf.ModTime()})
			}
		}
	}
	sort.Slice(files, func(i, j int) bool { return files[i].mod.Before(files[j].mod) })
	limit := time.Now().AddDate(0, 0, -w.c.MacroKeepDays)
	var total int64
	for _, f := range files {
		total += f.size
	}
	var kept []fi
	for _, f := range files {
		if f.mod.Before(limit) || total > int64(w.c.MacroMaxMB)*1024*1024 {
			total -= f.size
			os.Remove(f.path)
		} else {
			kept = append(kept, f)
		}
	}
	// sent.txt keeps only the files that are still in the store
	keep := map[string]bool{}
	for _, f := range kept {
		keep[strings.TrimSuffix(f.name, ".vba.txt")] = true
	}
	w.macro.mu.Lock()
	stale := false
	for k := range w.macro.sent {
		if !keep[k] {
			delete(w.macro.sent, k)
			stale = true
		}
	}
	if stale {
		w.writeSent()
	}
	w.macro.mu.Unlock()
	if w.c.MacroUpload != "" {
		// one per second at most: the collector names files <ip>_<yyyyMMdd_HHmmss>.txt
		for _, f := range kept {
			w.macro.mu.Lock()
			done := w.macro.sent[strings.TrimSuffix(f.name, ".vba.txt")]
			w.macro.mu.Unlock()
			if done {
				continue
			}
			if !w.sendMacro(f.path) {
				break
			}
			time.Sleep(1100 * time.Millisecond)
		}
	}
}

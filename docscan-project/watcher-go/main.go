// DocScan watcher (Go) - watches for new files and scans them with yara64.exe, several at once.
//
// Replaces docscan-watcher.ps1 with the same options, the same docscan-results.json records (read by the Wazuh
// agent) and the same watcher.log lines. Why: the PowerShell watcher handled change events in one thread and
// drained the whole event queue before scanning anything; Get-Event made each step walk the whole queue, so a
// burst of ~100 000 new files (25 users unpacking at once on a terminal server) kept it busy for hours with no
// scan at all and memory growing. Here:
//
//	watchTree (one goroutine per folder)  ReadDirectoryChangesW -> events channel; never waits for anything
//	coordinator (one goroutine)           owns all state: merges the events of a file, waits for the quiet
//	                                      time, cooldown, scan order (sched.go: retries, single files, then
//	                                      bulk copies round-robin per user), writes the records and the log
//	                                      lines, disarm retries, rescans, pool size
//	workers (pool.go)                     file ready -> sha256 -> yara64 (+ disarm, macro copy, critical queue);
//	                                      automatic count -MinWorkers..-MaxWorkers by queue and machine CPU
//	                                      (-Workers N = fixed), yara64 at below-normal priority
//
// A burst is scanned while it is still arriving, and a file saved or downloaded during a burst goes before it.
// Queue size is logged every minute while there is a queue, with a WARN when it keeps growing.
//
// One run per file:  yara64 -w --docscan-json [--docscan-disarm] -C rules.yarc <file>
// (rules.yarc is compiled from the rules once at start)
package main

import (
	"encoding/json"
	"fmt"
	"io/fs"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"runtime"
	"strings"
	"sync/atomic"
	"syscall"
	"time"

	"docscan/watcher/winsvc"
)

type fsEvent struct {
	path string
	evt  string
	t    time.Time
}

type job struct {
	path     string
	evt      string
	prevHash string // sha256 of the last scan: the same content is not scanned again
	retry    bool   // DisarmRetry / DisarmPending
}

type result struct {
	j         job
	rec       *Record // nil: gone, or unchanged content (skipped)
	unchanged bool
	hashAfter string
	locked    bool // disarm failed and the file is held by another program
}

type worker struct {
	id       int
	macroTmp string
	critTmp  string
}

type retryItem struct {
	next     time.Time
	since    time.Time
	noticed  bool
	inFlight bool
}

type Watcher struct {
	c          *Config
	log        *Logger
	results    *appender
	host       string
	ruleArgs   []string
	criticalOn bool
	docSet     map[string]bool
	genSet     map[string]bool
	crit       critState
	macro      macroState
	retryFile  string
}

func (w *Watcher) category(p string) string {
	ext := strings.ToLower(filepath.Ext(p))
	if w.docSet[ext] {
		return "document"
	}
	if w.genSet[ext] {
		return "general"
	}
	return ""
}

func hasPrefixFold(s, prefix string) bool {
	return len(s) >= len(prefix) && strings.EqualFold(s[:len(prefix)], prefix)
}

func (w *Watcher) excluded(p string) bool {
	for _, d := range []string{w.c.OutDir, w.c.BackupDir, w.c.MacroDir, filepath.Dir(w.c.CriticalOut)} {
		if hasPrefixFold(p, d) {
			return true
		}
	}
	for _, re := range w.c.Exclude {
		if re.MatchString(p) {
			return true
		}
	}
	return false
}

// ServiceName — служба Windows watcher-а (sc query DocScanWatcher); у списку служб — "DocScan Watcher".
const ServiceName = "DocScanWatcher"

func main() {
	c, err := parseConfig(os.Args[1:])
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(2)
	}
	body := func(stop <-chan os.Signal) int { return start(c, stop) }
	// служба Windows (install.ps1): SCM подає «стоп»; інакше — консоль, Ctrl+C / SIGTERM
	if ok, code := winsvc.Run(ServiceName, body); ok {
		os.Exit(code)
	}
	stop := make(chan os.Signal, 1)
	signal.Notify(stop, os.Interrupt, syscall.SIGTERM)
	os.Exit(body(stop))
}

// start — усе від підготовки тек і правил до зупинки; код виходу (0 — зупинено як слід).
func start(c *Config, stop <-chan os.Signal) int {
	for _, d := range []string{c.OutDir, c.BackupDir, c.MacroDir} {
		os.MkdirAll(d, 0o755)
	}
	w := &Watcher{c: c, host: hostName(), docSet: map[string]bool{}, genSet: map[string]bool{}}
	w.log = &Logger{a: &appender{file: filepath.Join(c.OutDir, "watcher.log"), maxBytes: int64(c.MaxLogMB) << 20, keep: c.KeepLogs}}
	w.results = &appender{file: filepath.Join(c.OutDir, "docscan-results.json"), maxBytes: int64(c.MaxLogMB) << 20, keep: c.KeepLogs}
	w.retryFile = filepath.Join(c.OutDir, "retry.json")
	w.crit.seen = map[string]bool{}
	for _, e := range c.DocExt {
		w.docSet[e] = true
	}
	for _, e := range c.GenExt {
		w.genSet[e] = true
	}
	if c.CriticalRules != "" {
		if isFile(c.CriticalRules) {
			os.MkdirAll(filepath.Dir(c.CriticalOut), 0o755)
			w.criticalOn = true
			for _, e := range c.CriticalExt {
				w.docSet[e] = true
			}
		} else {
			w.log.Log("WARN", "critical rules not found: %s - critical check off", c.CriticalRules)
		}
	}
	w.loadMacroSent()
	// правил ще немає (DocScan поставили без -Rules або їх щойно прибрали) — нічого не сканувати і чекати:
	// їх покладе install.ps1 -Rules або служба DocScanUpdater; падати й перезапускатися по колу немає сенсу
	if !exists(c.Rules) {
		w.log.Log("WARN", "waiting for rules: %s is missing - nothing is scanned until the rules are installed (install.ps1 -Rules, DocScanUpdater)", c.Rules)
		for !exists(c.Rules) {
			select {
			case <-stop:
				w.log.Log("INFO", "stopped (no rules)")
				return 0
			case <-time.After(15 * time.Second):
			}
		}
		time.Sleep(5 * time.Second) // правила щойно з'явились — дати updater-у дописати всі файли
		w.log.Log("INFO", "rules appeared: %s", c.Rules)
	}
	if err := w.prepareRules(); err != nil {
		w.log.Log("ERROR", "%v", err)
		return 1
	}
	return w.run(stop)
}

// rules: exist, compile (otherwise every scan would fail silently), then compiled ONCE with yarac64 -> every
// scan runs with -C. Thousands of vendor rules take ~0.5 s or more to compile - per file that would be seconds.
func (w *Watcher) prepareRules() error {
	c := w.c
	for _, p := range []string{c.Yara, c.Rules} {
		if !exists(p) {
			return fmt.Errorf("NOT FOUND: %s", p)
		}
	}
	probe := filepath.Join(c.OutDir, "probe.txt")
	os.WriteFile(probe, []byte("probe\r\n"), 0o644)
	cmd := execCmd(c.Yara, "-w", "--file-vars", c.Rules, probe)
	out, _ := cmd.CombinedOutput()
	os.Remove(probe)
	var errs []string
	for _, l := range strings.Split(string(out), "\n") {
		if strings.Contains(strings.ToLower(l), "error") {
			errs = append(errs, strings.TrimSpace(l))
		}
	}
	if len(errs) > 0 {
		return fmt.Errorf("the rules do not compile: %s - %s", c.Rules, strings.Join(errs, " "))
	}
	w.ruleArgs = []string{c.Rules}
	compiled := filepath.Join(c.OutDir, "rules.yarc")
	if !exists(c.Yarac) {
		w.log.Log("WARN", "%s is missing - scanning from the source .yar (every scan recompiles the rules)", c.Yarac)
		return nil
	}
	os.Remove(compiled)
	// the variables filename/filepath/extension/filetype/owner are declared here, yara64 sets them per file
	cmd = execCmd(c.Yarac, "-w", "-d", "filename=", "-d", "filepath=", "-d", "extension=", "-d", "filetype=", "-d", "owner=", c.Rules, compiled)
	out, err := cmd.CombinedOutput()
	if err == nil && exists(compiled) {
		w.ruleArgs = []string{"-C", compiled}
	} else {
		w.log.Log("WARN", "yarac64 did not compile the rules, scanning from the source .yar (slower): %s", strings.TrimSpace(string(out)))
	}
	return nil
}

func (w *Watcher) run(stop <-chan os.Signal) int {
	c := w.c
	events := make(chan fsEvent, 200000)
	var overflow atomic.Bool
	watching := 0
	for _, wp := range c.WatchPath {
		if !exists(wp) {
			w.log.Log("WARN", "watch folder does not exist: %s", wp)
			continue
		}
		if err := watchTree(wp, events, &overflow, w.log); err != nil {
			w.log.Log("WARN", "cannot watch %s: %v", wp, err)
			continue
		}
		watching++
	}
	if watching == 0 {
		w.log.Log("ERROR", "no folder to watch")
		return 1
	}
	w.log.Log("INFO", "start: watching %s | disarm=%s | quarantine: %s | results: %s", strings.Join(c.WatchPath, ", "),
		map[bool]string{true: "True", false: "False"}[!c.NoDisarm], c.BackupDir, w.results.file)
	upload := c.MacroUpload
	if upload == "" {
		upload = "off"
	}
	w.log.Log("INFO", "macros: %s (keep %d days / %d MB) | upload: %s", c.MacroDir, c.MacroKeepDays, c.MacroMaxMB, upload)
	if w.criticalOn {
		w.log.Log("INFO", "critical: rules %s -> queue %s", c.CriticalRules, c.CriticalOut)
	} else {
		w.log.Log("INFO", "critical: off")
	}
	p := newPool(w)
	start := runtime.NumCPU() / 2
	p.resize(start)
	if c.MinWorkers == c.MaxWorkers {
		w.log.Log("INFO", "engine: Go watcher, %d parallel scans (fixed)", p.size())
	} else {
		w.log.Log("INFO", "engine: Go watcher, %d parallel scans (automatic %d..%d, CPU target %d%%, high %d%%)",
			p.size(), c.MinWorkers, c.MaxWorkers, c.CpuTarget, c.CpuHigh)
	}
	go w.syncMacros()

	co := newCoordinator(w, p, events, &overflow)
	co.loop(stop)
	w.log.Log("INFO", "stopped")
	return 0
}

func (w *Watcher) work(j job, wk *worker) result {
	res := result{j: j}
	if !j.retry && j.prevHash != "" && isFile(j.path) {
		// the same content was already scanned - skip (Word / Explorer send several Changed in a row; our own
		// disarm changes the file too)
		if h, err := fileSHA256(j.path); err == nil && h == j.prevHash {
			res.unchanged, res.hashAfter = true, h
			return res
		}
	}
	res.rec = w.scanFile(j.path, j.evt, wk)
	if h, err := fileSHA256(j.path); err == nil {
		res.hashAfter = h
	}
	if res.rec != nil && strings.HasPrefix(res.rec.Disarm, "failed:") && fileLocked(j.path) {
		res.locked = true
	}
	return res
}

// ---------------------------------------------------------------- coordinator --

type pend struct {
	t   time.Time // last event
	evt string    // first event type
}

type coordinator struct {
	w        *Watcher
	pool     *pool
	s        *sched
	scale    scaler
	events   <-chan fsEvent
	overflow *atomic.Bool
	rescanCh chan fsEvent
	rescanN  chan int

	pending  map[string]*pend
	queued   map[string]bool // in one of the ready queues
	inflight map[string]bool
	recent   map[string]string    // path -> sha256 after the last scan
	lastScan map[string]time.Time // path -> time of the last scan (cooldown)
	lastKey  map[string]string    // path -> "verdict|summary" of the last Wazuh record
	retry    map[string]*retryItem

	rescanAt, rescanFrom time.Time
	rescanning           bool
	done1m               int
	doneScale            int
	lastQueueWarn        time.Time
	prevReady            int
}

func newCoordinator(w *Watcher, p *pool, events <-chan fsEvent, ov *atomic.Bool) *coordinator {
	co := &coordinator{w: w, pool: p, s: newSched(w.c.WatchPath), events: events, overflow: ov,
		rescanCh: make(chan fsEvent, 1000), rescanN: make(chan int, 1),
		pending: map[string]*pend{}, queued: map[string]bool{}, inflight: map[string]bool{},
		recent: map[string]string{}, lastScan: map[string]time.Time{}, lastKey: map[string]string{},
		retry: map[string]*retryItem{}}
	co.loadRetry()
	return co
}

func (co *coordinator) onEvent(e fsEvent) {
	if co.w.category(e.path) == "" || co.w.excluded(e.path) {
		return
	}
	if p, ok := co.pending[e.path]; ok {
		if e.t.After(p.t) {
			p.t = e.t
		}
		return
	}
	if co.queued[e.path] {
		return // waiting for a worker: it will see the latest content anyway
	}
	co.pending[e.path] = &pend{t: e.t, evt: e.evt}
}

func (co *coordinator) loop(stop <-chan os.Signal) {
	tick := time.NewTicker(250 * time.Millisecond)
	defer tick.Stop()
	minute := time.NewTicker(time.Minute)
	defer minute.Stop()
	scaleT := time.NewTicker(scaleEvery)
	defer scaleT.Stop()
	nextMacroSync := time.Now().Add(time.Hour)
	for {
		var jobs chan<- job
		nj, have := co.s.next()
		if have {
			jobs = co.pool.jobs
		}
		select {
		case <-stop:
			return
		case e := <-co.events:
			co.onEvent(e)
		case e := <-co.rescanCh:
			co.onEvent(e)
		case n := <-co.rescanN:
			co.rescanning = false
			co.w.log.Log("WARN", "rescan after overflow: files changed since %s - %d", co.rescanFrom.Format("15:04:05"), n)
			co.rescanFrom = time.Time{}
		case jobs <- nj:
			co.s.pop()
			delete(co.queued, nj.path)
			co.inflight[nj.path] = true
		case r := <-co.pool.results:
			co.onResult(r)
		case now := <-tick.C:
			co.onTick(now)
			if now.After(nextMacroSync) {
				go co.w.syncMacros()
				nextMacroSync = now.Add(time.Hour)
			}
		case <-minute.C:
			co.reportQueue()
		case now := <-scaleT.C:
			d := co.doneScale
			co.doneScale = 0
			co.autoscale(now, d)
		}
	}
}

func (co *coordinator) onTick(now time.Time) {
	c := co.w.c
	if co.overflow.Swap(false) {
		co.w.log.Log("ERROR", "change notification buffer overflow - some events lost; folders will be rescanned")
		// events were lost -> in a minute walk the folders and take the files changed since then
		if co.rescanFrom.IsZero() {
			co.rescanFrom = now.Add(-time.Minute)
		}
		co.rescanAt = now.Add(time.Minute)
	}
	if !co.rescanAt.IsZero() && now.After(co.rescanAt) && !co.rescanning {
		co.rescanAt = time.Time{}
		co.rescanning = true
		go co.rescan(co.rescanFrom, now.Add(-c.Settle))
	}
	// settled files -> ready queues
	for p, pd := range co.pending {
		if now.Sub(pd.t) < c.Settle || co.inflight[p] {
			continue
		}
		// scanned recently (editing with autosave): wait for the pause, then one scan of the latest version
		if t, ok := co.lastScan[p]; ok && now.Sub(t) < c.RescanCooldown {
			continue
		}
		delete(co.pending, p)
		if !isFile(p) {
			continue
		}
		co.s.add(job{path: p, evt: pd.evt, prevHash: co.recent[p]}, now)
		co.queued[p] = true
	}
	co.retryTick(now)
	if len(co.recent) > 50000 {
		co.recent, co.lastScan, co.lastKey = map[string]string{}, map[string]time.Time{}, map[string]string{}
	}
}

// walk the watched folders and take the files changed since `from` (after lost events)
func (co *coordinator) rescan(from, t time.Time) {
	n := 0
	for _, wp := range co.w.c.WatchPath {
		filepath.WalkDir(wp, func(p string, d fs.DirEntry, err error) error {
			if err != nil || d.IsDir() {
				return nil
			}
			if co.w.category(p) == "" || co.w.excluded(p) {
				return nil
			}
			if inf, err := d.Info(); err == nil && !inf.ModTime().Before(from) {
				co.rescanCh <- fsEvent{path: p, evt: "Rescan", t: t}
				n++
			}
			return nil
		})
	}
	co.rescanN <- n
}

func (co *coordinator) onResult(r result) {
	p := r.j.path
	delete(co.inflight, p)
	co.done1m++
	co.doneScale++
	if r.unchanged {
		return
	}
	now := time.Now()
	co.lastScan[p] = now
	if r.hashAfter != "" {
		co.recent[p] = r.hashAfter
	} else {
		delete(co.recent, p)
	}
	if r.rec != nil {
		co.write(r.rec, p)
	}
	failed := r.rec != nil && strings.HasPrefix(r.rec.Disarm, "failed:")
	switch r.j.evt {
	case "DisarmRetry":
		it := co.retry[p]
		if it == nil {
			return
		}
		it.inFlight = false
		if failed && r.locked {
			it.next = now.Add(co.retryStep(it, now))
			return
		}
		if failed {
			co.w.log.Log("ERROR", "disarm failed (file not locked): %s - %s", p, r.rec.Disarm)
		}
		co.removeRetry(p)
	case "DisarmPending":
		if it := co.retry[p]; it != nil {
			it.inFlight = false
		}
	default:
		// disarm failed because the file is open (Word) - retry when it is released;
		// a new scan without a failed disarm removes the file from the retry list
		if failed && r.locked {
			co.addRetry(p)
		} else if r.rec != nil {
			co.removeRetry(p)
		}
	}
}

// The same result as last time for this path (the user saves the document, the content changed, but the verdict
// and findings did not) - not written for Wazuh, only to the local log. HIGH is always written.
func (co *coordinator) write(r *Record, p string) {
	key := r.Verdict + "|" + r.Summary
	repeat := r.Verdict != "HIGH" && co.lastKey[p] == key
	if !repeat {
		b, err := json.Marshal(r)
		if err == nil {
			err = co.w.results.append(append(b, '\n'))
		}
		if err != nil {
			co.w.log.Log("ERROR", "cannot write the result of %s: %v", p, err)
		}
		co.lastKey[p] = key
	}
	co.w.logScan(r, repeat)
}

func (co *coordinator) reportQueue() {
	waiting, ready, busy := len(co.pending), co.s.len(), len(co.inflight)
	done := co.done1m
	co.done1m = 0
	if waiting+ready+busy == 0 {
		co.prevReady = 0
		return
	}
	co.w.log.Log("INFO", "queue: waiting %d, ready %d (single files %d, bulk %d from %d users), scanning %d of %d workers, done in the last minute %d",
		waiting, ready, len(co.s.fresh)+len(co.s.retry), co.s.nBulk, len(co.s.order), busy, co.pool.size(), done)
	// a queue that keeps growing: files reach the disk faster than they are scanned
	if ready > 1000 && ready > co.prevReady && time.Since(co.lastQueueWarn) > 10*time.Minute {
		co.w.log.Log("WARN", "scan backlog: %d files wait for a scan and the queue grows (%d scans / min with %d workers)",
			ready, done, co.pool.size())
		co.lastQueueWarn = time.Now()
	}
	co.prevReady = ready
}

// ---------------------------------------------------------------- disarm retry --
// A locked file (Word holds it) cannot be disarmed now. No end date: every 30 s for the first
// -DisarmRetryMinutes, then every 5 min. After -DisarmNoticeHours - one Wazuh record (DisarmPending): the SOC
// has to handle it manually. The list is kept in retry.json: survives a restart and a reboot.

func (co *coordinator) retryStep(it *retryItem, now time.Time) time.Duration {
	if now.Sub(it.since) < time.Duration(co.w.c.DisarmRetryMinutes)*time.Minute {
		return 30 * time.Second
	}
	return 5 * time.Minute
}

func (co *coordinator) retryTick(now time.Time) {
	for p, it := range co.retry {
		if it.inFlight || now.Before(it.next) || co.inflight[p] || co.queued[p] {
			continue
		}
		if !isFile(p) {
			co.removeRetry(p)
			continue
		}
		step := co.retryStep(it, now)
		if fileLocked(p) {
			it.next = now.Add(step)
			if !it.noticed && now.Sub(it.since).Hours() >= co.w.c.DisarmNoticeHours {
				it.noticed = true
				co.saveRetry()
				co.w.log.Log("ERROR", "disarm not done in %g h - the file is still open: %s", co.w.c.DisarmNoticeHours, p)
				it.inFlight = true
				co.s.addRetry(job{path: p, evt: "DisarmPending", retry: true}) // HIGH + failed:replace
				co.queued[p] = true
			}
			continue
		}
		it.inFlight = true
		co.s.addRetry(job{path: p, evt: "DisarmRetry", retry: true})
		co.queued[p] = true
	}
}

func (co *coordinator) addRetry(p string) {
	if it, ok := co.retry[p]; ok {
		it.next = time.Now().Add(30 * time.Second)
	} else {
		co.retry[p] = &retryItem{next: time.Now().Add(30 * time.Second), since: time.Now()}
		co.w.log.Log("WARN", "file is open in another program - disarm will be retried as soon as it is closed: %s", p)
	}
	co.saveRetry()
}

func (co *coordinator) removeRetry(p string) {
	if _, ok := co.retry[p]; ok {
		delete(co.retry, p)
		co.saveRetry()
	}
}

type retryJSON struct {
	Path    string `json:"path"`
	Since   string `json:"since"`
	Noticed bool   `json:"noticed"`
}

const dotnetRoundTrip = "2006-01-02T15:04:05.0000000-07:00" // .NET "o": the PowerShell watcher reads it too

func (co *coordinator) saveRetry() {
	items := []retryJSON{}
	for p, it := range co.retry {
		items = append(items, retryJSON{p, it.since.Format(dotnetRoundTrip), it.noticed})
	}
	b, _ := json.Marshal(items)
	tmp := co.w.retryFile + ".tmp"
	if os.WriteFile(tmp, b, 0o644) == nil {
		os.Rename(tmp, co.w.retryFile)
	}
}

// unfinished disarms from the previous run (after a reboot Word no longer holds the file)
func (co *coordinator) loadRetry() {
	b, err := os.ReadFile(co.w.retryFile)
	if err != nil {
		return
	}
	var items []retryJSON
	if err := json.Unmarshal(trimBOM(b), &items); err != nil {
		co.w.log.Log("ERROR", "could not read %s: %v", co.w.retryFile, err)
		return
	}
	for _, it := range items {
		if it.Path == "" || !isFile(it.Path) {
			continue
		}
		since, err := time.Parse(time.RFC3339Nano, it.Since)
		if err != nil {
			since = time.Now()
		}
		co.retry[it.Path] = &retryItem{next: time.Now(), since: since, noticed: it.Noticed}
	}
	if len(co.retry) > 0 {
		co.w.log.Log("WARN", "unfinished disarm from the previous run: %d file(s)", len(co.retry))
	}
	co.saveRetry()
}

func execCmd(name string, args ...string) *exec.Cmd {
	cmd := exec.Command(name, args...)
	hideWindow(cmd)
	return cmd
}

func trimBOM(b []byte) []byte {
	if len(b) >= 3 && b[0] == 0xEF && b[1] == 0xBB && b[2] == 0xBF {
		return b[3:]
	}
	return b
}

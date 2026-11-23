package main

// Скан на вимогу і скан знімних носіїв. Watcher бачить нові й змінені файли; тут — файли, що вже лежать на диску:
//
//	docs   скан документів: лише документи (docx, xlsm, pdf, rtf...) на вибраних (без вибору — усіх) локальних дисках,
//	       крім системних і програмних тек (drives.Protected) і виключень DocScan. Повного скану всіх файлів НЕМАЄ навмисно:
//	       на перевірці Mac він прибрав у карантин zip-шаблони з теки встановленої IDE — так само зламав би
//	       програми в C:\Program Files.
//	path   заданий шлях: тека, файл, знімний або не системний диск (D:\, E:\); цілий системний диск (C:\) — ні,
//	       лише docs
//	usb    знімний носій: запускається сам, щойно вставили флешку / USB-диск / SD-картку (settings.json usb_scan),
//	       або вручну з вебу
//
// Дія скану (веб / -ScanDetect / -ScanDelete): лише повідомити | лікувати (знешкодити документ, інше — у карантин,
// звідки можна повернути) | видалити (HIGH-файл видаляється БЕЗ копії; MEDIUM — лише повідомлення).
//
// Захист програм (drives.Protected): файл у системній / програмній теці (Windows, Program Files, ProgramData\Microsoft,
// AppData\Local\Programs; на Mac — /Applications, /System, Library, *.app) будь-який скан лише повідомляє,
// навіть у повному режимі: знешкоджений шаблон чи надбудова Office зламали б встановлену програму.
//
// Хто запускає: веб-інтерфейс або командний рядок (docscan-watcher -ScanDocs / -ScanPath E:\) кладуть файл-запит
// <DataDir>\scan\request-<id>.json, служба підхоплює його за 2 с. Пише результати лише служба — двох записувачів
// docscan-results.json не буває. Зупинка: файл cancel-<id> (або cancel-all).
//
// Порядок: файли скану йдуть ПІСЛЯ всіх живих файлів користувачів (sched.go: scanHi — usb і path, scanLo — docs),
// тож свіже завантаження не чекає на скан дисків. Обхід тримає в черзі не більше scanQueueMax файлів.
//
// Кеш (scan\cache.json): sha256 файлів, що вийшли чистими (INFO, без помилок) з ЦИМИ правилами — повторно не
// скануються (повторний скан диска, та сама флешка ще раз). Нові правила -> кеш порожній. Списки організації
// діють завжди: вони перевіряються до кешу.
//
// Записи для Wazuh: лише HIGH / MEDIUM (події DocsScan, PathScan, USBScan; поле scan — id скану). Чисті файли
// не пишуться (скан дисків — десятки тисяч файлів), лише рахуються; ERROR / SKIPPED — у watcher.log.
// Хід і підсумок — scan\status.json (поточні) і scan\history.json (останні 50); їх читає веб.
//
// Носій лише для читання (захищена від запису флешка, CD): знешкодити неможливо — лише повідомлення
// (disarm detect-only, у підсумку причина).

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"docscan/watcher/drives"
)

const (
	scanQueueMax   = 2000 // файлів скану в черзі одночасно (решту обхід тримає, доки черга не спаде)
	scanMaxActive  = 4    // сканів одночасно
	scanHistoryMax = 50
	scanHitsMax    = 100 // шляхів зі знахідками в підсумку
	scanCacheMax   = 500000
)

var drivePollEvery = 5 * time.Second // тести — коротше

var scanEvent = map[string]string{"docs": "DocsScan", "path": "PathScan", "usb": "USBScan"}

// scanReq — файл-запит request-<id>.json (пишуть веб і docscan-watcher -ScanDocs / -ScanPath).
type scanReq struct {
	ID     string   `json:"id"`
	Kind   string   `json:"kind"`  // docs | path | usb
	Paths  []string `json:"paths"` // docs — порожньо (усі локальні диски)
	By     string   `json:"by"`
	Detect bool     `json:"detect,omitempty"` // лише повідомлення, без знешкодження
	Delete bool     `json:"delete,omitempty"` // загрози (HIGH) видалити без копії; не в програмних теках
}

// scanRun — один скан (у status.json / history.json).
type scanRun struct {
	ID       string   `json:"id"`
	Kind     string   `json:"kind"`
	Paths    []string `json:"paths"`
	By       string   `json:"by"`
	Detect   bool     `json:"detect"`
	Delete   bool     `json:"delete,omitempty"`
	Deleted  int      `json:"deleted,omitempty"` // видалено файлів (режим Delete)
	Note     string   `json:"note,omitempty"`
	State    string   `json:"state"` // running | done | cancelled | failed
	Started  string   `json:"started"`
	Finished string   `json:"finished,omitempty"`
	Seconds  int      `json:"seconds"`
	Found    int64    `json:"found"`   // файлів знайдено обходом
	Scanned  int      `json:"scanned"` // проскановано
	Cached   int      `json:"cached"`  // пропущено: вже перевірені цими правилами
	Hits     int      `json:"hits"`    // HIGH / MEDIUM
	Errors   int      `json:"errors"`
	Skipped  int      `json:"skipped"` // зник, завеликий, уже в черзі watcher-а
	Walking  bool     `json:"walking"` // обхід ще триває
	Current  string   `json:"current,omitempty"`
	HitFiles []string `json:"hit_files,omitempty"`

	start       time.Time
	found       *atomic.Int64 // обхід (своя горутина)
	stop        *atomic.Bool
	walked      bool
	outstanding int // у черзі або в роботі
	drive       string
}

func (r *scanRun) snapshot() scanRun {
	s := scanRun{ID: r.ID, Kind: r.Kind, Paths: r.Paths, By: r.By, Detect: r.Detect, Delete: r.Delete, Deleted: r.Deleted, Note: r.Note, State: r.State,
		Started: r.Started, Finished: r.Finished, Scanned: r.Scanned, Cached: r.Cached, Hits: r.Hits, Errors: r.Errors,
		Skipped: r.Skipped, Walking: !r.walked, Current: r.Current, HitFiles: r.HitFiles}
	if r.found != nil {
		s.Found = r.found.Load()
	}
	s.Seconds = int(time.Since(r.start).Seconds())
	if r.Finished != "" {
		if t, err := time.Parse(time.RFC3339, r.Finished); err == nil {
			s.Seconds = int(t.Sub(r.start).Seconds())
		}
		s.Walking = false
	}
	return s
}

// ScanStatus — scan\status.json.
type ScanStatus struct {
	Updated string    `json:"updated"`
	USBMode string    `json:"usb_mode"` // off | detect | full — що зараз діє для нових носіїв
	Active  []scanRun `json:"active"`
	Queue   int       `json:"queue"` // файлів скану в черзі
}

func scanDir(c *Config) string { return filepath.Join(filepath.Dir(c.OutDir), "scan") }

// NewScanID — id скану: час + вид (сортується за часом).
func NewScanID(kind string) string {
	return time.Now().Format("20060102-150405.000") + "-" + kind
}

// WriteScanRequest — покласти запит (веб, командний рядок). Повертає id.
func WriteScanRequest(dir string, q scanReq) (string, error) {
	if q.ID == "" {
		q.ID = NewScanID(q.Kind)
	}
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return "", err
	}
	b, _ := json.MarshalIndent(q, "", "  ")
	tmp := filepath.Join(dir, "request-"+q.ID+".tmp")
	if err := os.WriteFile(tmp, b, 0o644); err != nil {
		return "", err
	}
	return q.ID, os.Rename(tmp, filepath.Join(dir, "request-"+q.ID+".json"))
}

var scanIDRe = regexp.MustCompile(`^[0-9A-Za-z.\-]{1,64}$`)

// ---------------------------------------------------------------- кеш

type scanCache struct {
	mu    sync.Mutex
	file  string
	rules string
	set   map[string]struct{}
	dirty bool
}

type cacheJSON struct {
	Rules string   `json:"rules"`
	SHA   []string `json:"sha256"`
}

func newScanCache(file, rules string) *scanCache {
	c := &scanCache{file: file, rules: rules, set: map[string]struct{}{}}
	if b, err := os.ReadFile(file); err == nil {
		var j cacheJSON
		if json.Unmarshal(b, &j) == nil && j.Rules == rules && rules != "" {
			for _, s := range j.SHA {
				c.set[s] = struct{}{}
			}
		}
	}
	return c
}

func (c *scanCache) has(sha string) bool {
	if c == nil || sha == "" {
		return false
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	_, ok := c.set[sha]
	return ok
}

func (c *scanCache) add(sha string) {
	if c == nil || sha == "" || c.rules == "" {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if len(c.set) >= scanCacheMax {
		c.set = map[string]struct{}{}
	}
	if _, ok := c.set[sha]; !ok {
		c.set[sha] = struct{}{}
		c.dirty = true
	}
}

func (c *scanCache) save() {
	if c == nil {
		return
	}
	c.mu.Lock()
	if !c.dirty {
		c.mu.Unlock()
		return
	}
	j := cacheJSON{Rules: c.rules, SHA: make([]string, 0, len(c.set))}
	for s := range c.set {
		j.SHA = append(j.SHA, s)
	}
	c.dirty = false
	c.mu.Unlock()
	b, _ := json.Marshal(j)
	os.MkdirAll(filepath.Dir(c.file), 0o755)
	if os.WriteFile(c.file+".tmp", b, 0o644) == nil {
		os.Rename(c.file+".tmp", c.file)
	}
}

func (c *scanCache) size() int {
	if c == nil {
		return 0
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	return len(c.set)
}

// rulesKey — відбиток правил, з якими працює watcher (кеш дійсний лише з ними).
func rulesKey(files ...string) string {
	h := sha256.New()
	n := 0
	for _, f := range files {
		fh, err := os.Open(f)
		if err != nil {
			continue
		}
		io.Copy(h, fh)
		fh.Close()
		n++
	}
	if n == 0 {
		return ""
	}
	return hex.EncodeToString(h.Sum(nil))[:32]
}

// ---------------------------------------------------------------- координатор

type scanState struct {
	dir        string
	runs       map[string]*scanRun
	order      []string // id активних за часом
	ch         chan job
	drivesCh   chan []drives.Drive
	seenDrives map[string]bool
	drivesInit bool
	nextCheck  time.Time
	nextStatus time.Time
	nextSave   time.Time
	dirty      bool
	usbMode    string // у status.json востаннє
	// файл уже в черзі або в роботі (інший скан тих самих файлів, живий файл): скан чекає на той результат
	// і рахує його в себе, а не пропускає (два скани однієї флешки — обидва з повним підсумком)
	waiters map[string][]string // шлях -> id сканів
}

func (co *coordinator) initScan() {
	co.sc = scanState{dir: scanDir(co.w.c), runs: map[string]*scanRun{}, ch: make(chan job, 256),
		drivesCh: make(chan []drives.Drive, 1), seenDrives: map[string]bool{}, dirty: true, waiters: map[string][]string{}}
	os.MkdirAll(co.sc.dir, 0o755)
	// незакінчені скани попередньої роботи служби (перезапуск після оновлення правил) — в історію як перервані
	if st := readScanStatus(co.sc.dir); st != nil {
		for _, r := range st.Active {
			r.State, r.Finished = "cancelled", time.Now().Format(time.RFC3339)
			r.Note = joinNote(r.Note, "служба DocScanWatcher перезапустилась - скан перервано, запустіть ще раз")
			appendScanHistory(co.sc.dir, r)
		}
	}
	go pollDrives(co.sc.drivesCh)
}

func pollDrives(out chan<- []drives.Drive) {
	for {
		d := drives.List()
		select {
		case out <- d:
		default: // координатор ще не забрав попередній список
		}
		time.Sleep(drivePollEvery)
	}
}

func joinNote(a, b string) string {
	if a == "" {
		return b
	}
	return a + "; " + b
}

// usbMode — що робити з новим знімним носієм: off | detect | full (settings.json usb_scan; без нього — як режим).
func (w *Watcher) usbMode() string {
	m := ""
	if w.set != nil {
		w.set.mu.Lock()
		m = w.set.cur.USBScan
		w.set.mu.Unlock()
	}
	switch m {
	case "off", "detect":
		return m
	case "full":
		if w.noDisarm() {
			return "detect" // увесь DocScan у режимі лише повідомлень
		}
		return "full"
	}
	if w.noDisarm() {
		return "detect"
	}
	return "full"
}

// scanTick — з onTick: запити, зупинки, стан.
func (co *coordinator) scanTick(now time.Time) {
	sc := &co.sc
	if now.After(sc.nextCheck) {
		sc.nextCheck = now.Add(2 * time.Second)
		co.scanRequests()
	}
	if now.After(sc.nextStatus) && (sc.dirty || len(sc.runs) > 0 || sc.usbMode != co.w.usbMode()) {
		sc.nextStatus = now.Add(2 * time.Second)
		sc.dirty = false
		sc.usbMode = co.w.usbMode()
		co.writeScanStatus()
	}
	if now.After(sc.nextSave) {
		sc.nextSave = now.Add(5 * time.Minute)
		co.w.cache.save()
	}
}

func (co *coordinator) scanRequests() {
	ents, err := os.ReadDir(co.sc.dir)
	if err != nil {
		return
	}
	for _, e := range ents {
		n := e.Name()
		switch {
		case strings.HasPrefix(n, "request-") && strings.HasSuffix(n, ".json"):
			f := filepath.Join(co.sc.dir, n)
			b, err := os.ReadFile(f)
			os.Remove(f)
			var q scanReq
			if err == nil {
				err = json.Unmarshal(trimBOM(b), &q)
			}
			if err != nil {
				co.w.log.Log("ERROR", "scan: bad request %s: %v", n, err)
				continue
			}
			co.startScan(q, "")
		case n == "cancel-all":
			os.Remove(filepath.Join(co.sc.dir, n))
			for _, id := range append([]string(nil), co.sc.order...) {
				co.cancelScan(id, "зупинено вручну")
			}
		case strings.HasPrefix(n, "cancel-"):
			os.Remove(filepath.Join(co.sc.dir, n))
			co.cancelScan(strings.TrimPrefix(n, "cancel-"), "зупинено вручну")
		}
	}
}

// startScan — перевірити запит і почати обхід. drive — ключ носія для авто-скану USB.
func (co *coordinator) startScan(q scanReq, drive string) {
	w := co.w
	if q.ID == "" || !scanIDRe.MatchString(q.ID) {
		q.ID = NewScanID(q.Kind)
	}
	if scanEvent[q.Kind] == "" {
		w.log.Log("ERROR", "scan: unknown kind %q (docs | path | usb)", q.Kind)
		return
	}
	if q.By == "" {
		q.By = "-"
	}
	r := &scanRun{ID: q.ID, Kind: q.Kind, By: q.By, Detect: q.Detect || w.noDisarm(), State: "running",
		Delete:  q.Delete && !q.Detect && !w.noDisarm(),
		Started: time.Now().Format(time.RFC3339), start: time.Now(), drive: drive, found: new(atomic.Int64), stop: new(atomic.Bool)}
	all := drives.List()
	if q.Kind == "docs" { // вибрані локальні диски (веб), без вибору — усі; інше тут не сканується
		var roots []string
		for _, p := range q.Paths {
			if drives.IsRoot(p, all, func(d drives.Drive) bool { return d.Kind == "fixed" }) {
				roots = append(roots, p)
			} else {
				r.Note = joinNote(r.Note, p+" - не локальний диск, пропущено")
			}
		}
		if len(q.Paths) == 0 {
			roots = drives.Fixed(all)
		}
		q.Paths = roots
	}
	for _, p := range q.Paths {
		p = strings.TrimSpace(p)
		if p == "" {
			continue
		}
		if len(p) == 2 && p[1] == ':' {
			p += `\`
		}
		if _, err := os.Stat(p); err != nil {
			r.Note = joinNote(r.Note, "немає доступу: "+p)
			continue
		}
		if q.Kind == "path" && drives.IsRoot(p, all, func(d drives.Drive) bool { return d.System }) {
			r.Note = joinNote(r.Note, p+" - цілий системний диск не сканується, лише «Скан документів» (теки на ньому - можна)")
			continue
		}
		if drives.Protected(p) {
			r.Note = joinNote(r.Note, p+" - системна / програмна тека: лише повідомлення")
		}
		for _, d := range all { // лише читання — знешкодити неможливо
			if d.ReadOnly && hasPrefixFold(p, d.Root) {
				r.Detect, r.Delete = true, false
				r.Note = joinNote(r.Note, d.Root+" лише для читання - тільки повідомлення, без знешкодження")
			}
		}
		r.Paths = append(r.Paths, p)
	}
	if len(r.Paths) == 0 {
		r.State, r.Finished = "failed", time.Now().Format(time.RFC3339)
		r.Note = joinNote(r.Note, "немає що сканувати")
		w.log.Log("ERROR", "scan %s (%s): nothing to scan - %s", r.ID, r.Kind, r.Note)
		appendScanHistory(co.sc.dir, r.snapshot())
		co.sc.dirty = true
		return
	}
	for _, id := range co.sc.order {
		o := co.sc.runs[id]
		if o.Kind == r.Kind && strings.Join(o.Paths, "|") == strings.Join(r.Paths, "|") {
			w.log.Log("INFO", "scan: %s %s is already running (%s)", r.Kind, strings.Join(r.Paths, ", "), o.ID)
			return
		}
	}
	if len(co.sc.order) >= scanMaxActive {
		r.State, r.Finished = "failed", time.Now().Format(time.RFC3339)
		r.Note = joinNote(r.Note, fmt.Sprintf("вже йде %d скани - дочекайтесь або зупиніть один", scanMaxActive))
		w.log.Log("WARN", "scan %s: %s", r.ID, r.Note)
		appendScanHistory(co.sc.dir, r.snapshot())
		co.sc.dirty = true
		return
	}
	co.sc.runs[r.ID] = r
	co.sc.order = append(co.sc.order, r.ID)
	co.sc.dirty = true
	mode := map[bool]string{true: "detect-only", false: "full"}[r.Detect]
	if r.Delete {
		mode = "delete threats"
	}
	w.log.Log("INFO", "scan %s started: %s %s (by %s, %s)%s", r.ID, r.Kind, strings.Join(r.Paths, ", "), r.By, mode,
		map[bool]string{true: " - " + r.Note, false: ""}[r.Note != ""])
	go co.walkScan(r)
}

// walkScan — обхід (своя горутина): файли — у sc.ch (координатор бере їх, доки черга скану < scanQueueMax).
func (co *coordinator) walkScan(r *scanRun) {
	w := co.w
	evt := scanEvent[r.Kind]
	docs := r.Kind == "docs"
	send := func(p string) {
		r.found.Add(1)
		prot := drives.Protected(p)
		// видалення: воркер лише сканує (без знешкодження), HIGH видаляє координатор (scanResult)
		co.sc.ch <- job{path: p, evt: evt, scan: r.ID, detect: r.Detect || r.Delete || prot, del: r.Delete && !prot}
	}
	for _, root := range r.Paths {
		if r.stop.Load() {
			break
		}
		st, err := os.Stat(root)
		if err != nil {
			continue
		}
		if !st.IsDir() { // один файл — будь-яке розширення
			send(root)
			continue
		}
		filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
			if r.stop.Load() {
				return fs.SkipAll
			}
			if err != nil {
				return nil // тека без доступу — далі
			}
			if d.IsDir() {
				if p != root && (w.excluded(p+string(filepath.Separator)) || docs && drives.Protected(p)) {
					return fs.SkipDir
				}
				return nil
			}
			cat := w.category(p)
			if !d.Type().IsRegular() || cat == "" || docs && cat != "document" || w.excluded(p) {
				return nil
			}
			send(p)
			return nil
		})
	}
	co.sc.ch <- job{scan: r.ID} // кінець обходу — тим самим каналом, тобто після всіх його файлів
}

// scanJob — файл від обходу: у чергу скану (або пропустити).
func (co *coordinator) scanJob(j job, now time.Time) {
	if j.path == "" {
		co.scanWalked(j.scan)
		return
	}
	r := co.sc.runs[j.scan]
	if r == nil || r.stop.Load() {
		return
	}
	r.Current = j.path
	if co.queued[j.path] || co.inflight[j.path] { // його вже сканують — дочекатися результату (scanWaiters)
		r.outstanding++
		co.sc.waiters[j.path] = append(co.sc.waiters[j.path], r.ID)
		return
	}
	r.outstanding++
	co.queued[j.path] = true
	co.s.addScan(j, r.Kind == "docs")
}

// scanResult — результат файлу скану: рахунки; true — писати запис для Wazuh.
func (co *coordinator) scanResult(res result) bool {
	r := co.sc.runs[res.j.scan]
	rec := res.rec
	write := rec != nil && (rec.Verdict == "HIGH" || rec.Verdict == "MEDIUM")
	if res.j.del && rec != nil && rec.Verdict == "HIGH" && (r == nil || !r.stop.Load()) {
		if err := os.Remove(res.j.path); err != nil && !os.IsNotExist(err) {
			rec.Disarm = "failed:delete"
			rec.Errors = append(rec.Errors, "delete failed: "+err.Error())
		} else {
			rec.Disarm = "deleted"
			if r != nil {
				r.Deleted++
			}
		}
	}
	if r != nil {
		r.outstanding--
		co.sc.dirty = true
		switch {
		case rec == nil:
			r.Skipped++
		case rec.Verdict == "CACHED":
			r.Cached++
		case write:
			r.Hits++
			r.Scanned++
			if len(r.HitFiles) < scanHitsMax {
				r.HitFiles = append(r.HitFiles, rec.Verdict+" "+rec.DocFile.Path)
			}
		case rec.Verdict == "ERROR":
			r.Errors++
		case rec.Verdict == "SKIPPED":
			r.Skipped++
		default:
			r.Scanned++
		}
		co.scanMaybeDone(r)
	}
	if rec != nil {
		switch {
		case rec.Verdict == "INFO" && len(rec.Errors) == 0 && rec.List == nil:
			co.w.cache.add(rec.DocFile.Sha256)
		case rec.Verdict == "ERROR" || rec.Verdict == "SKIPPED":
			co.w.logScan(rec, false)
		}
	}
	return write
}

// scanWaiters — результат файлу прийшов: врахувати його і в сканах, що чекали на цей файл (без другого запису).
func (co *coordinator) scanWaiters(res result) {
	ws := co.sc.waiters[res.j.path]
	if len(ws) == 0 {
		return
	}
	delete(co.sc.waiters, res.j.path)
	for _, id := range ws {
		if id == res.j.scan {
			continue
		}
		w := res
		w.j.scan, w.j.del = id, false
		co.scanResult(w)
	}
}

func (co *coordinator) scanWalked(id string) {
	if r := co.sc.runs[id]; r != nil {
		r.walked = true
		co.scanMaybeDone(r)
	}
}

func (co *coordinator) scanMaybeDone(r *scanRun) {
	if !r.walked || r.outstanding > 0 {
		return
	}
	if r.State == "running" {
		r.State = "done"
	}
	co.finishScan(r)
}

func (co *coordinator) cancelScan(id, why string) {
	r := co.sc.runs[id]
	if r == nil || r.State != "running" {
		return
	}
	r.stop.Store(true)
	r.State = "cancelled"
	r.Note = joinNote(r.Note, why)
	dropped := co.s.dropScan(id)
	for _, p := range dropped {
		if co.handOver(p) {
			continue // файл тепер сканується для скану, що на нього чекав
		}
		delete(co.queued, p)
	}
	r.outstanding -= len(dropped)
	co.w.log.Log("INFO", "scan %s: %s", id, why)
	co.sc.dirty = true
	co.scanMaybeDone(r) // файли в роботі ще повернуться; обхід ще має повідомити, що закінчив
}

// handOver — скан зупинили, його файл p прибрано з черги: якщо на p чекає інший скан, файл стає його.
func (co *coordinator) handOver(p string) bool {
	ws := co.sc.waiters[p]
	for i, id := range ws {
		o := co.sc.runs[id]
		if o == nil || o.State != "running" {
			continue
		}
		if rest := ws[i+1:]; len(rest) > 0 {
			co.sc.waiters[p] = rest
		} else {
			delete(co.sc.waiters, p)
		}
		prot := drives.Protected(p)
		co.s.addScan(job{path: p, evt: scanEvent[o.Kind], scan: o.ID, detect: o.Detect || o.Delete || prot, del: o.Delete && !prot}, o.Kind == "docs")
		return true
	}
	delete(co.sc.waiters, p)
	return false
}

func (co *coordinator) finishScan(r *scanRun) {
	if _, ok := co.sc.runs[r.ID]; !ok {
		return
	}
	r.Finished = time.Now().Format(time.RFC3339)
	r.Current = ""
	delete(co.sc.runs, r.ID)
	for i, id := range co.sc.order {
		if id == r.ID {
			co.sc.order = append(co.sc.order[:i], co.sc.order[i+1:]...)
			break
		}
	}
	s := r.snapshot()
	lvl := "INFO"
	if s.Hits > 0 {
		lvl = "WARN"
	}
	co.w.log.Log(lvl, "scan %s %s: %s %s - found %d, scanned %d, already checked %d, threats %d, errors %d, skipped %d, %ds",
		r.ID, r.State, r.Kind, strings.Join(r.Paths, ", "), s.Found, s.Scanned, s.Cached, s.Hits, s.Errors, s.Skipped, s.Seconds)
	appendScanHistory(co.sc.dir, s)
	co.w.cache.save()
	co.sc.dirty = true
}

// onDrives — новий список дисків: новий знімний носій — авто-скан, вилучений — зупинити його скан.
func (co *coordinator) onDrives(list []drives.Drive) {
	sc := &co.sc
	cur := map[string]drives.Drive{}
	for _, d := range list {
		if d.Removable() {
			cur[d.Key()] = d
		}
	}
	if !sc.drivesInit { // носії, що вже були під час старту служби, не скануються самі (перезапуск після оновлення)
		sc.drivesInit = true
		for k := range cur {
			sc.seenDrives[k] = true
		}
		return
	}
	for k := range sc.seenDrives {
		if _, ok := cur[k]; !ok {
			delete(sc.seenDrives, k)
			for _, id := range append([]string(nil), sc.order...) {
				if r := sc.runs[id]; r != nil && r.drive == k {
					co.cancelScan(id, "носій вилучено")
				}
			}
		}
	}
	keys := make([]string, 0, len(cur))
	for k := range cur {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		if sc.seenDrives[k] {
			continue
		}
		sc.seenDrives[k] = true
		d := cur[k]
		mode := co.w.usbMode()
		if mode == "off" {
			co.w.log.Log("INFO", "usb: %s connected - automatic scan is off (settings.json usb_scan)", d.Name())
			continue
		}
		co.w.log.Log("INFO", "usb: %s connected - scanning (%s)", d.Name(), mode)
		co.startScan(scanReq{Kind: "usb", Paths: []string{d.Root}, By: "auto", Detect: mode == "detect"}, k)
	}
}

func (co *coordinator) writeScanStatus() {
	st := ScanStatus{Updated: time.Now().Format(time.RFC3339), USBMode: co.w.usbMode(), Active: []scanRun{}, Queue: co.s.scanLen()}
	for _, id := range co.sc.order {
		st.Active = append(st.Active, co.sc.runs[id].snapshot())
	}
	b, _ := json.MarshalIndent(st, "", "  ")
	f := filepath.Join(co.sc.dir, "status.json")
	if os.WriteFile(f+".tmp", b, 0o644) == nil {
		os.Rename(f+".tmp", f)
	}
}

func readScanStatus(dir string) *ScanStatus {
	b, err := os.ReadFile(filepath.Join(dir, "status.json"))
	if err != nil {
		return nil
	}
	var st ScanStatus
	if json.Unmarshal(b, &st) != nil {
		return nil
	}
	return &st
}

func readScanHistory(dir string) []scanRun {
	b, err := os.ReadFile(filepath.Join(dir, "history.json"))
	if err != nil {
		return nil
	}
	var h []scanRun
	json.Unmarshal(b, &h)
	return h
}

func appendScanHistory(dir string, r scanRun) {
	h := append([]scanRun{r}, readScanHistory(dir)...)
	if len(h) > scanHistoryMax {
		h = h[:scanHistoryMax]
	}
	b, _ := json.MarshalIndent(h, "", "  ")
	f := filepath.Join(dir, "history.json")
	if os.WriteFile(f+".tmp", b, 0o644) == nil {
		os.Rename(f+".tmp", f)
	}
}

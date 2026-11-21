// docscan-updater — служба оновлення DocScan (DocScanUpdater). Як оновлюватися, каже <DataDir>\update\updater.json
// (config.go): github / mirror — сама перевіряє джерело раз на check_every_hours; marker — чекає, поки агент
// (Wazuh чи будь-який інший) запише маркер. Ставить лише релізи з дійсним підписом CI (watcher-go/manifest),
// ніколи — старішу версію. Самі кроки — update.go.
//
//	docscan-updater.exe [-DataDir C:\ProgramData\DocScan] [-InstallDir <тека над updater\>] [-Config <updater.json>]
//	docscan-updater.exe -Once      # одна перевірка зараз (і завершення оновлення, що триває) — вручну / для тесту
//	docscan-updater.exe -InstallRules <DocScan-rules-bundle.zip | тека>   # install.ps1 -Rules: перевірити й поставити правила
//	docscan-updater.exe -CheckList / -NewListKey / -SignList   # списки організації (listscli.go)
package main

import (
	"flag"
	"fmt"
	"math/rand/v2"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"docscan/watcher/manifest"
	"docscan/watcher/winsvc"
)

// ServiceName — служба Windows updater-а; у списку служб — "DocScan Updater".
const ServiceName = "DocScanUpdater"

func main() {
	// list administration: -CheckList, -NewListKey, -SignList (listscli.go) — not the service
	if code, ok := listsCLI(os.Args); ok {
		os.Exit(code)
	}
	exe, _ := os.Executable()
	dataDir := flag.String("DataDir", `C:\ProgramData\DocScan`, "DocScan data folder")
	installDir := flag.String("InstallDir", filepath.Dir(filepath.Dir(exe)), "DocScan program folder (VERSION.txt)")
	cfgPath := flag.String("Config", "", "updater.json (default <DataDir>\\update\\updater.json)")
	once := flag.Bool("Once", false, "check once now and exit")
	installRules := flag.String("InstallRules", "", "verify and install a rules bundle (DocScan-rules-bundle.zip or a folder) into <InstallDir>\\rules, then exit")
	flag.Parse()
	if *cfgPath == "" {
		*cfgPath = filepath.Join(*dataDir, "update", "updater.json")
	}
	host, _ := os.Hostname()
	u := &Updater{dataDir: *dataDir, installDir: *installDir, host: host,
		log: &logger{file: filepath.Join(*dataDir, "results", "updater.log")}, lastErr: map[string]time.Time{},
		http: &http.Client{Timeout: 30 * time.Minute}, svc: newServices(), poll: 3 * time.Second}
	// install.ps1 -Reuse бере параметри з <DataDir>\install.json: теки — ті самі, що в цієї служби
	u.launch = func(pkgDir, resultFile, logFile string) error {
		return launchInstaller(pkgDir, resultFile, logFile, "-InstallDir", u.installDir, "-DataDir", u.dataDir)
	}
	if *installRules != "" { // install.ps1 -Rules: без служби, результат — код виходу і рядок для інсталятора
		cfg, err := loadConfig(*cfgPath, u.dataDir)
		if err != nil {
			cfg = &Config{Mode: "off"} // конфіг ще не записаний — для встановлення правил він не потрібен
		}
		u.cfg = cfg
		u.keys = append(append([]string{}, manifest.OfficialKeys...), cfg.ExtraPublicKeys...)
		msg, err := u.installRulesFile(*installRules)
		if err != nil {
			u.log.Log("ERROR", "install rules %s: %v", *installRules, err)
			fmt.Fprintln(os.Stderr, "ERROR: "+err.Error())
			os.Exit(1)
		}
		u.log.Log("INFO", "installed %s", msg)
		fmt.Println("installed " + msg)
		os.Exit(0)
	}
	body := func(stop <-chan os.Signal) int { return run(u, *cfgPath, *once, stop) }
	if ok, code := winsvc.Run(ServiceName, body); ok {
		os.Exit(code)
	}
	stop := make(chan os.Signal, 1)
	signal.Notify(stop, os.Interrupt, syscall.SIGTERM)
	os.Exit(body(stop))
}

func run(u *Updater, cfgPath string, once bool, stop <-chan os.Signal) int {
	cfg, err := loadConfig(cfgPath, u.dataDir)
	if err != nil {
		u.log.Log("ERROR", "config: %v", err)
		if once {
			fmt.Fprintln(os.Stderr, err)
		}
		return 1
	}
	u.cfg = cfg
	u.keys = append(append([]string{}, manifest.OfficialKeys...), cfg.ExtraPublicKeys...)
	u.log.Log("INFO", "start: mode %s, installed %s, rules %s%s, every %gh, window %q", cfg.Mode, orNone(u.installed()), orNone(u.installedRules()),
		map[bool]string{true: " (rule updates off)", false: ""}[cfg.Rules.Off], cfg.CheckEveryHours, cfg.Window)
	if once {
		u.handleState(time.Now())
		u.tick(time.Now(), true)
		u.listsTick(time.Now())
		return 0
	}
	// перша перевірка — через 2..12 хв після старту (сотні ПК після ранкового ввімкнення не б'ють джерело разом)
	next := time.Now().Add(2*time.Minute + time.Duration(rand.Int64N(int64(10*time.Minute))))
	u.listsNext = next // списки — теж не одразу після старту
	var markerMod time.Time
	for {
		now := time.Now()
		u.handleState(now)
		if !u.busy() && cfg.Lists.URL != "" && !now.Before(u.listsNext) {
			u.listsTick(now) // списки організації: власний розклад, будь-який режим (і off)
		}
		if !u.busy() {
			switch cfg.Mode {
			case "github", "mirror":
				if now.After(next) {
					wait := u.tick(now, false)
					next = now.Add(wait)
				}
			case "marker":
				if st, err := os.Stat(cfg.Marker.File); err == nil && !st.ModTime().Equal(markerMod) {
					markerMod = st.ModTime()
					u.marker(now)
				}
			}
		}
		select {
		case <-stop:
			u.log.Log("INFO", "stopped")
			return 0
		case <-time.After(30 * time.Second):
		}
	}
}

// tick — періодична перевірка; повертає, коли перевіряти знову.
func (u *Updater) tick(now time.Time, once bool) time.Duration {
	every := time.Duration(u.cfg.CheckEveryHours * float64(time.Hour))
	jitter := time.Duration(rand.Int64N(int64(every/10) + 1))
	if u.cfg.Mode == "marker" || u.cfg.Mode == "off" {
		if once && u.cfg.Mode == "marker" {
			if _, err := os.Stat(u.cfg.Marker.File); err == nil {
				u.marker(now)
			} else {
				u.log.Log("INFO", "mode marker: no marker %s", u.cfg.Marker.File)
			}
		}
		return every
	}
	r := &Request{}
	o := u.check(r, false, now)
	src, _ := u.base(r)
	wait := every + jitter
	switch o.Status {
	case "error":
		u.reportError(o, r, src, now)
		wait = time.Hour + jitter // джерело недоступне — частіше, ніж раз на 6 год
	case "waiting":
		u.log.Log("INFO", "%s", o.Message)
		return 30 * time.Minute
	case "started":
		return 30 * time.Minute // програма оновлюється (інсталятор перезапустить службу); правила — наступного разу
	case "current":
		u.log.Log("INFO", "%s: %s", orNone(o.From), o.Message)
	}
	if !u.cfg.Rules.Off {
		rr := &Request{Component: "rules"}
		ro := u.checkRules(rr, false, now)
		rsrc, _ := u.rulesBase(rr)
		switch ro.Status {
		case "error":
			u.reportError(ro, rr, rsrc, now)
			if wait > time.Hour+jitter {
				wait = time.Hour + jitter
			}
		case "waiting":
			u.log.Log("INFO", "%s", ro.Message)
			return 30 * time.Minute
		case "current":
			u.log.Log("INFO", "rules %s: %s", orNone(ro.From), ro.Message)
		}
	}
	return wait
}

// marker — запит агента: прочитати, виконати, записати результат, маркер -> update.json.done.
func (u *Updater) marker(now time.Time) {
	f := u.cfg.Marker.File
	b, err := os.ReadFile(f)
	if err != nil {
		return
	}
	os.Remove(f + ".done")
	os.Rename(f, f+".done")
	r, err := parseMarker(b)
	if err != nil {
		u.writeRecord(RecordUpdate{Status: "error", From: u.installed(), Mode: u.cfg.Mode, Message: err.Error()})
		return
	}
	u.log.Log("INFO", "marker: component %s version %q source %q request %q", r.component(), r.Version, r.Source, r.RequestID)
	var o Outcome
	var src string
	if r.component() == "rules" {
		o = u.checkRules(r, true, now)
		src, _ = u.rulesBase(r)
	} else {
		o = u.check(r, true, now)
		src, _ = u.base(r)
	}
	switch o.Status {
	case "error":
		u.reportError(o, r, src, now)
	case "current":
		u.writeRecord(RecordUpdate{Status: "current", Component: r.component(), From: o.From, To: o.To, Mode: u.cfg.Mode, Source: src, RequestID: r.RequestID, Message: o.Message})
	}
}

// logger — updater.log (рядок на подію; 5 МБ -> .1).
type logger struct{ file string }

func (l *logger) Log(level, f string, a ...any) {
	line := fmt.Sprintf("%s [%s] %s\r\n", time.Now().Format("2006-01-02 15:04:05"), level, fmt.Sprintf(f, a...))
	os.MkdirAll(filepath.Dir(l.file), 0o755)
	if st, err := os.Stat(l.file); err == nil && st.Size() > 5<<20 {
		os.Remove(l.file + ".1")
		os.Rename(l.file, l.file+".1")
	}
	if fh, err := os.OpenFile(l.file, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o644); err == nil {
		fh.WriteString(line)
		fh.Close()
	}
}

package main

// Опис: docscan-project/DOCSCAN.md#watcher — параметри служби watcher і їхні значення за замовчуванням.

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"time"
)

// listFlag: a repeatable / comma-separated option; the first use replaces the default list.
type listFlag struct {
	vals []string
	set  bool
}

func (l *listFlag) String() string { return strings.Join(l.vals, ",") }
func (l *listFlag) Set(s string) error {
	if !l.set {
		l.vals, l.set = nil, true
	}
	for _, v := range strings.Split(s, ",") {
		if v = strings.TrimSpace(v); v != "" {
			l.vals = append(l.vals, v)
		}
	}
	return nil
}

// Config: the options of the PowerShell watcher (same names, so install.ps1 / the docs stay valid) + Workers.
type Config struct {
	WatchPath          []string
	Base               string
	Yara, Yarac, Rules string
	OutDir             string
	NoDisarm           bool
	BackupDir          string
	QuarantineGeneral  bool
	MaxLogMB, KeepLogs int
	MaxSizeMB          int
	Settle             time.Duration
	ReadyTimeout       time.Duration
	RescanCooldown     time.Duration
	DisarmRetryMinutes int
	DisarmNoticeHours  float64
	MacroDir           string
	MacroUpload        string
	MacroKeepDays      int
	MacroMaxMB         int
	Settings           string // settings.json (settings.go): mode, black list pause, folders, workers - over these flags
	Whitelist          string // whitelist.json of the organisation (lists.go)
	Blacklist          string // blacklist.json of the organisation (lists.go)
	CriticalRules      string
	CriticalOut        string
	CriticalExt        []string
	DocExt, GenExt     []string
	Exclude            []*regexp.Regexp
	MinWorkers         int
	MaxWorkers         int
	CpuTarget, CpuHigh int
	ScanTimeout        time.Duration

	// клієнт служби (scancli.go): покласти запит на скан і вийти — сам скан робить служба
	ScanDocs   bool
	ScanPath   []string
	ScanDetect bool
	ScanDelete bool
	ScanCancel string
	ScanStatus bool
	ScanWait   bool
	outDirSet  bool
}

// ScanClient — запущено як команда скану, а не як watcher.
func (c *Config) ScanClient() bool {
	return c.ScanDocs || len(c.ScanPath) > 0 || c.ScanCancel != "" || c.ScanStatus
}

var defDocExt = []string{
	".doc", ".dot", ".docx", ".docm", ".dotx", ".dotm",
	".xls", ".xlt", ".xlsx", ".xlsm", ".xltx", ".xltm", ".xlsb",
	".ppt", ".pps", ".pot", ".pptx", ".pptm", ".potx", ".potm", ".ppsx", ".ppsm",
	".xla", ".xlam", ".ppa", ".ppam", // Excel / PowerPoint add-ins (macros on open)
	".rtf", ".pdf", ".lnk",
	".one",         // OneNote: embedded scripts/exe
	".iqy", ".slk", // Excel Web Query / SYLK: pull data, run DDE
}

var defGenExt = []string{
	".exe", ".dll", ".sys", ".scr", ".cpl", ".ocx", ".com", ".msi",
	".ps1", ".psm1", ".vbs", ".vbe", ".js", ".jse", ".wsf", ".wsh", ".hta", ".bat", ".cmd", ".jar",
	".xll",                  // Excel add-in = DLL
	".msc",                  // MMC console (GrimResource)
	".url",                  // Internet Shortcut
	".svg", ".htm", ".html", // HTML smuggling
	".zip", ".rar", ".7z", ".iso", ".img", ".vhd", ".vhdx",
}

// watched only with the critical check on: text formats the docscan module has nothing to say about
var defCriticalExt = []string{".odt", ".ods", ".odp", ".txt", ".csv"}

// paths (regex, case-insensitive) that are not scanned: browser caches, Recent (a .lnk for every opened file), etc.
var defExclude = []string{
	`\\\$Recycle\.Bin\\`,
	`\\AppData\\Local\\(Temp\\chocolatey|Packages|Microsoft\\(Edge|OneDrive|Windows\\(WebCache|Explorer|Notifications|INetCache\\IE))|Google\\Chrome|Mozilla|D3DSCache)\\`,
	`\\AppData\\Roaming\\(Code|Mozilla|Microsoft\\(Windows\\Recent|Office\\Recent))\\`,
	`\.docscan-bak$`,
	`\\~\$[^\\]*$`,
}

func parseConfig(args []string) (*Config, error) {
	fs := flag.NewFlagSet("docscan-watcher", flag.ContinueOnError)
	c := &Config{}
	watch := &listFlag{vals: []string{`C:\Users`}}
	docExt := &listFlag{vals: defDocExt}
	genExt := &listFlag{vals: defGenExt}
	critExt := &listFlag{vals: defCriticalExt}
	excl := &listFlag{vals: defExclude}
	fs.Var(watch, "WatchPath", "folders to watch (recursive), comma-separated or repeated")
	fs.StringVar(&c.Base, "Base", `C:\docscan-build`, "base folder for the defaults below")
	fs.StringVar(&c.Yara, "Yara", "", `yara64.exe (default <Base>\yara\windows\vs2019\Release\yara64.exe)`)
	fs.StringVar(&c.Yarac, "Yarac", "", "yarac64.exe (default: next to yara64.exe); compiles the rules once at start")
	fs.StringVar(&c.Rules, "Rules", "", `rules (default <Base>\yara\docscan-project\rules\docscan-index.yar)`)
	fs.StringVar(&c.OutDir, "OutDir", "", `results + watcher.log (default <Base>\results)`)
	fs.BoolVar(&c.NoDisarm, "NoDisarm", false, "do NOT disarm (detection only)")
	fs.StringVar(&c.BackupDir, "BackupDir", "", `backups and quarantine (default <Base>\quarantine); not scanned`)
	fs.BoolVar(&c.QuarantineGeneral, "QuarantineGeneral", false, "general files matching vendor rules -> quarantine")
	fs.IntVar(&c.MaxLogMB, "MaxLogMB", 50, "rotation size of docscan-results.json and watcher.log")
	fs.IntVar(&c.KeepLogs, "KeepLogs", 5, "rotated copies kept")
	fs.IntVar(&c.MaxSizeMB, "MaxSizeMB", 100, "larger files are skipped (logged)")
	settle := fs.Int("SettleSeconds", 2, "quiet time after the last event for a file")
	ready := fs.Int("ReadyTimeout", 60, "how long to wait for a file to stop being written, s")
	cool := fs.Int("RescanCooldown", 60, "the same file again - at most once per N s (autosave)")
	fs.IntVar(&c.DisarmRetryMinutes, "DisarmRetryMinutes", 60, "locked file: retry every 30 s for N min, then every 5 min")
	fs.Float64Var(&c.DisarmNoticeHours, "DisarmNoticeHours", 24, "file locked this long - a DisarmPending record")
	fs.StringVar(&c.MacroDir, "MacroDir", "", `extracted VBA code (default <OutDir>\..\macros)`)
	fs.StringVar(&c.MacroUpload, "MacroUpload", "", "also POST the macro code to this collector URL")
	fs.IntVar(&c.MacroKeepDays, "MacroKeepDays", 90, "macro store retention, days")
	fs.IntVar(&c.MacroMaxMB, "MacroMaxMB", 500, "macro store size limit, MB")
	fs.StringVar(&c.CriticalRules, "CriticalRules", "", "critical-information rules: a .yar or a folder of .yar (<InstallDir>\\rules\\critical: critical\\*.yar of the rules package); empty = off")
	fs.StringVar(&c.Settings, "Settings", "", `settings.json over these parameters (default <OutDir>\..\settings.json; written by the web interface)`)
	fs.StringVar(&c.Whitelist, "Whitelist", "", "white list of the organisation (whitelist.json): matching files are not scanned; re-read when it changes")
	fs.StringVar(&c.Blacklist, "Blacklist", "", "black list of the organisation (blacklist.json): matching files -> HIGH, quarantine; re-read when it changes")
	fs.StringVar(&c.CriticalOut, "CriticalOut", "", `E5Search queue (default <OutDir>\..\critical\critical.json)`)
	fs.Var(critExt, "CriticalExt", "extra extensions watched with the critical check on")
	fs.Var(docExt, "DocExt", "document extensions")
	fs.Var(genExt, "GenExt", "general file extensions")
	fs.Var(excl, "ExcludePattern", "path regexes that are not scanned (case-insensitive)")
	workers := fs.Int("Workers", 0, "a FIXED number of parallel scans (no automatic size)")
	fs.IntVar(&c.MinWorkers, "MinWorkers", 2, "automatic pool size: at least this many parallel scans")
	fs.IntVar(&c.MaxWorkers, "MaxWorkers", 0, "automatic pool size: at most this many (default: number of CPUs, max 32)")
	fs.IntVar(&c.CpuTarget, "CpuTarget", 60, "grow the pool only while the machine's CPU is below this %")
	fs.IntVar(&c.CpuHigh, "CpuHigh", 85, "shrink the pool when the machine's CPU reaches this %")
	stimeout := fs.Int("ScanTimeout", 600, "one yara64 run longer than this is killed, s")
	scanPath := &listFlag{}
	fs.BoolVar(&c.ScanDocs, "ScanDocs", false, "ask the running service to scan the DOCUMENTS on all local disks, then exit")
	fs.Var(scanPath, "ScanPath", "ask the running service to scan these paths (folder, file, removable drive E:\\), then exit")
	fs.BoolVar(&c.ScanDetect, "ScanDetect", false, "with -ScanDocs / -ScanPath: report only, no disarm")
	fs.BoolVar(&c.ScanDelete, "ScanDelete", false, "with -ScanDocs / -ScanPath: DELETE the HIGH files, no copy kept (not in program folders)")
	fs.StringVar(&c.ScanCancel, "ScanCancel", "", "stop a scan: its id, or all")
	fs.BoolVar(&c.ScanStatus, "ScanStatus", false, "show the running scans and the last ones")
	fs.BoolVar(&c.ScanWait, "Wait", false, "with -ScanDocs / -ScanPath: show the progress until the scan ends")
	if err := fs.Parse(args); err != nil {
		return nil, err
	}
	if fs.NArg() > 0 {
		return nil, fmt.Errorf("unexpected arguments: %v", fs.Args())
	}
	c.WatchPath = watch.vals
	c.ScanPath = scanPath.vals
	fs.Visit(func(f *flag.Flag) {
		if f.Name == "OutDir" {
			c.outDirSet = true
		}
	})
	c.Settle = time.Duration(*settle) * time.Second
	c.ReadyTimeout = time.Duration(*ready) * time.Second
	c.RescanCooldown = time.Duration(*cool) * time.Second
	c.ScanTimeout = time.Duration(*stimeout) * time.Second
	if c.MaxWorkers <= 0 {
		c.MaxWorkers = runtime.NumCPU()
		if c.MaxWorkers > 32 {
			c.MaxWorkers = 32
		}
	}
	if c.MinWorkers < 1 {
		c.MinWorkers = 1
	}
	if c.MinWorkers > c.MaxWorkers {
		c.MinWorkers = c.MaxWorkers
	}
	if *workers > 0 { // fixed size
		c.MinWorkers, c.MaxWorkers = *workers, *workers
	}
	if c.Yara == "" {
		c.Yara = filepath.Join(c.Base, `yara\windows\vs2019\Release\yara64.exe`)
	}
	if c.Yarac == "" {
		c.Yarac = filepath.Join(filepath.Dir(c.Yara), "yarac64.exe")
	}
	if c.Rules == "" {
		c.Rules = filepath.Join(c.Base, `yara\docscan-project\rules\docscan-index.yar`)
	}
	if c.OutDir == "" {
		c.OutDir = filepath.Join(c.Base, "results")
	}
	if c.BackupDir == "" {
		c.BackupDir = filepath.Join(c.Base, "quarantine")
	}
	if c.MacroDir == "" {
		c.MacroDir = filepath.Join(filepath.Dir(c.OutDir), "macros")
	}
	if c.Settings == "" {
		c.Settings = filepath.Join(filepath.Dir(c.OutDir), "settings.json")
	}
	if c.CriticalOut == "" {
		c.CriticalOut = filepath.Join(filepath.Dir(c.OutDir), "critical", "critical.json")
	}
	c.MacroUpload = strings.TrimRight(c.MacroUpload, "/")
	lower := func(v []string) []string {
		o := make([]string, len(v))
		for i, s := range v {
			o[i] = strings.ToLower(s)
		}
		return o
	}
	c.DocExt, c.GenExt, c.CriticalExt = lower(docExt.vals), lower(genExt.vals), lower(critExt.vals)
	for _, p := range excl.vals {
		re, err := regexp.Compile("(?i)" + p)
		if err != nil {
			return nil, fmt.Errorf("-ExcludePattern %q: %v", p, err)
		}
		c.Exclude = append(c.Exclude, re)
	}
	return c, nil
}

func exists(p string) bool { _, err := os.Stat(p); return err == nil }

func isFile(p string) bool {
	st, err := os.Stat(p)
	return err == nil && st.Mode().IsRegular()
}

// hasYar — p is a folder with at least one .yar (critical\*.yar of the rules package: <InstallDir>\rules\critical)
func hasYar(p string) bool {
	ents, err := os.ReadDir(p)
	if err != nil {
		return false
	}
	for _, e := range ents {
		if !e.IsDir() && strings.EqualFold(filepath.Ext(e.Name()), ".yar") && !strings.HasPrefix(e.Name(), ".") {
			return true
		}
	}
	return false
}

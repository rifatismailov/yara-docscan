package main

// Команди скану для адміністратора (PowerShell від імені адміністратора). Сам скан робить служба DocScanWatcher —
// тут лише запит у <DataDir>\scan і, з -Wait, показ ходу:
//
//	docscan-watcher.exe -ScanDocs [-ScanDetect] [-Wait]    документи на всіх локальних дисках
//	docscan-watcher.exe -ScanPath E:\ [-Wait]              тека, файл, знімний або не системний диск (кілька — через кому)
//	   ... [-ScanDetect | -ScanDelete]                      лише повідомити | видалити HIGH без копії (без — лікувати)
//	docscan-watcher.exe -ScanStatus                        що сканується зараз і останні скани
//	docscan-watcher.exe -ScanCancel <id>|all               зупинити
//
// DataDir — тека над -OutDir; без -OutDir — C:\ProgramData\DocScan (встановлений DocScan).

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"
)

const installedOutDir = `C:\ProgramData\DocScan\results`

func scanClient(c *Config, out io.Writer) int {
	if !c.outDirSet && exists(installedOutDir) {
		c.OutDir = installedOutDir
	}
	dir := scanDir(c)
	switch {
	case c.ScanStatus:
		printScanStatus(dir, out)
		return 0
	case c.ScanCancel != "":
		id := strings.TrimSpace(c.ScanCancel)
		name := "cancel-" + id
		if strings.EqualFold(id, "all") {
			name = "cancel-all"
		} else if !scanIDRe.MatchString(id) {
			fmt.Fprintf(out, "bad scan id %q (see -ScanStatus)\n", id)
			return 2
		}
		if err := os.WriteFile(filepath.Join(dir, name), []byte(time.Now().Format(time.RFC3339)), 0o644); err != nil {
			fmt.Fprintln(out, "cannot write the request:", err)
			return 1
		}
		fmt.Fprintln(out, "stop requested:", id)
		return 0
	}
	q := scanReq{Kind: "docs", By: cliUser(), Detect: c.ScanDetect, Delete: c.ScanDelete}
	if !c.ScanDocs {
		q.Kind = "path"
		for _, p := range c.ScanPath {
			if a, err := filepath.Abs(p); err == nil && !(len(p) == 2 && p[1] == ':') {
				p = a
			}
			q.Paths = append(q.Paths, p)
		}
	}
	id, err := WriteScanRequest(dir, q)
	if err != nil {
		fmt.Fprintln(out, "cannot write the request:", err)
		return 1
	}
	fmt.Fprintf(out, "scan requested: %s (%s %s)\n", id, q.Kind, strings.Join(q.Paths, ", "))
	if !c.ScanWait {
		fmt.Fprintln(out, "progress: docscan-watcher.exe -ScanStatus, or the web interface (Сканування)")
		return 0
	}
	return waitScan(dir, id, out, 5*time.Second, 0)
}

// waitScan — показувати хід, доки скан id не потрапить в історію. limit 0 — без обмеження (тести).
func waitScan(dir, id string, out io.Writer, every, limit time.Duration) int {
	start := time.Now()
	picked := false
	last := ""
	for limit == 0 || time.Since(start) < limit {
		for _, h := range readScanHistory(dir) {
			if h.ID == id {
				fmt.Fprintln(out, scanLine(h))
				for _, f := range h.HitFiles {
					fmt.Fprintln(out, "   ", f)
				}
				if h.Hits > 0 {
					return 3
				}
				if h.State == "failed" {
					return 1
				}
				return 0
			}
		}
		if st := readScanStatus(dir); st != nil {
			for _, r := range st.Active {
				if r.ID == id {
					picked = true
					if l := scanLine(r); l != last {
						fmt.Fprintln(out, l)
						last = l
					}
				}
			}
		}
		if !picked && time.Since(start) > 30*time.Second && exists(filepath.Join(dir, "request-"+id+".json")) {
			fmt.Fprintln(out, "the service has not picked up the request in 30 s - is DocScanWatcher running?")
			return 1
		}
		time.Sleep(every)
	}
	return 1
}

func scanLine(r scanRun) string {
	s := fmt.Sprintf("%s  %-9s %-5s %s  found %d, scanned %d, already checked %d, threats %d, errors %d, skipped %d, %ds",
		r.ID, r.State, r.Kind, strings.Join(r.Paths, ","), r.Found, r.Scanned, r.Cached, r.Hits, r.Errors, r.Skipped, r.Seconds)
	if r.Deleted > 0 {
		s += fmt.Sprintf(", deleted %d", r.Deleted)
	}
	if r.Note != "" {
		s += "  (" + r.Note + ")"
	}
	return s
}

func printScanStatus(dir string, out io.Writer) {
	st := readScanStatus(dir)
	if st != nil {
		fmt.Fprintf(out, "removable media: %s   (status %s)\n", st.USBMode, st.Updated)
		if len(st.Active) == 0 {
			fmt.Fprintln(out, "no scan running")
		}
		for _, r := range st.Active {
			fmt.Fprintln(out, "RUNNING ", scanLine(r))
			if r.Current != "" {
				fmt.Fprintln(out, "         now:", r.Current)
			}
		}
	} else {
		fmt.Fprintln(out, "no status yet:", filepath.Join(dir, "status.json"))
	}
	h := readScanHistory(dir)
	if len(h) > 10 {
		h = h[:10]
	}
	if len(h) > 0 {
		fmt.Fprintln(out, "last scans:")
	}
	for _, r := range h {
		fmt.Fprintln(out, "  ", scanLine(r))
	}
}

func cliUser() string {
	u := os.Getenv("USERNAME")
	if u == "" {
		u = os.Getenv("USER")
	}
	if u == "" {
		return "cli"
	}
	return "cli:" + u
}

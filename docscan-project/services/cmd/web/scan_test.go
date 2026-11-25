package main

import (
	"encoding/json"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestScanPage(t *testing.T) {
	_, p, do := signedIn(t)
	sd := p.scanDir()
	os.MkdirAll(sd, 0o755)
	// a running scan and one in the history, as the watcher writes them
	now := time.Now().Format(time.RFC3339)
	os.WriteFile(filepath.Join(sd, "status.json"), []byte(`{"updated":"`+now+`","usb_mode":"full","active":[{"id":"20261123-100000.000-usb","kind":"usb","paths":["E:\\"],"by":"auto","state":"running","started":"`+now+`","found":200,"scanned":50,"cached":30,"hits":1,"walking":true,"current":"E:\\docs\\a.docx"}],"queue":120}`), 0o644)
	os.WriteFile(filepath.Join(sd, "history.json"), []byte(`[{"id":"20261123-090000.000-docs","kind":"docs","paths":["C:\\"],"by":"admin","state":"done","started":"`+now+`","seconds":3700,"found":1000,"scanned":990,"hits":2,"hit_files":["HIGH C:\\x\\evil.docm"]}]`), 0o644)

	w := do("GET", "/scan", nil)
	page := w.Body.String()
	for _, s := range []string{"Сканування", "носій", "E:\\docs\\a.docx", "80 з 200", "ще шукаю", "1 год 1 хв", "evil.docm", `http-equiv="refresh"`, "Скан документів", "документи"} {
		if !strings.Contains(page, s) {
			t.Fatalf("scan page: no %q", s)
		}
	}

	// start: a path -> request file for the watcher + audit
	dir := t.TempDir()
	w = do("POST", "/scan/start", url.Values{"kind": {"path"}, "paths": {dir + "\n"}, "detect": {"on"}})
	if w.Code != 303 {
		t.Fatalf("start: %d %s", w.Code, w.Body.String())
	}
	reqs, _ := filepath.Glob(filepath.Join(sd, "request-*.json"))
	if len(reqs) != 1 {
		t.Fatalf("requests: %v", reqs)
	}
	var q wScanReq
	b, _ := os.ReadFile(reqs[0])
	json.Unmarshal(b, &q)
	if q.Kind != "path" || len(q.Paths) != 1 || q.Paths[0] != dir || !q.Detect || q.By != "admin" || !strings.HasSuffix(reqs[0], "request-"+q.ID+".json") {
		t.Fatalf("request %+v", q)
	}
	auditHas(t, p, "scan-start")
	// relative / missing path refused
	if w := do("POST", "/scan/start", url.Values{"kind": {"path"}, "paths": {"relative\\x"}}); !strings.Contains(w.Body.String(), "a full path") {
		t.Fatal("relative path accepted")
	}
	if w := do("POST", "/scan/start", url.Values{"kind": {"path"}, "paths": {filepath.Join(dir, "nope")}}); w.Code == 303 {
		t.Fatal("missing path accepted")
	}
	// documents on the local disks
	if w := do("POST", "/scan/start", url.Values{"kind": {"docs"}}); !strings.Contains(w.Body.String(), "at least one local disk") {
		t.Fatal("docs scan without a disk accepted")
	}
	do("POST", "/scan/start", url.Values{"kind": {"docs"}, "docs_root": {"/", "/not-a-disk"}})
	reqs, _ = filepath.Glob(filepath.Join(sd, "request-*docs.json"))
	if len(reqs) != 1 {
		t.Fatalf("docs request: %v", reqs)
	}
	b, _ = os.ReadFile(reqs[0])
	q = wScanReq{}
	json.Unmarshal(b, &q)
	if len(q.Paths) != 1 || q.Paths[0] != "/" {
		t.Fatalf("docs request %+v", q)
	}
	// no full scan of everything: the old kind, a whole local disk (path or drive button) are refused
	before, _ := filepath.Glob(filepath.Join(sd, "request-*.json"))
	do("POST", "/scan/start", url.Values{"kind": {"full"}})
	if w := do("POST", "/scan/start", url.Values{"kind": {"path"}, "paths": {"/"}}); !strings.Contains(w.Body.String(), "whole system disk") {
		t.Fatal("whole local disk accepted as a path")
	}
	if w := do("POST", "/scan/start", url.Values{"kind": {"drive"}, "root": {"/"}}); !strings.Contains(w.Body.String(), "removable") {
		t.Fatal("local disk accepted by the drive button")
	}
	if after, _ := filepath.Glob(filepath.Join(sd, "request-*.json")); len(after) != len(before) {
		t.Fatalf("full-scan request written: %v", after)
	}
	// stop: bad id refused, good one -> cancel file
	do("POST", "/scan/stop", url.Values{"id": {"../../auth"}})
	if m, _ := filepath.Glob(filepath.Join(sd, "cancel-*")); len(m) != 0 {
		t.Fatalf("bad id: %v", m)
	}
	do("POST", "/scan/stop", url.Values{"id": {"20261123-100000.000-usb"}})
	if !fileExists(filepath.Join(sd, "cancel-20261123-100000.000-usb")) {
		t.Fatal("no cancel file")
	}
	auditHas(t, p, "scan-stop")
	// removable media mode -> settings.json usb_scan, the other keys kept
	os.WriteFile(p.settingsFile(), []byte(`{"detect_only": false, "blacklist_paused_until": "manual"}`), 0o644)
	do("POST", "/scan/usb", url.Values{"usb": {"detect"}})
	set, err := readSettings(p)
	if err != nil || set.USBScan != "detect" || set.BlacklistPausedUntil != "manual" || set.DetectOnly == nil {
		t.Fatalf("settings %+v %v", set, err)
	}
	do("POST", "/scan/usb", url.Values{"usb": {"bogus"}})
	if set, _ = readSettings(p); set.USBScan != "detect" {
		t.Fatal("bogus mode written")
	}
	auditHas(t, p, "usb-scan")
	// no active scan -> no auto refresh
	os.WriteFile(filepath.Join(sd, "status.json"), []byte(`{"updated":"`+now+`","usb_mode":"detect","active":[]}`), 0o644)
	os.RemoveAll(filepath.Join(sd))
	os.MkdirAll(sd, 0o755)
	if strings.Contains(do("GET", "/scan", nil).Body.String(), `http-equiv="refresh"`) {
		t.Fatal("refresh without a running scan")
	}
	// delete: first a confirmation page (no request), then with confirm=on the request has delete
	os.MkdirAll(sd, 0o755)
	w2 := do("POST", "/scan/start", url.Values{"kind": {"path"}, "pick": {dir}, "action": {"delete"}})
	if !strings.Contains(w2.Body.String(), "Так, сканувати і видаляти") || !strings.Contains(w2.Body.String(), `name="pick"`) {
		t.Fatalf("no confirmation page: %s", w2.Body.String())
	}
	if m, _ := filepath.Glob(filepath.Join(sd, "request-*.json")); len(m) != 0 {
		t.Fatalf("request without confirmation: %v", m)
	}
	do("POST", "/scan/start", url.Values{"kind": {"path"}, "pick": {dir}, "action": {"delete"}, "confirm": {"on"}})
	m, _ := filepath.Glob(filepath.Join(sd, "request-*.json"))
	if len(m) != 1 {
		t.Fatalf("delete request: %v", m)
	}
	b2, _ := os.ReadFile(m[0])
	var dq wScanReq
	json.Unmarshal(b2, &dq)
	if !dq.Delete || dq.Detect || len(dq.Paths) != 1 || dq.Paths[0] != dir {
		t.Fatalf("delete request %+v", dq)
	}
	if lg, _ := os.ReadFile(p.resultsLog()); !strings.Contains(string(lg), "ВИДАЛИТИ") {
		t.Error("delete scan not audited")
	}
	// browser: drives, then a folder with its files; the system disk root cannot be picked whole
	if b := do("GET", "/scan/browse", nil).Body.String(); !strings.Contains(b, "/scan/browse?p=%2f") {
		t.Fatalf("browser: no drives\n%s", b)
	}
	os.WriteFile(filepath.Join(dir, "report.docm"), []byte("x"), 0o644)
	os.MkdirAll(filepath.Join(dir, "sub"), 0o755)
	bp := do("GET", "/scan/browse?p="+url.QueryEscape(dir), nil).Body.String()
	for _, s := range []string{"report.docm", "sub", "уся ця тека", "уся відкрита тека", `name="cur" value="` + dir + `"`, `value="` + filepath.Join(dir, "sub") + `"`} {
		if !strings.Contains(bp, s) {
			t.Fatalf("browser page: no %q", s)
		}
	}
	if b := do("GET", "/scan/browse?p=%2F", nil).Body.String(); strings.Contains(b, "уся ця тека") || !strings.Contains(b, "системний диск не вибирається") {
		t.Fatal("system disk root pickable")
	}
	// browser: nothing ticked -> the opened folder (cur); nothing at all -> a clear error, no request
	os.RemoveAll(sd)
	os.MkdirAll(sd, 0o755)
	do("POST", "/scan/start", url.Values{"kind": {"path"}, "cur": {dir}, "action": {"detect"}})
	cq, _ := filepath.Glob(filepath.Join(sd, "request-*.json"))
	if len(cq) != 1 {
		t.Fatalf("opened folder: requests %v", cq)
	}
	var cr wScanReq
	b3, _ := os.ReadFile(cq[0])
	json.Unmarshal(b3, &cr)
	if len(cr.Paths) != 1 || cr.Paths[0] != dir {
		t.Fatalf("opened folder: %+v", cr)
	}
	if b := do("POST", "/scan/start", url.Values{"kind": {"path"}, "action": {"detect"}}).Body.String(); !strings.Contains(b, "нічого не вибрано") {
		t.Fatalf("nothing picked: no error\n%s", b)
	}
	// queue: a second identical request refused; an old request -> "the service does not take requests";
	// "Прибрати" removes a request from the queue
	os.RemoveAll(sd)
	os.MkdirAll(sd, 0o755)
	do("POST", "/scan/start", url.Values{"kind": {"path"}, "paths": {dir}, "action": {"detect"}})
	do("POST", "/scan/start", url.Values{"kind": {"path"}, "paths": {dir}, "action": {"cure"}})
	pq, _ := filepath.Glob(filepath.Join(sd, "request-*.json"))
	if len(pq) != 1 {
		t.Fatalf("duplicate request written: %v", pq)
	}
	old := time.Now().Add(-time.Minute)
	os.Chtimes(pq[0], old, old)
	if b := do("GET", "/scan", nil).Body.String(); !strings.Contains(b, "не бере запити") || !strings.Contains(b, "Прибрати") {
		t.Fatal("no warning for a request the service does not take")
	}
	id := strings.TrimSuffix(strings.TrimPrefix(filepath.Base(pq[0]), "request-"), ".json")
	do("POST", "/scan/stop", url.Values{"id": {id}})
	if fileExists(pq[0]) || fileExists(filepath.Join(sd, "cancel-"+id)) {
		t.Fatal("pending request not removed from the queue")
	}
}

package orglists

import (
	"strings"
	"testing"
)

func TestParse(t *testing.T) {
	ok := "\ufeff" + `{"schema": 1, "serial": 7, "description": "x", "entries": [
	  {"path": "C:\\Users\\*\\Desktop\\App*.lnk", "lnk_target": "//fileserver/BIN", "comment": "App", "added": "2026-11-21", "by": "admin"},
	  {"sha256": "` + strings.Repeat("AB", 32) + `", "comment": "own app"}]}`
	l, err := Parse([]byte(ok), "white")
	if err != nil {
		t.Fatal(err)
	}
	if l.Entries[0].LnkTarget != `\\fileserver\bin\` || l.Entries[1].SHA256 != strings.Repeat("ab", 32) || l.Serial != 7 {
		t.Fatalf("not normalised: %+v", l)
	}
	bad := map[string][2]string{
		"schema":             {"white", `{"schema": 2, "entries": []}`},
		"unknown field":      {"white", `{"schema": 1, "entries": [{"path": "C:\\a\\b.exe", "action": "x"}]}`},
		"top field":          {"black", `{"schema": 1, "entry": []}`},
		"empty entry":        {"black", `{"schema": 1, "entries": [{"comment": "x"}]}`},
		"bad sha":            {"black", `{"schema": 1, "entries": [{"sha256": "1234"}]}`},
		"relative path":      {"black", `{"schema": 1, "entries": [{"path": "Downloads\\*.exe"}]}`},
		"env variable path":  {"black", `{"schema": 1, "entries": [{"path": "%USERPROFILE%\\Downloads\\*.exe"}]}`},
		"dotdot path":        {"black", `{"schema": 1, "entries": [{"path": "C:\\Users\\..\\x.exe"}]}`},
		"white all files":    {"white", `{"schema": 1, "entries": [{"path": "C:\\Users\\*\\Downloads\\*.*"}]}`},
		"white whole server": {"white", `{"schema": 1, "entries": [{"lnk_target": "\\\\srv"}]}`},
		"local lnk_target":   {"black", `{"schema": 1, "entries": [{"lnk_target": "C:\\Windows"}]}`},
		"mask in target":     {"black", `{"schema": 1, "entries": [{"lnk_target": "\\\\srv\\*"}]}`},
		"negative serial":    {"black", `{"schema": 1, "serial": -1, "entries": []}`},
		"trailing data":      {"black", `{"schema": 1, "entries": []} {}`},
	}
	for name, c := range bad {
		if _, err := Parse([]byte(c[1]), c[0]); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	// a macOS / Linux absolute path (tests, CLI) is a full path too; a UNC path is not a local file path
	if _, err := Parse([]byte(`{"schema": 1, "entries": [{"path": "/tmp/in/App*.lnk"}]}`), "white"); err != nil {
		t.Errorf("unix absolute path: %v", err)
	}
	if _, err := Parse([]byte(`{"schema": 1, "entries": [{"path": "\\\\srv\\x\\a.exe"}]}`), "black"); err == nil {
		t.Errorf("UNC path accepted as a file path")
	}
	// black list: a whole server and "all .exe of a folder" are fine there
	if _, err := Parse([]byte(`{"schema": 1, "entries": [{"lnk_target": "\\\\evil-srv\\"}, {"path": "C:\\Users\\*\\Downloads\\*.exe"}]}`), "black"); err != nil {
		t.Errorf("black list: %v", err)
	}
}

func TestMatchPath(t *testing.T) {
	cases := []struct {
		pat, p string
		want   bool
	}{
		{`C:\Users\*\Desktop\App*.lnk`, `C:\Users\anna\Desktop\App - fileserver.lnk`, true},
		{`C:\Users\*\Desktop\App*.lnk`, `c:\users\ANNA\desktop\app.LNK`, true},
		{`C:\Users\*\Desktop\App*.lnk`, `C:\Users\anna\Desktop\sub\App.lnk`, false},
		{`C:\Users\*\Desktop\App*.lnk`, `C:\Users\anna\Documents\App.lnk`, false},
		{`C:\Users\*\Downloads\*.exe`, `C:\Users\bob\Downloads\AnyDesk.exe`, true},
		{`C:\Users\*\Downloads\*.exe`, `C:\Users\bob\Downloads\x\AnyDesk.exe`, false},
		{`C:\Users\*\Downloads\**\*.exe`, `C:\Users\bob\Downloads\x\y\AnyDesk.exe`, true},
		{`C:\Users\*\Downloads\setup?.msi`, `C:\Users\bob\Downloads\setup1.msi`, true},
		{`C:\Users\*\Downloads\setup?.msi`, `C:\Users\bob\Downloads\setup12.msi`, false},
		{`C:\Users\*\Downloads\a+b(1).exe`, `C:\Users\bob\Downloads\a+b(1).exe`, true},
	}
	for _, c := range cases {
		if got := MatchPath(c.pat, c.p); got != c.want {
			t.Errorf("MatchPath(%q, %q) = %v", c.pat, c.p, got)
		}
	}
}

func TestMatchTarget(t *testing.T) {
	for _, c := range []struct {
		pre, t string
		want   bool
	}{
		{`\\fileserver\bin\`, `\\fileserver\BIN\App\Bin\App.exe`, true},
		{`\\fileserver\bin\`, `\\FILESERVER\bin\x.exe`, true},
		{`\\fileserver\bin\`, `\\fileserver\binx\x.exe`, false},
		{`\\fileserver\bin\`, `\\fileserver\bin\..\other\x.exe`, false},
		{`\\fileserver\bin\`, `C:\Windows\cmd.exe`, false},
		{`\\fileserver\bin\`, ``, false},
		{`\\evil-srv\`, `\\evil-srv\share\x.exe`, true},
	} {
		if got := MatchTarget(c.pre, c.t); got != c.want {
			t.Errorf("MatchTarget(%q, %q) = %v", c.pre, c.t, got)
		}
	}
}

func TestDecide(t *testing.T) {
	own := strings.Repeat("a", 64)
	bad := strings.Repeat("b", 64)
	white, err := Parse([]byte(`{"schema": 1, "entries": [
	  {"path": "C:\\Users\\*\\Desktop\\App*.lnk", "lnk_target": "\\\\fileserver\\BIN\\"},
	  {"sha256": "`+own+`"},
	  {"sha256": "`+bad+`", "comment": "a mistake: also in the black list"}]}`), "white")
	if err != nil {
		t.Fatal(err)
	}
	black, err := Parse([]byte(`{"schema": 1, "entries": [
	  {"path": "C:\\Users\\*\\Downloads\\*.exe"},
	  {"sha256": "`+bad+`"},
	  {"lnk_target": "\\\\evil-srv\\"}]}`), "black")
	if err != nil {
		t.Fatal(err)
	}
	calls := 0
	lnk := func(p, target string) File {
		return File{Path: p, SHA256: "c", Target: func() string { calls++; return target }}
	}
	cases := []struct {
		name string
		f    File
		want string
	}{
		{"App shortcut to the share", lnk(`C:\Users\anna\Desktop\App - fileserver.lnk`, `\\fileserver\BIN\App\Bin\App.exe`), "allow:white"},
		{"App-named shortcut to another server", lnk(`C:\Users\anna\Desktop\App.lnk`, `\\evil\x\App.exe`), ""},
		{"any shortcut to the forbidden server", lnk(`C:\Users\anna\Documents\Report.lnk`, `\\evil-srv\share\r.exe`), "block:black"},
		{"exe in Downloads", File{Path: `C:\Users\bob\Downloads\AnyDesk.exe`, SHA256: "c"}, "block:black"},
		{"own app in Downloads (white sha256 beats the folder ban)", File{Path: `C:\Users\bob\Downloads\our.exe`, SHA256: own}, "allow:white"},
		{"known bad file, also in white by mistake", File{Path: `C:\Temp\x.dll`, SHA256: bad}, "block:black"},
		{"ordinary document", File{Path: `C:\Users\bob\Documents\a.docx`, SHA256: "c"}, ""},
	}
	for _, c := range cases {
		d := Decide(white, black, c.f)
		got := ""
		if d.Action != "" {
			got = d.Action + ":" + d.List
		}
		if got != c.want {
			t.Errorf("%s: got %q, want %q", c.name, got, c.want)
		}
	}
	// the target is read only for shortcuts whose other fields matched / that have lnk_target entries
	calls = 0
	Decide(white, black, File{Path: `C:\Users\bob\Documents\a.docx`, SHA256: "c", Target: func() string { calls++; return "" }})
	if calls != 0 {
		t.Errorf("target looked up for a non-shortcut: %d", calls)
	}
	if !NeedsTarget(white) || NeedsTarget(&List{Entries: []Entry{{SHA256: own}}}) {
		t.Errorf("NeedsTarget")
	}
}

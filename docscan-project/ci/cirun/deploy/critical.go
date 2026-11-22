package deploy

// Правила критичної інформації в пакеті правил: тека critical/ пакета DocScan-rules.zip (на ПК —
// <InstallDir>\rules\critical\*.yar, watcher -CriticalRules). Джерело — окремий репозиторій (docscan-critical):
//
//	critical/*.yar        правила; скільки завгодно файлів, лише верхній рівень, імена латиницею
//	tests/match/...       документи, які МАЮТЬ потрапити в чергу (будь-яка вкладеність)
//	tests/no-match/...    документи, які НЕ мають потрапити в чергу
//
// CheckCritical перед пакуванням: імена файлів, компіляція усіх .yar разом (yara --critical-rules=<тека>, як на ПК),
// тести на документах. Будь-яка помилка — релізу немає.

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
)

// CriticalNameRe — ім'я файлу правил (ім'я без .yar — простір імен yara на ПК).
var CriticalNameRe = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.-]{0,99}\.yar$`)

// CriticalResult — що перевірено (для звіту).
type CriticalResult struct {
	Files            []string // critical/*.yar
	Match, NoMatch   int      // документів у tests/match, tests/no-match
	Missed, Unwanted []string // не потрапили в чергу / потрапили, хоча не мали
}

// CriticalFiles — *.yar у critical/ (відсортовані); інші файли й підтеки — помилка.
func CriticalFiles(dir string) ([]string, error) {
	ents, err := os.ReadDir(dir)
	if err != nil {
		return nil, err
	}
	var names, bad []string
	for _, e := range ents {
		n := e.Name()
		switch {
		case strings.HasPrefix(n, "."):
		case e.IsDir():
			bad = append(bad, n+"/ (no subfolders: every .yar at the top level of critical/)")
		case CriticalNameRe.MatchString(n):
			names = append(names, n)
		default:
			bad = append(bad, n)
		}
	}
	if len(bad) > 0 {
		return nil, fmt.Errorf("critical/: not a rules file (expected NAME.yar, NAME of A-Z a-z 0-9 _ - .): %s", strings.Join(bad, ", "))
	}
	if len(names) == 0 || len(names) > 256 {
		return nil, fmt.Errorf("critical/ has %d .yar files (1..256)", len(names))
	}
	sort.Strings(names)
	return names, nil
}

// CheckCritical — repo: checkout репозиторію критичних правил (critical/, tests/); yara — наш yara (з модулем docscan);
// index — docscan-index.yar релізу (основні правила — як на ПК); work — тимчасова тека.
func CheckCritical(repo, yara, index, work string) (*CriticalResult, error) {
	dir := filepath.Join(repo, "critical")
	names, err := CriticalFiles(dir)
	if err != nil {
		return nil, err
	}
	r := &CriticalResult{Files: names}
	tmp, err := os.MkdirTemp(work, "critical-check-")
	if err != nil {
		return nil, err
	}
	defer os.RemoveAll(tmp)
	// 1) компіляція: основні правила — одне порожнє правило, файл — пробний
	empty, probe := filepath.Join(tmp, "empty.yar"), filepath.Join(tmp, "probe.txt")
	os.WriteFile(empty, []byte("rule docscan_critical_probe { condition: false }\n"), 0o644)
	os.WriteFile(probe, []byte("probe\n"), 0o644)
	out, _ := exec.Command(yara, "-w", "--critical-rules="+dir, "--critical-out="+filepath.Join(tmp, "probe.json"), empty, probe).CombinedOutput()
	if errs := errorLines(string(out)); len(errs) > 0 {
		return nil, fmt.Errorf("the critical rules do not compile: %s", strings.Join(errs, "; "))
	}
	// 2) тести: один прохід yara по теці, у черзі — шлях кожного документа, що спрацював
	for _, t := range []struct {
		sub  string
		want bool
	}{{"match", true}, {"no-match", false}} {
		td := filepath.Join(repo, "tests", t.sub)
		if st, err := os.Stat(td); err != nil || !st.IsDir() {
			continue
		}
		docs := map[string]bool{}
		filepath.Walk(td, func(p string, fi os.FileInfo, err error) error {
			if err == nil && fi.Mode().IsRegular() && !strings.HasPrefix(fi.Name(), ".") {
				docs[realPath(p)] = true
			}
			return nil
		})
		q := filepath.Join(tmp, t.sub+".json")
		out, _ := exec.Command(yara, "-w", "-r", "--file-vars", "--critical-rules="+dir, "--critical-out="+q, index, td).CombinedOutput()
		if errs := errorLines(string(out)); len(errs) > 0 {
			return nil, fmt.Errorf("tests/%s: yara: %s", t.sub, strings.Join(errs, "; "))
		}
		queued, err := queuedPaths(q)
		if err != nil {
			return nil, fmt.Errorf("tests/%s: %w", t.sub, err)
		}
		root := realPath(repo)
		for p := range docs {
			rel, _ := filepath.Rel(root, p)
			switch {
			case t.want && !queued[p]:
				r.Missed = append(r.Missed, rel)
			case !t.want && queued[p]:
				r.Unwanted = append(r.Unwanted, rel)
			}
		}
		if t.want {
			r.Match = len(docs)
		} else {
			r.NoMatch = len(docs)
		}
	}
	sort.Strings(r.Missed)
	sort.Strings(r.Unwanted)
	if len(r.Missed) > 0 || len(r.Unwanted) > 0 {
		return r, fmt.Errorf("critical tests: %d of %d documents of tests/match not found, %d of %d of tests/no-match found by mistake",
			len(r.Missed), r.Match, len(r.Unwanted), r.NoMatch)
	}
	return r, nil
}

// queuedPaths — document.path кожного рядка черги (абсолютні шляхи).
func queuedPaths(q string) (map[string]bool, error) {
	m := map[string]bool{}
	f, err := os.Open(q)
	if os.IsNotExist(err) {
		return m, nil // нічого не спрацювало
	}
	if err != nil {
		return nil, err
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 1<<20), 256<<20)
	for sc.Scan() {
		var rec struct {
			Document struct {
				Path string `json:"path"`
			} `json:"document"`
		}
		if err := json.Unmarshal(sc.Bytes(), &rec); err != nil {
			return nil, fmt.Errorf("queue line is not JSON: %w", err)
		}
		m[realPath(rec.Document.Path)] = true
	}
	return m, sc.Err()
}

// realPath — абсолютний шлях без символьних посилань (yara пише в чергу повний шлях: на macOS /var -> /private/var).
func realPath(p string) string {
	abs, _ := filepath.Abs(p)
	if r, err := filepath.EvalSymlinks(abs); err == nil {
		return r
	}
	return abs
}

func errorLines(out string) []string {
	var errs []string
	for _, l := range strings.Split(out, "\n") {
		if strings.Contains(strings.ToLower(l), "error") {
			errs = append(errs, strings.TrimSpace(l))
		}
	}
	return errs
}

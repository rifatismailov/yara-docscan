package platform

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"docscan/cirun/assets"
	"docscan/cirun/config"
	"docscan/cirun/transport"
)

// Unix — спільна частина macOS і Linux: збірка і тести скриптом build-test-unix.sh (кроки build / test).
// MacOS і Linux відрізняються лише перевіркою інструментів (Prepare).
type Unix struct {
	name   string           // "macos" | "linux"
	cfg    *config.Platform // розділ конфігу цієї платформи
	sec    *config.Resolver // секрети для підключення
	fuzz   int              // секунди фазингу
	runDir string           // локальна тека прогону (абсолютна): тут робоча тека для local
	report Reporter
	checks []string          // команди перевірки інструментів (усі мають завершитися з 0)
	assets *assets.Assets    // тестові файли поза git (nil — тестів на корпусах немає)
	full   bool              // вибрана машина проганяє всі тести (Candidate.full_tests)
	env    map[string]string // CI_CORPUS / CI_SEEDS / CI_MALWARE для кроку test

	t       transport.Transport
	local   bool   // машина — цей комп'ютер
	repoDir string // де лежить код на машині
	outDir  string // CI_OUT скрипта на машині
}

// NewMacOS — macOS: локально (цей Мак) або через SSH.
func NewMacOS(cfg *config.Platform, sec *config.Resolver, fuzz int, runDir string, as *assets.Assets, report Reporter) *Unix {
	return &Unix{name: "macos", cfg: cfg, sec: sec, fuzz: fuzz, runDir: runDir, assets: as, report: report,
		checks: []string{"xcode-select -p", "command -v make", "command -v python3",
			"PATH=/opt/homebrew/bin:$PATH command -v autoreconf"}}
}

// NewLinux — Linux через SSH (або локально, якщо cirun запущено на Linux).
func NewLinux(cfg *config.Platform, sec *config.Resolver, fuzz int, runDir string, as *assets.Assets, report Reporter) *Unix {
	return &Unix{name: "linux", cfg: cfg, sec: sec, fuzz: fuzz, runDir: runDir, assets: as, report: report,
		checks: []string{"command -v gcc", "command -v make", "command -v autoreconf", "command -v python3",
			"command -v tar", "pkg-config --exists libcrypto jansson libmagic"}}
}

func (u *Unix) Name() string { return u.name }

// Prepare підключається до першої доступної машини і перевіряє інструменти збірки.
func (u *Unix) Prepare(ctx context.Context) error {
	var tried []string
	for _, m := range u.cfg.Machines() {
		if !transport.Reachable(m.Connection) {
			tried = append(tried, m.Name+" ("+m.Connection.Host+")")
			continue
		}
		t, err := transport.New(ctx, m.Connection, u.sec)
		if err != nil {
			return fmt.Errorf("%s: %w", m.Name, err)
		}
		u.t = t
		u.local = m.Connection.Type == "local"
		u.full = m.Full()
		where := t.Where()
		if u.local {
			where = "this computer"
		}
		u.report(Event{Platform: u.name, Kind: "machine", Where: where + " (" + m.Name + ")"})
		break
	}
	if u.t == nil {
		return fmt.Errorf("no machine is reachable: %s", strings.Join(tried, ", "))
	}
	if u.local && (u.cfg.Workdir == "" || u.cfg.Workdir == ".") {
		u.repoDir, _ = os.Getwd() // сам репозиторій (cirun уже перейшов у його корінь)
		u.outDir = filepath.Join(u.runDir, u.name+"-work")
	} else {
		u.repoDir = strings.TrimRight(u.cfg.Workdir, "/") + "/src"
		u.outDir = strings.TrimRight(u.cfg.Workdir, "/") + "/out"
	}
	var missing []string
	for _, c := range u.checks {
		if r, err := u.t.Run(ctx, c+" >/dev/null 2>&1", nil); err != nil || r.ExitCode != 0 {
			missing = append(missing, c)
		}
	}
	if len(missing) > 0 {
		return fmt.Errorf("build tools missing on the machine: %s", strings.Join(missing, "; "))
	}
	return nil
}

// SyncSource: локально з workdir "." — нічого (збирається сам репозиторій); інакше git archive
// точного коміту -> на машину -> розпакувати в чисту теку src (повна збірка з нуля).
func (u *Unix) SyncSource(ctx context.Context, src Source) error {
	if u.local && (u.cfg.Workdir == "" || u.cfg.Workdir == ".") {
		return nil
	}
	data, err := src.Archive("tar.gz")
	if err != nil {
		return err
	}
	arch := strings.TrimRight(u.cfg.Workdir, "/") + "/src.tar.gz"
	if err := u.t.Upload(ctx, data, arch); err != nil {
		return err
	}
	r, err := u.t.Run(ctx, fmt.Sprintf("rm -rf %s %s && mkdir -p %s && tar xzf %s -C %s && rm -f %s",
		shq(u.repoDir), shq(u.outDir), shq(u.repoDir), shq(arch), shq(u.repoDir), shq(arch)), nil)
	if err == nil && r.ExitCode != 0 {
		err = fmt.Errorf("unpack: %s", strings.TrimSpace(r.Output))
	}
	return err
}

// script — команда запуску build-test-unix.sh з кроком stage і змінними середовища.
func (u *Unix) script(stage string) string {
	env := map[string]string{"CI_OUT": u.outDir, "FUZZ_SECONDS": fmt.Sprint(u.fuzz), "CI_SEEDS": config.ExpandHome(u.cfg.Seeds)}
	if !u.full {
		env["FUZZ_SECONDS"] = "0" // машина лише для збірки і 35 зразків
		env["CI_SEEDS"] = ""
	}
	for k, v := range u.cfg.Env {
		env[k] = v
	}
	for k, v := range u.env {
		env[k] = v
	}
	keys := make([]string, 0, len(env))
	for k := range env {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	var b strings.Builder
	fmt.Fprintf(&b, "cd %s &&", shq(u.repoDir))
	for _, k := range keys {
		fmt.Fprintf(&b, " %s=%s", k, shq(env[k]))
	}
	fmt.Fprintf(&b, " sh %s %s", shq(u.cfg.Script), stage)
	return b.String()
}

// Build — крок build скрипта (bootstrap, configure, make).
func (u *Unix) Build(ctx context.Context) (StepResult, error) {
	tr := newTracker(u.name, u.report, "build")
	r, err := u.t.Run(ctx, u.script("build"), tr.line)
	if err != nil {
		return StepResult{Name: "build", Status: "FAIL", Log: r.Output}, err
	}
	if len(tr.steps) == 1 {
		res := tr.steps[0]
		res.Log = r.Output
		return res, nil
	}
	// скрипт не дійшов до рядка підсумку (напр. упав до кроку) — вирішує код виходу
	st := map[bool]string{true: "PASS", false: "FAIL"}[r.ExitCode == 0]
	res := StepResult{Name: "build", Status: st, Log: r.Output}
	u.report(Event{Platform: u.name, Kind: "done", Step: "build", Result: &res})
	return res, nil
}

// Test — крок test скрипта: documents, critical, hostile, corpus, malware, fuzz. Тестові файли поза git:
// Мак бере розпаковану копію, віддалена машина завантажує архіви зі сховку і ВИДАЛЯЄ їх після тестів.
func (u *Unix) Test(ctx context.Context) ([]StepResult, error) {
	cleanup, err := u.fetchAssets(ctx)
	defer cleanup()
	if err != nil {
		return nil, fmt.Errorf("test assets: %w", err)
	}
	tr := newTracker(u.name, u.report, "documents", "critical", "hostile", "corpus", "malware", "fuzz")
	r, err := u.t.Run(ctx, u.script("test"), tr.line)
	if err != nil {
		return tr.steps, err
	}
	if r.ExitCode != 0 && !Failed(tr.steps) { // упав поза кроками — теж провал
		tr.steps = append(tr.steps, StepResult{Name: "test", Status: "FAIL", Log: r.Output})
	}
	return tr.steps, nil
}

// fetchAssets готує тестові файли для кроку test і повертає функцію прибирання (викликати завжди).
func (u *Unix) fetchAssets(ctx context.Context) (func(), error) {
	none := func() {}
	if u.assets == nil || !u.full {
		return none, nil
	}
	if u.local { // Мак: розпакована копія того самого архіву, що отримують віддалені машини
		u.env = map[string]string{"CI_CORPUS": u.assets.LocalCorpus, "CI_SEEDS": u.assets.LocalSeeds, "CI_MALWARE": u.assets.LocalMalware}
		return none, nil
	}
	if u.assets.CorpusURL == "" {
		return none, nil
	}
	dir := strings.TrimRight(u.cfg.Workdir, "/") + "/tests"
	cleanup := func() { // шкідливе ПЗ і корпуси на машині не лишаються
		u.t.Run(context.Background(), "rm -rf "+shq(dir), nil)
	}
	// токен — у файлі заголовка (не в командному рядку curl, тобто не в списку процесів)
	if err := u.t.Upload(ctx, []byte("Authorization: token "+u.assets.Token+"\n"), dir+"/.hdr"); err != nil {
		return cleanup, err
	}
	script := fmt.Sprintf("set -e\ncd %s && chmod 600 .hdr\ncurl -fsS -H @.hdr -o corpus.tar.gz %s && tar xzf corpus.tar.gz && rm -f corpus.tar.gz",
		shq(dir), shq(u.assets.CorpusURL))
	if u.assets.MalwareURL != "" {
		script += fmt.Sprintf("\ncurl -fsS -H @.hdr -o malware.zip %s\n"+
			"python3 -c \"import zipfile; zipfile.ZipFile('malware.zip').extractall('malware', pwd=b'%s')\" && rm -f malware.zip",
			shq(u.assets.MalwareURL), assets.MalwareZipKey)
	}
	script += "\nrm -f .hdr"
	r, err := u.t.Run(ctx, script, nil)
	if err == nil && r.ExitCode != 0 {
		err = fmt.Errorf("download: %s", strings.TrimSpace(r.Output))
	}
	if err != nil {
		return cleanup, err
	}
	u.env = map[string]string{"CI_CORPUS": dir + "/corpus", "CI_SEEDS": dir + "/seeds"}
	if u.assets.MalwareURL != "" {
		u.env["CI_MALWARE"] = dir + "/malware"
	}
	return cleanup, nil
}

// FetchArtifacts забирає <outDir>/artifacts (yara-<os>-<arch>.tar.gz, логи, summary.txt) у dst.
func (u *Unix) FetchArtifacts(ctx context.Context, dst string) ([]string, error) {
	if err := os.MkdirAll(dst, 0o755); err != nil {
		return nil, err
	}
	r, err := u.t.Run(ctx, fmt.Sprintf("cd %s && COPYFILE_DISABLE=1 tar czf artifacts.tgz -C artifacts .", shq(u.outDir)), nil)
	if err == nil && r.ExitCode != 0 {
		err = fmt.Errorf("pack artifacts: %s", strings.TrimSpace(r.Output))
	}
	if err != nil {
		return nil, err
	}
	data, err := u.t.Download(ctx, u.outDir+"/artifacts.tgz")
	if err != nil {
		return nil, err
	}
	files, err := untar(data, dst)
	if u.local && err == nil {
		os.RemoveAll(u.outDir) // робоча тека (дерево збірки фазерів тощо) більше не потрібна
	}
	return files, err
}

// CollectLogs — після провалу: логи кроків і summary.txt з машини в dst (без бінарників, якщо їх немає).
func (u *Unix) CollectLogs(ctx context.Context, dst string) {
	if u.t == nil || u.outDir == "" {
		return
	}
	u.t.Run(ctx, fmt.Sprintf("mkdir -p %[1]s/artifacts && cp %[1]s/*.log %[1]s/summary.txt %[1]s/artifacts/ 2>/dev/null; true", shq(u.outDir)), nil)
	u.FetchArtifacts(ctx, dst)
}

func (u *Unix) Close() error {
	if u.t != nil {
		return u.t.Close()
	}
	return nil
}

// untar розпаковує tar.gz у dst; шляхи поза dst («../») відхиляються.
func untar(data []byte, dst string) ([]string, error) {
	gz, err := gzip.NewReader(bytes.NewReader(data))
	if err != nil {
		return nil, err
	}
	root := filepath.Clean(dst) + string(os.PathSeparator)
	tr := tar.NewReader(gz)
	var files []string
	for {
		h, err := tr.Next()
		if err == io.EOF {
			return files, nil
		}
		if err != nil {
			return files, err
		}
		if strings.HasPrefix(filepath.Base(h.Name), "._") {
			continue // macOS AppleDouble (extended attributes), not a real file
		}
		p := filepath.Join(dst, h.Name)
		if !strings.HasPrefix(p+string(os.PathSeparator), root) {
			return files, fmt.Errorf("bad path in archive: %s", h.Name)
		}
		switch h.Typeflag {
		case tar.TypeDir:
			os.MkdirAll(p, 0o755)
		case tar.TypeReg:
			os.MkdirAll(filepath.Dir(p), 0o755)
			f, err := os.Create(p)
			if err != nil {
				return files, err
			}
			_, err = io.Copy(f, tr)
			f.Close()
			if err != nil {
				return files, err
			}
			files = append(files, p)
		}
	}
}

// shq бере рядок в одинарні лапки для sh.
func shq(s string) string { return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'" }

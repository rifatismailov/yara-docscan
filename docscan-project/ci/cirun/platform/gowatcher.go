package platform

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
)

// goWatcherDir — модуль Go-watcher-а в репозиторії (cirun працює з кореня репозиторію).
const goWatcherDir = "docscan-project/watcher-go"

// buildGoWatcher збирає docscan-watcher.exe (windows/amd64, без cgo) на цьому Маку з ТОЧНОГО коміту sha:
// git archive теки watcher-go у тимчасову теку -> go vet + go test (модульні тести) -> go build.
// Go для Windows крос-компілюється, тож на Windows-машині Go не потрібен. Повертає exe і вивід.
func buildGoWatcher(ctx context.Context, sha string) ([]byte, string, error) {
	tmp, err := os.MkdirTemp("", "cirun-watcher-go-")
	if err != nil {
		return nil, "", err
	}
	defer os.RemoveAll(tmp)
	log := ""
	run := func(dir string, env []string, name string, args ...string) error {
		cmd := exec.CommandContext(ctx, name, args...)
		cmd.Dir = dir
		cmd.Env = append(os.Environ(), env...)
		out, err := cmd.CombinedOutput()
		log += "$ " + name + " " + fmt.Sprint(args) + "\n" + string(out)
		if err != nil {
			return fmt.Errorf("%s: %w", name, err)
		}
		return nil
	}
	tarFile := filepath.Join(tmp, "src.tar")
	// + the PowerShell watcher: config_test.go checks that both watch the same extensions
	if err := run("", nil, "git", "archive", "--format=tar", "-o", tarFile, sha, goWatcherDir, "docscan-project/watcher"); err != nil {
		return nil, log, err
	}
	if err := run(tmp, nil, "tar", "-xf", tarFile); err != nil {
		return nil, log, err
	}
	src := filepath.Join(tmp, filepath.FromSlash(goWatcherDir))
	if err := run(src, nil, "go", "vet", "./..."); err != nil {
		return nil, log, err
	}
	if err := run(src, nil, "go", "test", "./..."); err != nil {
		return nil, log, err
	}
	exe := filepath.Join(tmp, "docscan-watcher.exe")
	win := []string{"GOOS=windows", "GOARCH=amd64", "CGO_ENABLED=0"}
	if err := run(src, win, "go", "vet", "./..."); err != nil {
		return nil, log, err
	}
	if err := run(src, win, "go", "build", "-trimpath", "-ldflags=-s -w", "-o", exe, "."); err != nil {
		return nil, log, err
	}
	b, err := os.ReadFile(exe)
	return b, log, err
}

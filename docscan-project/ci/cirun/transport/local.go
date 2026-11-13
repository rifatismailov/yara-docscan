package transport

import (
	"bufio"
	"context"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
)

// Local — команди на цьому комп'ютері (sh -c), файли — звичайні файли.
type Local struct{}

// NewLocal створює локальний «транспорт».
func NewLocal() *Local { return &Local{} }

func (l *Local) Where() string { return "local" }
func (l *Local) Close() error  { return nil }

func (l *Local) Run(ctx context.Context, script string, onLine func(string)) (Result, error) {
	cmd := exec.CommandContext(ctx, "sh", "-c", script)
	pr, pw := io.Pipe()
	cmd.Stdout, cmd.Stderr = pw, pw
	var out strings.Builder
	var wg sync.WaitGroup
	wg.Add(1)
	go func() { // збирає вивід і віддає рядки одразу
		defer wg.Done()
		collect(pr, &out, onLine)
	}()
	err := cmd.Start()
	if err == nil {
		err = cmd.Wait()
	}
	pw.Close()
	wg.Wait()
	if err != nil {
		if e, ok := err.(*exec.ExitError); ok {
			return Result{Output: out.String(), ExitCode: e.ExitCode()}, nil
		}
		return Result{Output: out.String()}, err
	}
	return Result{Output: out.String()}, nil
}

func (l *Local) Upload(ctx context.Context, data []byte, remotePath string) error {
	if err := os.MkdirAll(filepath.Dir(remotePath), 0o755); err != nil {
		return err
	}
	return os.WriteFile(remotePath, data, 0o644)
}

func (l *Local) Download(ctx context.Context, remotePath string) ([]byte, error) {
	return os.ReadFile(remotePath)
}

// collect читає потік до кінця: усе — в out, кожен рядок — в onLine (якщо задано).
func collect(r io.Reader, out *strings.Builder, onLine func(string)) {
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 64*1024), 4*1024*1024)
	for sc.Scan() {
		line := sc.Text()
		out.WriteString(line)
		out.WriteByte('\n')
		if onLine != nil {
			onLine(strings.TrimRight(line, "\r"))
		}
	}
	io.Copy(io.Discard, r) // рядок довший за буфер: дочитати, щоб процес не завис
}

package main

// Робота з файлами: читання (BOM, хвіст журналу, JSON), атомарний запис, дописування рядка, копія, sha256, позначка
// «змінено вебом» і журнал служби web.log.

import (
	"bufio"
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

func fileExists(p string) bool {
	st, err := os.Stat(p)
	return err == nil && st.Mode().IsRegular()
}

// noBOM — файли, записані PowerShell 5.1, починаються з UTF-8 BOM.
func noBOM(b []byte) []byte { return bytes.TrimPrefix(b, []byte("\xef\xbb\xbf")) }

func readJSON(f string, v any) bool {
	b, err := os.ReadFile(f)
	return err == nil && json.Unmarshal(noBOM(b), v) == nil
}

func firstLine(file string) string {
	f, err := os.Open(file)
	if err != nil {
		return ""
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	if sc.Scan() {
		return strings.TrimSpace(strings.TrimPrefix(sc.Text(), "\ufeff"))
	}
	return ""
}

// tailLines — останні n рядків файлу (читає не більше 8 МБ з кінця).
func tailLines(file string, n int) []string {
	f, err := os.Open(file)
	if err != nil {
		return nil
	}
	defer f.Close()
	st, _ := f.Stat()
	const max = 8 << 20
	off := int64(0)
	if st.Size() > max {
		off = st.Size() - max
	}
	f.Seek(off, io.SeekStart)
	b, _ := io.ReadAll(f)
	if off > 0 {
		if i := bytes.IndexByte(b, '\n'); i >= 0 {
			b = b[i+1:]
		}
	}
	lines := strings.Split(strings.TrimRight(strings.ReplaceAll(string(b), "\r\n", "\n"), "\n"), "\n")
	if len(lines) == 1 && lines[0] == "" {
		return nil
	}
	if len(lines) > n {
		lines = lines[len(lines)-n:]
	}
	return lines
}

// writeFileAtomic — тимчасовий файл поруч, потім rename (без напівзаписаних файлів).
func writeFileAtomic(path string, b []byte, mode os.FileMode) error {
	tmp := fmt.Sprintf("%s.tmp%d", path, os.Getpid())
	if err := os.WriteFile(tmp, b, mode); err != nil {
		return err
	}
	if err := os.Rename(tmp, path); err != nil {
		os.Remove(tmp)
		return err
	}
	return nil
}

// appendLine — один запис у кінець файлу (O_APPEND: рядок не перемішується з рядками watcher-а).
func appendLine(file string, b []byte) error {
	f, err := os.OpenFile(file, os.O_WRONLY|os.O_CREATE|os.O_APPEND, 0o644)
	if err != nil {
		return err
	}
	_, err = f.Write(b)
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	return err
}

// copyFile — копія без перезапису (dst не повинно існувати).
func copyFile(src, dst string) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()
	out, err := os.OpenFile(dst, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o644)
	if err != nil {
		return err
	}
	if _, err := io.Copy(out, in); err != nil {
		out.Close()
		os.Remove(dst)
		return err
	}
	return out.Close()
}

func fileSHA(p string) (string, error) {
	f, err := os.Open(p)
	if err != nil {
		return "", err
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

func globEscape(s string) string {
	return strings.NewReplacer("[", "[[]", "*", "[*]", "?", "[?]").Replace(s)
}

func baseOf(p string) string { return p[strings.LastIndexAny(p, `\/`)+1:] }

// markWeb — поруч із файлом налаштувань, який щойно записав веб, — <файл>.websha: sha256 вмісту ("-" — видалено).
// Watcher (audit.go) так відрізняє зміну через веб (вона вже має запис аудиту) від зміни в обхід вебу (руками,
// скриптом) — на таку він пише запис "config-changed-outside-web".
func markWeb(path string) {
	sum := "-"
	if b, err := os.ReadFile(path); err == nil {
		h := sha256.Sum256(b)
		sum = hex.EncodeToString(h[:])
	}
	os.WriteFile(path+".websha", []byte(sum+"\n"), 0o644)
}

// ---------------------------------------------------------------- журнал служби (web.log)

type logger struct {
	mu   sync.Mutex
	file string
}

func newLogger(file string) *logger {
	os.MkdirAll(filepath.Dir(file), 0o755)
	return &logger{file: file}
}

// Log — "<yyyy-MM-dd HH:mm:ss> [LEVEL] message" (як watcher.log); 5 МБ, 3 старі копії.
func (l *logger) Log(level, format string, args ...any) {
	line := fmt.Sprintf("%s [%s] %s", time.Now().Format("2006-01-02 15:04:05"), level, fmt.Sprintf(format, args...))
	fmt.Println(line)
	l.mu.Lock()
	defer l.mu.Unlock()
	if st, err := os.Stat(l.file); err == nil && st.Size() >= 5<<20 {
		for k := 2; k >= 1; k-- {
			os.Rename(fmt.Sprintf("%s.%d", l.file, k), fmt.Sprintf("%s.%d", l.file, k+1))
		}
		os.Rename(l.file, l.file+".1")
	}
	appendLine(l.file, []byte(line+"\r\n"))
}

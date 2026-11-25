package main

import (
	"fmt"
	"os"
	"sync"
	"time"
)

// rotate: file -> file.1 -> ... -> file.<keep> (the oldest is dropped), when the file reached maxBytes.
func rotateIfBig(file string, maxBytes int64, keep int) {
	st, err := os.Stat(file)
	if err != nil || st.Size() < maxBytes {
		return
	}
	for k := keep - 1; k >= 1; k-- {
		src := fmt.Sprintf("%s.%d", file, k)
		if exists(src) {
			os.Rename(src, fmt.Sprintf("%s.%d", file, k+1))
		}
	}
	os.Rename(file, file+".1")
}

// appender: one writer for a log-like file (watcher.log, docscan-results.json) shared by all goroutines.
type appender struct {
	mu       sync.Mutex
	file     string
	maxBytes int64
	keep     int
}

func (a *appender) append(b []byte) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	rotateIfBig(a.file, a.maxBytes, a.keep)
	f, err := os.OpenFile(a.file, os.O_WRONLY|os.O_CREATE|os.O_APPEND, 0o644)
	if err != nil {
		return err
	}
	_, err = f.Write(b)
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	return err
}

// Logger: "<yyyy-MM-dd HH:mm:ss> [LEVEL] message" lines (the PowerShell watcher's format: the CI checks and the
// load-test report read it), to watcher.log and the console.
type Logger struct{ a *appender }

func (l *Logger) Log(level, format string, args ...any) {
	line := fmt.Sprintf("%s [%s] %s", time.Now().Format("2006-01-02 15:04:05"), level, fmt.Sprintf(format, args...))
	fmt.Println(line)
	if l.a != nil {
		if err := l.a.append([]byte(line + "\r\n")); err != nil {
			fmt.Fprintln(os.Stderr, "watcher.log:", err)
		}
	}
}

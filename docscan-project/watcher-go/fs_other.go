//go:build !windows

package main

// Non-Windows build: only for developing and testing the pipeline on a Mac / Linux (polling instead of change
// notifications). DocScan itself runs on Windows.

import (
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"sync/atomic"
	"time"
)

func hideWindow(cmd *exec.Cmd) {}
func fileLocked(p string) bool { return false }
func archiveBit(p string) bool { return false }

func ansiToUTF8(b []byte) string { // Latin-1
	r := make([]rune, len(b))
	for i, c := range b {
		r[i] = rune(c)
	}
	return string(r)
}

func watchTree(root string, out chan<- fsEvent, overflow *atomic.Bool, log *Logger) error {
	if _, err := os.Stat(root); err != nil {
		return err
	}
	type st struct {
		size int64
		mod  time.Time
	}
	seen := map[string]st{}
	walk := func(emit bool) {
		now := time.Now()
		filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
			if err != nil || d.IsDir() {
				return nil
			}
			inf, err := d.Info()
			if err != nil {
				return nil
			}
			cur := st{inf.Size(), inf.ModTime()}
			old, ok := seen[p]
			seen[p] = cur
			if !emit || (ok && old == cur) {
				return nil
			}
			evt := "Changed"
			if !ok {
				evt = "Created"
			}
			select {
			case out <- fsEvent{path: p, evt: evt, t: now}:
			default:
				overflow.Store(true)
			}
			return nil
		})
	}
	walk(false)
	go func() {
		for {
			time.Sleep(500 * time.Millisecond)
			walk(true)
		}
	}()
	return nil
}

func hostName() string { h, _ := os.Hostname(); return h }

type cpuMeter struct{}

func (m *cpuMeter) busy() float64 { return -1 } // unknown: the pool then scales on the queue only

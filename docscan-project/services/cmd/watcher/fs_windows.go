//go:build windows

package main

import (
	"os"
	"os/exec"
	"path/filepath"
	"sync/atomic"
	"syscall"
	"time"
	"unicode/utf16"
	"unsafe"
)

const (
	createNoWindow      = 0x08000000
	belowNormalPriority = 0x00004000          // yara64 (and its sandbox worker, which inherits it) yield to the users' programs
	errorNotifyEnumDir  = syscall.Errno(1022) // ERROR_NOTIFY_ENUM_DIR: the change buffer overflowed
	fileActionAdded     = 1
	fileActionModified  = 3
	fileActionRenamedTo = 5
	notifyBufBytes      = 1 << 20 // 1 MB: local volumes allow more than the 64 KB of a network share
)

func hideWindow(cmd *exec.Cmd) {
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true, CreationFlags: createNoWindow | belowNormalPriority}
}

// open for read/write with no sharing: fails while another program (Word) holds the file
func fileLocked(p string) bool {
	u, err := syscall.UTF16PtrFromString(p)
	if err != nil {
		return false
	}
	h, err := syscall.CreateFile(u, syscall.GENERIC_READ|syscall.GENERIC_WRITE, 0, nil, syscall.OPEN_EXISTING, syscall.FILE_ATTRIBUTE_NORMAL, 0)
	if err != nil {
		return isFile(p)
	}
	syscall.CloseHandle(h)
	return false
}

func archiveBit(p string) bool {
	u, err := syscall.UTF16PtrFromString(p)
	if err != nil {
		return false
	}
	a, err := syscall.GetFileAttributes(u)
	return err == nil && a&syscall.FILE_ATTRIBUTE_ARCHIVE != 0
}

var (
	kernel32                = syscall.NewLazyDLL("kernel32.dll")
	procMultiByteToWideChar = kernel32.NewProc("MultiByteToWideChar")
	procGetSystemTimes      = kernel32.NewProc("GetSystemTimes")
)

// cpuMeter: busy % of the whole machine between two calls (GetSystemTimes: kernel time includes idle)
type cpuMeter struct {
	idle, total uint64
	ok          bool
}

func (m *cpuMeter) busy() float64 {
	var idle, kernel, user syscall.Filetime
	if r, _, _ := procGetSystemTimes.Call(uintptr(unsafe.Pointer(&idle)), uintptr(unsafe.Pointer(&kernel)), uintptr(unsafe.Pointer(&user))); r == 0 {
		return -1
	}
	ft := func(f syscall.Filetime) uint64 { return uint64(f.HighDateTime)<<32 | uint64(f.LowDateTime) }
	i, t := ft(idle), ft(kernel)+ft(user)
	defer func() { m.idle, m.total, m.ok = i, t, true }()
	if !m.ok || t <= m.total {
		return -1
	}
	return 100 * (1 - float64(i-m.idle)/float64(t-m.total))
}

// bytes in this PC's ANSI code page (CP_ACP) -> UTF-8
func ansiToUTF8(b []byte) string {
	if len(b) == 0 {
		return ""
	}
	n, _, _ := procMultiByteToWideChar.Call(0, 0, uintptr(unsafe.Pointer(&b[0])), uintptr(len(b)), 0, 0)
	if n == 0 {
		return string(b)
	}
	w := make([]uint16, n)
	procMultiByteToWideChar.Call(0, 0, uintptr(unsafe.Pointer(&b[0])), uintptr(len(b)), uintptr(unsafe.Pointer(&w[0])), n)
	return string(utf16.Decode(w))
}

// watchTree: ReadDirectoryChangesW on root (recursive) in its own goroutine. It only reads the kernel buffer and
// hands the names on - nothing slow happens here, so the buffer does not overflow while files are scanned.
// Lost events (overflow, or a full channel) set *overflow: the coordinator then rescans the folders.
func watchTree(root string, out chan<- fsEvent, overflow *atomic.Bool, log *Logger) error {
	u, err := syscall.UTF16PtrFromString(root)
	if err != nil {
		return err
	}
	open := func() (syscall.Handle, error) {
		return syscall.CreateFile(u, syscall.FILE_LIST_DIRECTORY,
			syscall.FILE_SHARE_READ|syscall.FILE_SHARE_WRITE|syscall.FILE_SHARE_DELETE,
			nil, syscall.OPEN_EXISTING, syscall.FILE_FLAG_BACKUP_SEMANTICS, 0)
	}
	h, err := open()
	if err != nil {
		return err
	}
	go func() {
		buf := make([]byte, notifyBufBytes)
		mask := uint32(syscall.FILE_NOTIFY_CHANGE_FILE_NAME | syscall.FILE_NOTIFY_CHANGE_LAST_WRITE | syscall.FILE_NOTIFY_CHANGE_SIZE)
		for {
			var n uint32
			err := syscall.ReadDirectoryChanges(h, &buf[0], uint32(len(buf)), true, mask, &n, nil, 0)
			if err == errorNotifyEnumDir || (err == nil && n == 0) {
				overflow.Store(true)
				continue
			}
			if err != nil {
				log.Log("ERROR", "change notifications for %s stopped: %v - reopening in 5 s", root, err)
				syscall.CloseHandle(h)
				for {
					time.Sleep(5 * time.Second)
					if h, err = open(); err == nil {
						break
					}
				}
				overflow.Store(true) // changes while the handle was closed are unknown
				continue
			}
			now := time.Now()
			off := uint32(0)
			for {
				rec := (*struct {
					Next, Action, NameLen uint32
				})(unsafe.Pointer(&buf[off]))
				name := unsafe.Slice((*uint16)(unsafe.Pointer(&buf[off+12])), rec.NameLen/2)
				evt := ""
				switch rec.Action {
				case fileActionAdded:
					evt = "Created"
				case fileActionModified:
					evt = "Changed"
				case fileActionRenamedTo:
					evt = "Renamed"
				}
				if evt != "" {
					select {
					case out <- fsEvent{path: filepath.Join(root, string(utf16.Decode(name))), evt: evt, t: now}:
					default:
						overflow.Store(true)
					}
				}
				if rec.Next == 0 {
					break
				}
				off += rec.Next
			}
		}
	}()
	return nil
}

func hostName() string {
	if h := os.Getenv("COMPUTERNAME"); h != "" {
		return h
	}
	h, _ := os.Hostname()
	return h
}

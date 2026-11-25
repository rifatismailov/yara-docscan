//go:build !windows

package drives

import (
	"os"
	"path/filepath"
	"sync"
)

var (
	mu   sync.Mutex
	fake []Drive
)

// List — не Windows (розробка і тести на Mac / Linux): "/" як fixed + те, що задав тест (SetFake).
// Змінна DOCSCAN_FAKE_USB=<тека> додає її як USB-носій (ручна перевірка на Mac).
func List() []Drive {
	mu.Lock()
	defer mu.Unlock()
	if fake != nil {
		return append([]Drive(nil), fake...)
	}
	out := []Drive{{Root: "/", Kind: "fixed", FS: "apfs", System: true}}
	if d := os.Getenv("DOCSCAN_FAKE_USB"); d != "" {
		if st, err := os.Stat(d); err == nil && st.IsDir() {
			out = append(out, Drive{Root: filepath.Clean(d) + "/", Kind: "usb", Label: "FAKE", Serial: 1})
		}
	}
	return out
}

// SetFake — для тестів: List повертає саме це (nil — звичайна поведінка).
func SetFake(d []Drive) {
	mu.Lock()
	fake = d
	mu.Unlock()
}

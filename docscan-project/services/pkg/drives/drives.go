// Package drives — диски цього ПК для сканування: літера, тип (fixed / usb / removable / network / cdrom),
// мітка, серійний номер тому, лише читання. USB визначається за шиною пристрою (IOCTL_STORAGE_QUERY_PROPERTY,
// BusType USB / SD / MMC), тож зовнішній USB-диск, який Windows показує як «локальний диск», теж USB.
// Спільний для docscan-watcher (авто-скан флешок, повний скан) і docscan-web (сторінка «Сканування»).
package drives

// Опис: docscan-project/DOCSCAN.md#architecture — диски, USB, теки програм (спільне для watcher і вебу).

import (
	"fmt"
	"regexp"
	"strings"
)

// Drive — один том з літерою.
type Drive struct {
	Root     string  `json:"root"`  // E:\
	Kind     string  `json:"kind"`  // fixed | usb | removable | network | cdrom | other
	Label    string  `json:"label"` // мітка тому
	Serial   uint32  `json:"serial"`
	FS       string  `json:"fs"`
	ReadOnly bool    `json:"read_only"`
	System   bool    `json:"system"` // диск з Windows (%SystemDrive%): цілим — лише скан документів
	SizeGB   float64 `json:"size_gb"`
	FreeGB   float64 `json:"free_gb"`
}

// Removable — знімний носій (флешка, зовнішній USB-диск, SD-картка).
func (d Drive) Removable() bool { return d.Kind == "usb" || d.Kind == "removable" }

// Key — той самий носій: літера + серійний номер тому (інша флешка в тому ж гнізді — інший ключ).
func (d Drive) Key() string { return fmt.Sprintf("%s|%08X", d.Root, d.Serial) }

// Name — для журналу і вебу: "E:\ (USB, KINGSTON, лише читання)".
func (d Drive) Name() string {
	s := d.Root + " (" + map[string]string{"usb": "USB", "removable": "знімний", "fixed": "локальний",
		"network": "мережевий", "cdrom": "CD/DVD", "other": "інший"}[d.Kind]
	if d.Label != "" {
		s += ", " + d.Label
	}
	if d.ReadOnly {
		s += ", лише читання"
	}
	return s + ")"
}

// IsRoot — p є коренем диска з all, для якого ok(d) (C:\ і C: — те саме).
func IsRoot(p string, all []Drive, ok func(Drive) bool) bool {
	t := strings.TrimRight(p, `\/`)
	for _, d := range all {
		if ok(d) && strings.EqualFold(t, strings.TrimRight(d.Root, `\/`)) {
			return true
		}
	}
	return false
}

// Fixed — локальні диски для скану документів (без USB).
func Fixed(all []Drive) []string {
	var o []string
	for _, d := range all {
		if d.Kind == "fixed" {
			o = append(o, d.Root)
		}
	}
	return o
}

// protected — системні й програмні теки: скан документів їх не обходить, а файл у них будь-який скан лише повідомляє
// (без знешкодження і карантину). Windows: C:\Windows, Program Files і Program Files (x86) на будь-якому диску, ProgramData\Microsoft, кошик,
// System Volume Information, Recovery, AppData\Local\Programs (програми користувача: VS Code, Teams...).
// Mac / Linux (розробка): /System, /Applications, /Library і ~/Library, /usr, /opt, /Volumes, *.app (без /var: там тимчасові теки тестів).
var protected = regexp.MustCompile(`(?i)(^[a-z]:\\(Windows|Program Files|Program Files \(x86\)|ProgramData\\Microsoft|\$Recycle\.Bin|System Volume Information|Recovery|PerfLogs)(\\|$)` +
	`|\\AppData\\Local\\Programs(\\|$)` +
	`|^/(System|Applications|Library|usr|bin|sbin|opt|dev|proc|sys|Volumes|cores)(/|$)|/Library(/|$)|\.app(/|$))`)

// Protected — p лежить у системній / програмній теці.
func Protected(p string) bool { return protected.MatchString(p) }

//go:build windows

package drives

import (
	"os"
	"strings"
	"syscall"
	"unsafe"
)

var (
	k32                  = syscall.NewLazyDLL("kernel32.dll")
	procGetLogicalDrives = k32.NewProc("GetLogicalDrives")
	procGetDriveType     = k32.NewProc("GetDriveTypeW")
	procGetVolumeInfo    = k32.NewProc("GetVolumeInformationW")
	procGetDiskFree      = k32.NewProc("GetDiskFreeSpaceExW")
	procSetErrorMode     = k32.NewProc("SetErrorMode")
)

const (
	driveRemovable = 2
	driveFixed     = 3
	driveRemote    = 4
	driveCDROM     = 5

	fileReadOnlyVolume = 0x00080000

	ioctlStorageQueryProperty = 0x002D1400
	busUsb, busSd, busMmc     = 7, 0x0C, 0x0D
)

// List — усі томи з літерою зараз. Порожній кардрідер (немає носія) не повертається.
func List() []Drive {
	// без вікна "Вставте диск у пристрій" для порожнього кардрідера
	procSetErrorMode.Call(0x0001 | 0x8000) // SEM_FAILCRITICALERRORS | SEM_NOOPENFILEERRORBOX
	mask, _, _ := procGetLogicalDrives.Call()
	var out []Drive
	for i := 0; i < 26; i++ {
		if mask&(1<<i) == 0 {
			continue
		}
		root := string(rune('A'+i)) + `:\`
		r16, _ := syscall.UTF16PtrFromString(root)
		t, _, _ := procGetDriveType.Call(uintptr(unsafe.Pointer(r16)))
		d := Drive{Root: root}
		switch t {
		case driveFixed:
			d.Kind = "fixed"
		case driveRemovable:
			d.Kind = "removable"
		case driveRemote:
			d.Kind = "network"
		case driveCDROM:
			d.Kind = "cdrom"
		default:
			continue // немає тому / RAM-диск / невідомо
		}
		var label, fsName [261]uint16
		var serial, maxLen, flags uint32
		ok, _, _ := procGetVolumeInfo.Call(uintptr(unsafe.Pointer(r16)), uintptr(unsafe.Pointer(&label[0])), 261,
			uintptr(unsafe.Pointer(&serial)), uintptr(unsafe.Pointer(&maxLen)), uintptr(unsafe.Pointer(&flags)),
			uintptr(unsafe.Pointer(&fsName[0])), 261)
		if ok == 0 {
			if d.Kind != "network" {
				continue // носія немає
			}
		}
		d.Label, d.FS, d.Serial = syscall.UTF16ToString(label[:]), syscall.UTF16ToString(fsName[:]), serial
		d.ReadOnly = flags&fileReadOnlyVolume != 0
		var free, total, totalFree uint64
		if r, _, _ := procGetDiskFree.Call(uintptr(unsafe.Pointer(r16)), uintptr(unsafe.Pointer(&free)),
			uintptr(unsafe.Pointer(&total)), uintptr(unsafe.Pointer(&totalFree))); r != 0 {
			d.SizeGB, d.FreeGB = float64(total)/(1<<30), float64(free)/(1<<30)
		}
		if (d.Kind == "fixed" || d.Kind == "removable") && usbBus(root[:2]) {
			d.Kind = "usb"
		}
		d.System = strings.EqualFold(root[:2], sysDrive())
		out = append(out, d)
	}
	return out
}

// usbBus — пристрій тому на шині USB / SD / MMC (зовнішній диск Windows показує як fixed).
func usbBus(letter string) bool {
	p, _ := syscall.UTF16PtrFromString(`\\.\` + letter)
	h, err := syscall.CreateFile(p, 0, syscall.FILE_SHARE_READ|syscall.FILE_SHARE_WRITE, nil, syscall.OPEN_EXISTING, 0, 0)
	if err != nil {
		return false
	}
	defer syscall.CloseHandle(h)
	query := [3]uint32{0, 0, 0} // StorageDeviceProperty, PropertyStandardQuery, AdditionalParameters
	var buf [1024]byte
	var n uint32
	if err := syscall.DeviceIoControl(h, ioctlStorageQueryProperty, (*byte)(unsafe.Pointer(&query[0])), 12,
		&buf[0], uint32(len(buf)), &n, nil); err != nil || n < 32 {
		return false
	}
	bus := *(*uint32)(unsafe.Pointer(&buf[28])) // STORAGE_DEVICE_DESCRIPTOR.BusType
	return bus == busUsb || bus == busSd || bus == busMmc
}

// sysDrive — "C:" (диск з Windows).
func sysDrive() string {
	if s := os.Getenv("SystemDrive"); len(s) == 2 {
		return s
	}
	return "C:"
}

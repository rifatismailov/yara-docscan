//go:build windows

package main

// Хто з користувачів Windows відкрив веб: на термінальному сервері 127.0.0.1:8741 доступний кожному, хто там
// працює, тож у записі аудиту мало «admin» — потрібен ще обліковий запис Windows. З'єднання браузера знаходимо в
// таблиці TCP (GetExtendedTcpTable: локальний порт = порт клієнта запиту, віддалений = порт вебу), беремо процес
// і власника його токена (веб працює від SYSTEM — відкрити можна будь-який процес).

import (
	"net"
	"strconv"
	"unsafe"

	"golang.org/x/sys/windows"
)

var (
	iphlpapi            = windows.NewLazySystemDLL("iphlpapi.dll")
	procGetExtTcpTable  = iphlpapi.NewProc("GetExtendedTcpTable")
	tcpTableOwnerPIDAll = uintptr(5)
)

// winUser — DOMAIN\user процесу, що відкрив з'єднання remote (адреса клієнта запиту) до порту вебу port;
// "" — не вдалося визначити.
func winUser(remote string, port int) string {
	h, ps, err := net.SplitHostPort(remote)
	if err != nil {
		return ""
	}
	cp, _ := strconv.Atoi(ps)
	ip := net.ParseIP(h)
	if ip == nil || cp == 0 {
		return ""
	}
	pid := uint32(0)
	if ip.To4() != nil {
		pid = ownerPID(windows.AF_INET, cp, port)
	} else {
		pid = ownerPID(windows.AF_INET6, cp, port)
	}
	if pid == 0 {
		return ""
	}
	return processUser(pid)
}

func ntohs(v uint32) int { return int((v&0xff)<<8 | (v>>8)&0xff) }

// ownerPID — PID процесу з локальним портом local і віддаленим remote (сторона клієнта з'єднання).
func ownerPID(family int, local, remote int) uint32 {
	var size uint32
	procGetExtTcpTable.Call(0, uintptr(unsafe.Pointer(&size)), 0, uintptr(family), tcpTableOwnerPIDAll, 0)
	if size == 0 {
		return 0
	}
	buf := make([]byte, size+1024)
	size = uint32(len(buf))
	r, _, _ := procGetExtTcpTable.Call(uintptr(unsafe.Pointer(&buf[0])), uintptr(unsafe.Pointer(&size)), 0, uintptr(family), tcpTableOwnerPIDAll, 0)
	if r != 0 {
		return 0
	}
	n := *(*uint32)(unsafe.Pointer(&buf[0]))
	if family == windows.AF_INET {
		// MIB_TCPROW_OWNER_PID: state, localAddr, localPort, remoteAddr, remotePort, pid (6 x uint32)
		const row = 24
		for i := uint32(0); i < n; i++ {
			off := 4 + int(i)*row
			if off+row > len(buf) {
				break
			}
			f := (*[6]uint32)(unsafe.Pointer(&buf[off]))
			if ntohs(f[2]) == local && ntohs(f[4]) == remote {
				return f[5]
			}
		}
		return 0
	}
	// MIB_TCP6ROW_OWNER_PID: localAddr[16], localScope, localPort, remoteAddr[16], remoteScope, remotePort, state, pid
	const row = 56
	for i := uint32(0); i < n; i++ {
		off := 4 + int(i)*row
		if off+row > len(buf) {
			break
		}
		lp := *(*uint32)(unsafe.Pointer(&buf[off+20]))
		rp := *(*uint32)(unsafe.Pointer(&buf[off+44]))
		if ntohs(lp) == local && ntohs(rp) == remote {
			return *(*uint32)(unsafe.Pointer(&buf[off+52]))
		}
	}
	return 0
}

func processUser(pid uint32) string {
	h, err := windows.OpenProcess(windows.PROCESS_QUERY_LIMITED_INFORMATION, false, pid)
	if err != nil {
		return ""
	}
	defer windows.CloseHandle(h)
	var tok windows.Token
	if err := windows.OpenProcessToken(h, windows.TOKEN_QUERY, &tok); err != nil {
		return ""
	}
	defer tok.Close()
	u, err := tok.GetTokenUser()
	if err != nil {
		return ""
	}
	name, dom, _, err := u.User.Sid.LookupAccount("")
	if err != nil {
		return u.User.Sid.String()
	}
	return dom + `\` + name
}

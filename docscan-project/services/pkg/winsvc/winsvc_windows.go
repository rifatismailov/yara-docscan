//go:build windows

// Package winsvc — служба Windows для docscan-watcher і docscan-updater.
package winsvc

// install.ps1 реєструє docscan-watcher.exe (DocScanWatcher) і docscan-updater.exe (DocScanUpdater) як служби (автозапуск, SYSTEM, перезапуск після
// збою). Service Control Manager запускає exe з тими самими параметрами, що й з консолі (вони в ImagePath служби).
// Тут — лише розмова з SCM: «запущено», «зупиняюся», код виходу. Ініціалізація (компіляція тисяч правил триває
// хвилину і довше) іде вже після «запущено»: SCM чекає на StartServiceCtrlDispatcher лише ~30 с.

import (
	"os"
	"syscall"

	"golang.org/x/sys/windows/svc"
)

// Run: якщо exe запустив SCM — працює як служба name (body отримує канал зупинки) і повертає (true, код виходу);
// інакше — (false, 0), і main працює як звичайна консольна програма.
func Run(name string, body func(stop <-chan os.Signal) int) (bool, int) {
	is, err := svc.IsWindowsService()
	if err != nil || !is {
		return false, 0
	}
	h := &service{body: body}
	if err := svc.Run(name, h); err != nil {
		return true, 1
	}
	return true, h.code
}

// StopReason — чому служба зупиняється: stop (команда служби) | shutdown (вимкнення Windows); порожньо — консоль.
var StopReason string

type service struct {
	body func(stop <-chan os.Signal) int
	code int
}

func (s *service) Execute(_ []string, req <-chan svc.ChangeRequest, st chan<- svc.Status) (bool, uint32) {
	st <- svc.Status{State: svc.StartPending}
	stop := make(chan os.Signal, 1)
	done := make(chan int, 1)
	go func() { done <- s.body(stop) }()
	st <- svc.Status{State: svc.Running, Accepts: svc.AcceptStop | svc.AcceptShutdown}
	for {
		select {
		case s.code = <-done:
			// сам завершився (помилка запуску: правила не компілюються, немає теки) — ненульовий код =
			// збій служби, SCM перезапустить її за діями відновлення (sc failure / failureflag)
			return s.code != 0, uint32(s.code)
		case c := <-req:
			switch c.Cmd {
			case svc.Interrogate:
				st <- c.CurrentStatus
			case svc.Stop, svc.Shutdown:
				StopReason = map[bool]string{true: "shutdown", false: "stop"}[c.Cmd == svc.Shutdown]
				st <- svc.Status{State: svc.StopPending}
				stop <- syscall.SIGTERM
				s.code = <-done
				return false, 0
			}
		}
	}
}

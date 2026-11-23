//go:build windows

package main

import (
	"fmt"
	"time"

	"golang.org/x/sys/windows/svc"
	"golang.org/x/sys/windows/svc/mgr"
)

var svcNames = []string{"DocScanWatcher", "DocScanUpdater", "DocScanWeb", "WazuhSvc"}

// services — стан служб DocScan і агента Wazuh.
func services() []svcState {
	m, err := mgr.Connect()
	if err != nil {
		return []svcState{{Name: "-", State: "cannot read: " + err.Error()}}
	}
	defer m.Disconnect()
	var out []svcState
	for _, n := range svcNames {
		st := svcState{Name: n, State: "not installed"}
		if s, err := m.OpenService(n); err == nil {
			if q, err := s.Query(); err == nil {
				st.State = stateName(q.State)
			}
			if c, err := s.Config(); err == nil {
				st.Display = c.DisplayName
				st.Start = map[uint32]string{mgr.StartAutomatic: "auto", mgr.StartManual: "manual", mgr.StartDisabled: "disabled"}[c.StartType]
			}
			s.Close()
		}
		out = append(out, st)
	}
	return out
}

// restartService — зупинити (до 30 с) і запустити службу.
func restartService(name string) error {
	m, err := mgr.Connect()
	if err != nil {
		return err
	}
	defer m.Disconnect()
	s, err := m.OpenService(name)
	if err != nil {
		return err
	}
	defer s.Close()
	if q, err := s.Query(); err == nil && q.State != svc.Stopped {
		if _, err := s.Control(svc.Stop); err != nil {
			return fmt.Errorf("stop: %w", err)
		}
		for i := 0; i < 60; i++ {
			time.Sleep(500 * time.Millisecond)
			if q, err := s.Query(); err == nil && q.State == svc.Stopped {
				break
			}
		}
	}
	return s.Start()
}

func serviceCommand(name string) string {
	m, err := mgr.Connect()
	if err != nil {
		return ""
	}
	defer m.Disconnect()
	s, err := m.OpenService(name)
	if err != nil {
		return ""
	}
	defer s.Close()
	c, err := s.Config()
	if err != nil {
		return ""
	}
	return c.BinaryPathName
}

func stateName(s svc.State) string {
	switch s {
	case svc.Running:
		return "running"
	case svc.Stopped:
		return "stopped"
	case svc.StartPending:
		return "starting"
	case svc.StopPending:
		return "stopping"
	case svc.Paused:
		return "paused"
	}
	return "unknown"
}

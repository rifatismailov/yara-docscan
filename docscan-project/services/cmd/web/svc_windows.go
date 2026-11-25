//go:build windows

package main

import (
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

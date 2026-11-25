//go:build windows

package main

import (
	"fmt"
	"time"

	"golang.org/x/sys/windows/svc"
	"golang.org/x/sys/windows/svc/mgr"
)

// winServices — Service Control Manager (служба працює від SYSTEM).
type winServices struct{}

func (winServices) Stop(name string) error {
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
	st, err := s.Query()
	if err != nil {
		return err
	}
	if st.State == svc.Stopped {
		return nil
	}
	if _, err := s.Control(svc.Stop); err != nil {
		return err
	}
	for i := 0; i < 60; i++ { // до 30 с: watcher дописує чергу й виходить
		time.Sleep(500 * time.Millisecond)
		if st, err = s.Query(); err == nil && st.State == svc.Stopped {
			return nil
		}
	}
	return fmt.Errorf("%s did not stop in 30 s", name)
}

func (winServices) Start(name string) error {
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
	if st, err := s.Query(); err == nil && st.State == svc.Running {
		return nil
	}
	return s.Start()
}

func newServices() services { return winServices{} }

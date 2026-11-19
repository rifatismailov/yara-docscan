//go:build !windows

package main

import "fmt"

type noServices struct{}

func (noServices) Stop(string) error  { return fmt.Errorf("services: Windows only") }
func (noServices) Start(string) error { return fmt.Errorf("services: Windows only") }

func newServices() services { return noServices{} }

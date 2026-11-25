//go:build !windows

package main

import "fmt"

// macOS / Linux (тести, розробка): служб Windows немає.
func services() []svcState { return []svcState{{Name: "-", State: "not Windows"}} }

func serviceCommand(string) string { return "" }

func restartService(name string) error { return fmt.Errorf("not Windows: restart %s by hand", name) }

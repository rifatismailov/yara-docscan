//go:build !windows

package main

// macOS / Linux (тести, розробка): служб Windows немає.
func services() []svcState { return []svcState{{Name: "-", State: "not Windows"}} }

func serviceCommand(string) string { return "" }

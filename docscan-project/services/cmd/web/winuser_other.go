//go:build !windows

package main

// winUser — лише Windows (winuser_windows.go); на Маку / Linux (розробка) — порожньо.
func winUser(remote string, port int) string { return "" }

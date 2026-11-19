//go:build !windows

package winsvc

import "os"

// поза Windows служби немає: main працює як звичайна програма
func Run(string, func(stop <-chan os.Signal) int) (bool, int) { return false, 0 }

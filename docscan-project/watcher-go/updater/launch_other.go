//go:build !windows

package main

import "fmt"

// поза Windows інсталятора немає (updater — лише для Windows; тут — щоб збирались тести)
func launchInstaller(pkgDir, resultFile, logFile string, extra ...string) error {
	return fmt.Errorf("install.ps1 runs on Windows only")
}

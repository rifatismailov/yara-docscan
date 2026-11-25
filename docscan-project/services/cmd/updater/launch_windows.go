//go:build windows

package main

import (
	"os"
	"os/exec"
	"path/filepath"
	"syscall"
)

const (
	createNoWindow         = 0x08000000 // своя прихована консоль: powershell.exe без консолі (DETACHED_PROCESS) не стартує
	createNewProcessGroup  = 0x00000200
	createBreakawayFromJob = 0x01000000
)

// launchInstaller — powershell install.ps1 -Reuse -ResultFile з теки пакета, від'єднано від служби: інсталятор
// зупиняє DocScanUpdater (цей процес), замінює файли і запускає службу знову — сам він має жити далі.
func launchInstaller(pkgDir, resultFile, logFile string, extra ...string) error {
	ps := filepath.Join(os.Getenv("SystemRoot"), `System32\WindowsPowerShell\v1.0\powershell.exe`)
	out, err := os.Create(logFile)
	if err != nil {
		return err
	}
	defer out.Close()
	start := func(flags uint32) error {
		args := append([]string{"-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass",
			"-File", filepath.Join(pkgDir, "install.ps1"), "-Reuse", "-ResultFile", resultFile}, extra...)
		cmd := exec.Command(ps, args...)
		cmd.Dir = pkgDir
		cmd.Stdout, cmd.Stderr = out, out
		cmd.SysProcAttr = &syscall.SysProcAttr{CreationFlags: flags, HideWindow: true}
		if err := cmd.Start(); err != nil {
			return err
		}
		return cmd.Process.Release()
	}
	// поза job object служби (якщо він є), щоб зупинка служби не вбила інсталятор; job без дозволу — без цього прапорця
	if err := start(createNoWindow | createNewProcessGroup | createBreakawayFromJob); err != nil {
		return start(createNoWindow | createNewProcessGroup)
	}
	return nil
}

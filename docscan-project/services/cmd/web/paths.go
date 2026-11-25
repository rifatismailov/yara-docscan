package main

// Усі файли й теки, з якими працює веб: <DataDir> (C:\ProgramData\DocScan) і <InstallDir> (C:\Program Files\DocScan).
// Опис: docscan-project/DOCSCAN.md#web.

import "path/filepath"

type paths struct {
	data, install string
}

// web\ — сертифікат, пароль
func (p paths) web() string       { return filepath.Join(p.data, "web") }
func (p paths) certPEM() string   { return filepath.Join(p.web(), "cert.pem") }
func (p paths) certDER() string   { return filepath.Join(p.web(), "cert.cer") }
func (p paths) keyPEM() string    { return filepath.Join(p.web(), "key.pem") }
func (p paths) authFile() string  { return filepath.Join(p.web(), "auth.json") }
func (p paths) initialPw() string { return filepath.Join(p.web(), "initial-password.txt") }

// results\ — записи для Wazuh і журнали служб
func (p paths) results() string    { return filepath.Join(p.data, "results") }
func (p paths) resultsLog() string { return filepath.Join(p.results(), "docscan-results.json") }
func (p paths) updatesLog() string { return filepath.Join(p.results(), "docscan-updates.json") }
func (p paths) webLog() string     { return filepath.Join(p.results(), "web.log") }

// налаштування, які читають служби
func (p paths) settingsFile() string { return filepath.Join(p.data, "settings.json") }
func (p paths) installJSON() string  { return filepath.Join(p.data, "install.json") }
func (p paths) updaterJSON() string  { return filepath.Join(p.data, "update", "updater.json") }
func (p paths) checkNow() string     { return filepath.Join(p.data, "update", "check-now") }

// списки, карантин, скани, макроси
func (p paths) listsDir() string   { return filepath.Join(p.data, "lists") }
func (p paths) quarantine() string { return filepath.Join(p.data, "quarantine") }
func (p paths) scanDir() string    { return filepath.Join(p.data, "scan") }
func (p paths) macroDir() string   { return filepath.Join(p.data, "macros") }

// listFile — файл списку: kind white | black, local — цього ПК (інакше — з дзеркала організації).
func (p paths) listFile(kind string, local bool) string {
	n := kind + "list"
	if local {
		n += ".local"
	}
	return filepath.Join(p.listsDir(), n+".json")
}

// програма
func (p paths) programVersion() string { return filepath.Join(p.install, "VERSION.txt") }
func (p paths) rulesDir() string       { return filepath.Join(p.install, "rules") }
func (p paths) updaterExe() string     { return filepath.Join(p.install, "updater", "docscan-updater.exe") }

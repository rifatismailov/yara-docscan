package main

// Локальна політика ПК (веб-інтерфейс; опис: docscan-project/DOCSCAN.md#updater): <DataDir>\policy\docscan-policy.yar. Після кожного
// оновлення правил вона знову стає <InstallDir>\rules\docscan-policy.yar, а пакетна лишається поруч як
// docscan-policy.package.yar (веб показує різницю). Не компілюється з новими правилами — діє пакетна, у записі
// оновлення пояснення (захист не вимикається через локальну правку).

import (
	"fmt"
	"os"
	"path/filepath"
)

const (
	policyName        = "docscan-policy.yar"
	policyPackageName = "docscan-policy.package.yar"
)

func (u *Updater) localPolicy() string { return filepath.Join(u.dataDir, "policy", policyName) }

// applyLocalPolicy — у підготовлену теку правил dir (уже скомпільовану з пакетною політикою). Повертає примітку
// для запису оновлення ("" — локальної політики немає або вона застосована без проблем).
func (u *Updater) applyLocalPolicy(dir string) string {
	local, err := os.ReadFile(u.localPolicy())
	if err != nil {
		return ""
	}
	cur := filepath.Join(dir, policyName)
	pkg, err := os.ReadFile(cur)
	if err != nil {
		return "local policy not applied: " + err.Error()
	}
	if err := os.WriteFile(filepath.Join(dir, policyPackageName), pkg, 0o644); err != nil {
		return "local policy not applied: " + err.Error()
	}
	if err := os.WriteFile(cur, local, 0o644); err != nil {
		return "local policy not applied: " + err.Error()
	}
	if err := u.compileRules(dir); err != nil {
		os.WriteFile(cur, pkg, 0o644)
		os.Remove(filepath.Join(dir, policyPackageName))
		msg := fmt.Sprintf("the local policy (%s) does not compile with these rules - the package policy is in force: %v", u.localPolicy(), err)
		u.log.Log("WARN", "%s", msg)
		return msg
	}
	u.log.Log("INFO", "local policy applied (%s); the package policy is kept as %s", u.localPolicy(), policyPackageName)
	return "local policy applied"
}

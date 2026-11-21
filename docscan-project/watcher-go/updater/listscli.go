package main

// Списки організації — команди адміністратора і інсталятора (не служба):
//
//	docscan-updater -CheckList white|black <файл>      перевірити файл тим самим кодом, що й watcher (install.ps1)
//	docscan-updater -NewListKey -Out <org-lists.key>   ключ організації для підпису списків (listsign.go)
//	docscan-updater -SignList <файл> -Kind white|black -Key <org-lists.key>   новий serial + <файл>.sig

import (
	"fmt"
	"os"

	"docscan/watcher/orglists"
)

// listsCLI — якщо args — команда списків, виконати її: (код виходу, true).
func listsCLI(args []string) (int, bool) {
	if len(args) < 2 {
		return 0, false
	}
	switch args[1] {
	case "-CheckList":
		if len(args) != 4 {
			return checkListCmd("", ""), true
		}
		return checkListCmd(args[2], args[3]), true
	case "-NewListKey":
		return newListKeyCmd(args[1:]), true
	case "-SignList":
		return signListCmd(args[1:]), true
	}
	return 0, false
}

// checkListCmd — 0 і кількість записів, або 1 і причина.
func checkListCmd(kind, p string) int {
	if kind != "white" && kind != "black" {
		fmt.Println("usage: docscan-updater -CheckList white|black <whitelist.json|blacklist.json>")
		return 2
	}
	b, err := os.ReadFile(p)
	if err == nil {
		var l *orglists.List
		if l, err = orglists.Parse(b, kind); err == nil {
			fmt.Printf("OK: %d entries (serial %d)\n", len(l.Entries), l.Serial)
			return 0
		}
	}
	fmt.Printf("ERROR: %s: %v\n", p, err)
	return 1
}

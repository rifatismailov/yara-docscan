package main

// Підпис списків організації — у адміністратора (не на ПК):
//
//	docscan-updater -NewListKey -Out org-lists.key              новий ключ: seed у файл (тримати в секреті, напр.
//	                                                            KeePassXC), публічний ключ — у вивід (-> ПК: -ListsKey)
//	docscan-updater -SignList blacklist.json -Kind black -Key org-lists.key
//
// Підпис: <файл>.sig поруч ("ed25519 <key_id> <base64>", як у релізів). Перед підписом файлу ставиться новий
// "serial" (UTC-час РРРРММДДггххсс, щонайменше старий + 1): DocScanUpdater ставить лише список з більшим serial —
// старий підписаний список повторно не підсунути. Ключ можна дати змінною DOCSCAN_LISTS_KEY замість -Key.

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"

	"docscan/watcher/manifest"
	"docscan/watcher/orglists"
)

func newListKeyCmd(args []string) int {
	fs := flag.NewFlagSet("NewListKey", flag.ContinueOnError)
	fs.Bool("NewListKey", true, "")
	out := fs.String("Out", "", "file for the secret key (seed); it must not exist")
	if err := fs.Parse(args); err != nil || *out == "" {
		fmt.Println("usage: docscan-updater -NewListKey -Out <org-lists.key>")
		return 2
	}
	seed, pub, err := manifest.NewSeed()
	if err == nil {
		var f *os.File
		if f, err = os.OpenFile(*out, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600); err == nil {
			_, err = f.WriteString(seed + "\n")
			if cerr := f.Close(); err == nil {
				err = cerr
			}
		}
	}
	if err != nil {
		fmt.Printf("ERROR: %v\n", err)
		return 1
	}
	pk, _ := manifest.ParseKey(pub)
	fmt.Printf("secret key (seed): %s - keep it secret (KeePassXC), never on the PCs\n", *out)
	fmt.Printf("public key (key_id %s), for the PCs (DocScan-Install.ps1 -ListsKey):\n%s\n", manifest.KeyID(pk), pub)
	return 0
}

func signListCmd(args []string) int {
	fs := flag.NewFlagSet("SignList", flag.ContinueOnError)
	file := fs.String("SignList", "", "whitelist.json / blacklist.json to sign")
	kind := fs.String("Kind", "", "white | black")
	key := fs.String("Key", "", "secret key file (or DOCSCAN_LISTS_KEY)")
	if err := fs.Parse(args); err != nil || *file == "" || (*kind != "white" && *kind != "black") {
		fmt.Println("usage: docscan-updater -SignList <file> -Kind white|black -Key <org-lists.key>")
		return 2
	}
	b, err := os.ReadFile(*file)
	if err == nil {
		var l *orglists.List
		if l, err = orglists.Parse(b, *kind); err == nil {
			var serial int64
			if serial, err = signList(l, *file, *key); err == nil {
				fmt.Printf("OK: %s serial %d, signature %s.sig\n", *file, serial, *file)
				return 0
			}
		}
	}
	fmt.Printf("ERROR: %v\n", err)
	return 1
}

// signList: новий serial, файл p (канонічний JSON) і p.sig.
func signList(l *orglists.List, p, keyFile string) (int64, error) {
	seed, err := readListKey(keyFile)
	if err != nil {
		return 0, err
	}
	s, _ := strconv.ParseInt(time.Now().UTC().Format("20060102150405"), 10, 64)
	if s <= l.Serial {
		s = l.Serial + 1
	}
	l.Serial = s
	data, err := json.MarshalIndent(l, "", "  ")
	if err != nil {
		return 0, err
	}
	data = append(data, '\n')
	sig, err := manifest.Sign(data, seed)
	if err != nil {
		return 0, err
	}
	if err := os.WriteFile(p, data, 0o644); err != nil {
		return 0, err
	}
	return s, os.WriteFile(p+".sig", []byte(sig), 0o644)
}

func readListKey(file string) (string, error) {
	if file == "" {
		if v := strings.TrimSpace(os.Getenv("DOCSCAN_LISTS_KEY")); v != "" {
			return v, nil
		}
		return "", fmt.Errorf("no key: -Key <file> or DOCSCAN_LISTS_KEY")
	}
	b, err := os.ReadFile(file)
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(b)), nil
}

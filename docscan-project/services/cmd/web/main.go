// docscan-web — веб-інтерфейс DocScan на самому ПК (опис: docscan-project/DOCSCAN.md#web): https://127.0.0.1:8741/,
// служба Windows DocScanWeb (SYSTEM). Слухає лише loopback; HTTPS із сертифікатом, який генерується під час
// встановлення і стає довіреним у Windows; вхід — admin + пароль, згенерований під час встановлення (перший вхід
// вимагає його змінити).
//
//	docscan-web.exe [-DataDir C:\ProgramData\DocScan] [-InstallDir <тека над web\>] [-Listen 127.0.0.1:8741]
//	docscan-web.exe -InitTLS          # сертифікат і ключ (install.ps1): новий, якщо немає або закінчується
//	docscan-web.exe -InitAuth         # пароль admin, якщо його ще немає (install.ps1)
//	docscan-web.exe -ResetPassword    # новий тимчасовий пароль (забули)
package main

import (
	"context"
	"crypto/tls"
	"flag"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/signal"
	"os/user"
	"path/filepath"
	"syscall"
	"time"

	"docscan/services/pkg/winsvc"
)

// ServiceName — служба Windows веб-інтерфейсу.
const ServiceName = "DocScanWeb"

// DefaultListen — адреса за замовчуванням.
const DefaultListen = "127.0.0.1:8741"

func main() {
	exe, _ := os.Executable()
	dataDir := flag.String("DataDir", `C:\ProgramData\DocScan`, "DocScan data folder")
	installDir := flag.String("InstallDir", filepath.Dir(filepath.Dir(exe)), "DocScan program folder")
	listen := flag.String("Listen", DefaultListen, "address (loopback only)")
	initTLS := flag.Bool("InitTLS", false, "create the HTTPS certificate and key if missing or expiring, then exit")
	initAuth := flag.Bool("InitAuth", false, "create the admin password if there is none yet, then exit")
	reset := flag.Bool("ResetPassword", false, "set a new temporary admin password, then exit")
	flag.Parse()
	p := paths{data: *dataDir, install: *installDir}

	switch {
	case *initTLS:
		os.Exit(cmdInitTLS(p))
	case *initAuth || *reset:
		os.Exit(cmdInitAuth(p, *reset, *listen))
	}
	if !loopback(*listen) {
		fmt.Fprintf(os.Stderr, "%s: the web interface listens on 127.0.0.1 only\n", *listen)
		os.Exit(2)
	}
	body := func(stop <-chan os.Signal) int { return serve(p, *listen, stop) }
	if ok, code := winsvc.Run(ServiceName, body); ok {
		os.Exit(code)
	}
	stop := make(chan os.Signal, 1)
	signal.Notify(stop, os.Interrupt, syscall.SIGTERM)
	os.Exit(body(stop))
}

func loopback(addr string) bool {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return false
	}
	ip := net.ParseIP(host)
	return host == "localhost" || ip != nil && ip.IsLoopback()
}

func cmdInitTLS(p paths) int {
	os.MkdirAll(p.web(), 0o700)
	thumb, made, err := ensureCert(p, time.Now())
	if err != nil {
		fmt.Fprintln(os.Stderr, "ERROR:", err)
		return 1
	}
	// install.ps1 reads this line: cert <der file> <sha1 thumbprint> new|kept
	fmt.Printf("cert %s %s %s\n", p.certDER(), thumb, map[bool]string{true: "new", false: "kept"}[made])
	return 0
}

func cmdInitAuth(p paths, reset bool, listen string) int {
	os.MkdirAll(p.web(), 0o700)
	if !reset {
		if _, err := os.Stat(p.authFile()); err == nil {
			fmt.Println("password kept")
			return 0
		}
	}
	pw, err := newInitialPassword(p, listen)
	if err != nil {
		fmt.Fprintln(os.Stderr, "ERROR:", err)
		return 1
	}
	// аудит: хто зробив новий тимчасовий пароль (install.ps1 при встановленні — SYSTEM / адміністратор, або -ResetPassword)
	host, _ := os.Hostname()
	wu := ""
	if u, err := user.Current(); err == nil {
		wu = u.Username
	}
	action := map[bool]string{true: "password-reset", false: "password-initial"}[reset]
	writeAdminRecord(p, host, AdminUser, action, "a new temporary password (valid "+tempPasswordTTL.String()+") in "+p.initialPw(), "cli", wu)
	// install.ps1 reads this line: password <password>
	fmt.Printf("password %s\n", pw)
	return 0
}

func serve(p paths, listen string, stop <-chan os.Signal) int {
	lg := newLogger(p.webLog())
	cert, err := tls.LoadX509KeyPair(p.certPEM(), p.keyPEM())
	if err != nil {
		lg.Log("ERROR", "certificate: %v (install.ps1 creates it: docscan-web.exe -InitTLS)", err)
		return 1
	}
	s, err := newServer(p, listen, lg)
	if err != nil {
		lg.Log("ERROR", "%v", err)
		return 1
	}
	srv := &http.Server{Addr: listen, Handler: s, ReadHeaderTimeout: 10 * time.Second, ReadTimeout: time.Minute, WriteTimeout: 2 * time.Minute,
		TLSConfig: &tls.Config{MinVersion: tls.VersionTLS12, Certificates: []tls.Certificate{cert}}}
	errc := make(chan error, 1)
	go func() { errc <- srv.ListenAndServeTLS("", "") }()
	lg.Log("INFO", "start: https://%s/", listen)
	s.purgeTempPassword(time.Now())
	go func() { // тимчасовий пароль, який ніхто не забрав, не лежить на ПК довше за строк
		for range time.Tick(time.Hour) {
			s.purgeTempPassword(time.Now())
		}
	}()
	select {
	case err := <-errc:
		lg.Log("ERROR", "%v", err)
		return 1
	case <-stop:
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		srv.Shutdown(ctx)
		lg.Log("INFO", "stopped")
		return 0
	}
}

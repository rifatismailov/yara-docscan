package main

// cirun prepare — перед probe (завдання probe конвеєра): підготувати стенди, щоб прогін ішов без ручних дій.
//
//	1. stands[].vm: ВМ вимкнена -> start через API Proxmox (токен лише з VM.PowerMgmt + VM.Audit), чекати, поки
//	   відкриється її WinRM / SSH (до 10 хв). Увімкнені — не чіпаються; після прогону ВМ не вимикаються.
//	2. stands[].sessions: на термінальному сервері менше count активних RDP-сесій <prefix>01.. -> відкрити їх зі
//	   стенда from: rds_connect.ps1 (з цього коміту) завданням планувальника в інтерактивній сесії його
//	   користувача (mstsc потребує робочого столу; на win11 — автовхід), чекати до 5 хв.
//
// Нічого з цього не валить прогін: не вдалося — рядок "! ..." у лозі, далі probe вирішує online / SKIPPED.

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	"docscan/cirun/config"
	"docscan/cirun/transport"
)

func cmdPrepare(args []string) int {
	fs := flag.NewFlagSet("prepare", flag.ExitOnError)
	cfgPath := fs.String("config", "docscan-project/ci/config.yaml", "configuration file")
	fs.Parse(args)
	cfg, sec := loadPipelineConfig(*cfgPath)
	ctx := context.Background()

	// 1. ВМ
	var started []*config.Stand
	if cfg.Proxmox.URL != "" {
		px, err := newProxmox(cfg.Proxmox, sec)
		if err != nil {
			fmt.Printf("[prepare] ! proxmox: %v - VMs are not started\n", err)
		} else {
			for i := range cfg.Stands {
				s := &cfg.Stands[i]
				if s.VM == nil {
					continue
				}
				st, err := px.status(s.VM.ProxmoxID)
				switch {
				case err != nil:
					fmt.Printf("[prepare] ! %s: VM %d: %v\n", s.Name, s.VM.ProxmoxID, err)
				case st == "running":
					fmt.Printf("[prepare] %-8s VM %d running\n", s.Name, s.VM.ProxmoxID)
				default:
					if err := px.start(s.VM.ProxmoxID); err != nil {
						fmt.Printf("[prepare] ! %s: start VM %d: %v\n", s.Name, s.VM.ProxmoxID, err)
						continue
					}
					fmt.Printf("[prepare] %-8s VM %d was %s - started\n", s.Name, s.VM.ProxmoxID, st)
					started = append(started, s)
				}
			}
		}
	}
	// ВМ, щойно ввімкнені, — чекати їхнього WinRM / SSH (Windows піднімається 1–3 хв)
	deadline := time.Now().Add(10 * time.Minute)
	for _, s := range started {
		for !transport.Reachable(s.Connection) && time.Now().Before(deadline) {
			time.Sleep(10 * time.Second)
		}
		if transport.Reachable(s.Connection) {
			fmt.Printf("[prepare] %-8s %s reachable\n", s.Name, s.Connection.Host)
			if s.OS == "windows" {
				time.Sleep(30 * time.Second) // WinRM відповідає раніше, ніж служби й автовхід готові
			}
		} else {
			fmt.Printf("[prepare] ! %s: %s not reachable 10 min after the start\n", s.Name, s.Connection.Host)
		}
	}

	// 2. RDP-сесії
	for i := range cfg.Stands {
		s := &cfg.Stands[i]
		if s.Sessions != nil {
			if err := ensureSessions(ctx, cfg, sec, s); err != nil {
				fmt.Printf("[prepare] ! %s: RDP sessions: %v\n", s.Name, err)
			}
		}
	}
	return 0
}

// ---------------------------------------------------------------- Proxmox --

type proxmox struct {
	base, auth string
	c          *http.Client
}

func newProxmox(p config.Proxmox, sec *config.Resolver) (*proxmox, error) {
	tok, err := sec.Get(p.TokenRef)
	if err != nil {
		return nil, err
	}
	// самопідписаний сертифікат Proxmox (лише ця адреса в локальній мережі стендів)
	tr := &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}}
	return &proxmox{base: strings.TrimRight(p.URL, "/") + "/api2/json/nodes/" + p.Node + "/qemu/",
		auth: "PVEAPIToken=" + strings.TrimSpace(tok), c: &http.Client{Timeout: 30 * time.Second, Transport: tr}}, nil
}

func (p *proxmox) call(method, path string) (json.RawMessage, error) {
	req, _ := http.NewRequest(method, p.base+path, nil)
	req.Header.Set("Authorization", p.auth)
	resp, err := p.c.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("%s %s: %s %s", method, path, resp.Status, strings.TrimSpace(string(b)))
	}
	var r struct {
		Data json.RawMessage `json:"data"`
	}
	json.Unmarshal(b, &r)
	return r.Data, nil
}

func (p *proxmox) status(id int) (string, error) {
	d, err := p.call("GET", strconv.Itoa(id)+"/status/current")
	if err != nil {
		return "", err
	}
	var s struct {
		Status string `json:"status"`
	}
	json.Unmarshal(d, &s)
	return s.Status, nil
}

func (p *proxmox) start(id int) error {
	_, err := p.call("POST", strconv.Itoa(id)+"/status/start")
	return err
}

// ---------------------------------------------------------------- RDP-сесії --

func ensureSessions(ctx context.Context, cfg *config.Config, sec *config.Resolver, s *config.Stand) error {
	ss := s.Sessions
	if !transport.Reachable(s.Connection) {
		return fmt.Errorf("%s is offline", s.Connection.Host)
	}
	srv, err := transport.New(ctx, s.Connection, sec)
	if err != nil {
		return err
	}
	defer srv.Close()
	count := func() (int, string, error) {
		r, err := srv.Run(ctx, fmt.Sprintf(`$n = @(quser 2>$null | Select-Object -Skip 1 | ? { $_ -match '^\s*>?%s\d\d\s' -and $_ -match '\sActive\s' }).Count; "$n $env:COMPUTERNAME"`, ss.Prefix), nil)
		if err != nil {
			return 0, "", err
		}
		f := strings.Fields(strings.TrimSpace(r.Output))
		if len(f) < 2 {
			return 0, "", fmt.Errorf("quser: %q", strings.TrimSpace(r.Output))
		}
		n, _ := strconv.Atoi(f[0])
		return n, f[1], nil
	}
	n, computer, err := count()
	if err != nil {
		return err
	}
	if n >= ss.Count {
		fmt.Printf("[prepare] %-8s %d RDP sessions active (%s01..)\n", s.Name, n, ss.Prefix)
		return nil
	}
	from := cfg.Stand(ss.From)
	if from == nil || !transport.Reachable(from.Connection) {
		return fmt.Errorf("%d of %d sessions, and the client stand %s is offline", n, ss.Count, ss.From)
	}
	pass, err := sec.Get(ss.PasswordRef)
	if err != nil {
		return err
	}
	script, err := os.ReadFile("docscan-project/ci/loadtest/rds_connect.ps1")
	if err != nil {
		return err
	}
	cl, err := transport.New(ctx, from.Connection, sec)
	if err != nil {
		return err
	}
	defer cl.Close()
	if wr, ok := cl.(*transport.WinRM); ok {
		wr.SetWorkdir(from.Workdir)
	}
	dir := strings.TrimRight(from.Workdir, `\`)
	if err := cl.Upload(ctx, script, dir+`\rds_connect.ps1`); err != nil {
		return err
	}
	user, err := sec.User(from.Connection)
	if err != nil {
		return err
	}
	// пароль — файлом (rds_connect.ps1 читає і видаляє його), не командним рядком
	if err := cl.Upload(ctx, []byte(pass), dir+`\rds_pw.txt`); err != nil {
		return err
	}
	q := func(v string) string { return "'" + strings.ReplaceAll(v, "'", "''") + "'" }
	// завдання в інтерактивній сесії користувача стенда-клієнта (лише коли він увійшов — автовхід): спершу
	// закрити старі вікна mstsc цих користувачів, потім відкрити count сесій
	ps := fmt.Sprintf(`
$t = "DocScan CI rdp sessions"; $d = %[1]s
Unregister-ScheduledTask -TaskName $t -Confirm:$false -EA 0
$u = "$env:COMPUTERNAME\" + %[2]s
if (-not (@(quser 2>$null) -match ('^\s*>?' + [regex]::Escape(%[2]s) + '\s'))) { Remove-Item "$d\rds_pw.txt" -EA 0; "NO-SESSION"; exit 0 }
icacls "$d\rds_pw.txt" /inheritance:r /grant:r "${u}:F" "*S-1-5-18:F" "*S-1-5-32-544:F" | Out-Null   # until rds_connect.ps1 reads and deletes it
$c = 'powershell.exe -NoProfile -ExecutionPolicy Bypass -File "' + $d + '\rds_connect.ps1"'
$arg = '/c ' + $c + ' -Close -Count 25 -Prefix %[5]s > "' + $d + '\rds_connect.log" 2>&1 & ' + $c + ' -Server %[3]s -Domain %[4]s -Count %[6]d -Prefix %[5]s -DelaySec 4 -PasswordFile "' + $d + '\rds_pw.txt" >> "' + $d + '\rds_connect.log" 2>&1'
$a = New-ScheduledTaskAction -Execute cmd.exe -Argument $arg
$p = New-ScheduledTaskPrincipal -UserId $u -LogonType Interactive -RunLevel Highest
Register-ScheduledTask -TaskName $t -Action $a -Principal $p -Force | Out-Null
Start-ScheduledTask -TaskName $t
"STARTED"
`, q(dir), q(user), s.Connection.Host, computer, ss.Prefix, ss.Count)
	r, err := cl.Run(ctx, ps, nil)
	if err != nil {
		return err
	}
	if strings.Contains(r.Output, "NO-SESSION") {
		return fmt.Errorf("%d of %d sessions; %s has no interactive session of %s (autologon?) - mstsc cannot run", n, ss.Count, ss.From, user)
	}
	if !strings.Contains(r.Output, "STARTED") {
		return fmt.Errorf("rds_connect.ps1 on %s: %s", ss.From, strings.TrimSpace(r.Output))
	}
	fmt.Printf("[prepare] %-8s %d of %d RDP sessions - opening them from %s\n", s.Name, n, ss.Count, ss.From)
	deadline := time.Now().Add(5 * time.Minute)
	for time.Now().Before(deadline) {
		time.Sleep(15 * time.Second)
		if n, _, err = count(); err == nil && n >= ss.Count {
			fmt.Printf("[prepare] %-8s %d RDP sessions active\n", s.Name, n)
			return nil
		}
	}
	return fmt.Errorf("only %d of %d sessions after 5 min (log: %s\\rds_connect.log on %s)", n, ss.Count, dir, ss.From)
}

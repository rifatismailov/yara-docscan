package transport

import (
	"context"
	"encoding/base64"
	"fmt"
	"io"
	"strings"
	"sync"
	"time"

	"github.com/masterzen/winrm"

	"docscan/cirun/config"
)

// WinRM — Windows-машина через WinRM (HTTP 5985, NTLM): скрипти — PowerShell.
type WinRM struct {
	host   string
	wdir   string // тека для тимчасових файлів скриптів кроків
	client *winrm.Client
}

// NewWinRM створює клієнта; з'єднання відкривається при першій команді.
func NewWinRM(c config.Connection, sec *config.Resolver) (*WinRM, error) {
	user, err := sec.User(c)
	if err != nil {
		return nil, err
	}
	pw, err := sec.Get(c.PasswordRef)
	if err != nil {
		return nil, err
	}
	params := *winrm.DefaultParameters
	if c.Auth == "ntlm" {
		// NTLM: вхід локальним обліковим записом Windows без домену і без HTTPS
		params.TransportDecorator = func() winrm.Transporter { return &winrm.ClientNTLM{} }
	}
	// тайм-аут ОДНОГО HTTP-запиту: довгі команди бібліотека опитує запитами по <= 60 с (OperationTimeout
	// PT60S), тож 5 хв вистачає, а зниклу машину (вимкнули світло) cirun помітить за хвилини, а не за години
	cl, err := winrm.NewClientWithParameters(winrm.NewEndpoint(c.Host, c.Port, false, false, nil, nil, nil, 5*time.Minute), user, pw, &params)
	if err != nil {
		return nil, err
	}
	return &WinRM{host: c.Host, wdir: `C:\ci`, client: cl}, nil
}

func (w *WinRM) Where() string { return w.host }
func (w *WinRM) Close() error  { return nil }

// SetWorkdir — тека на машині для тимчасових файлів (скрипти кроків, base64).
func (w *WinRM) SetWorkdir(dir string) { w.wdir = dir }

// Run виконує PowerShell-скрипт файлом step-<мс>.ps1 у робочій теці (так немає обмеження на довжину
// команди), з BOM UTF-8 (щоб PowerShell 5.1 правильно прочитав не-ASCII) і заголовком «помилки не
// зупиняють, без смуги прогресу». Службові рядки прогресу («#< CLIXML», «<Objs …») прибираються.
func (w *WinRM) Run(ctx context.Context, script string, onLine func(string)) (Result, error) {
	path := fmt.Sprintf(`%s\step-%d.ps1`, w.wdir, time.Now().UnixMilli())
	body := "\ufeff$ErrorActionPreference='Continue'\n$ProgressPreference='SilentlyContinue'\n" + script
	if err := w.Upload(ctx, []byte(body), path); err != nil {
		return Result{}, fmt.Errorf("upload of the step script failed: %w", err)
	}
	stdout, stderr, rc, err := w.client.RunPSWithContext(ctx, fmt.Sprintf(
		"& powershell -NoProfile -ExecutionPolicy Bypass -File '%[1]s'; $c=$LASTEXITCODE; Remove-Item '%[1]s' -EA 0; exit $c", path))
	if err != nil {
		return Result{Output: stdout + stderr}, err
	}
	var keep []string
	for _, l := range strings.Split(strings.ReplaceAll(stdout+stderr, "\r\n", "\n"), "\n") {
		if strings.HasPrefix(l, "#< CLIXML") || strings.HasPrefix(l, "<Objs ") {
			continue
		}
		keep = append(keep, l)
		if onLine != nil {
			onLine(l)
		}
	}
	return Result{Output: strings.Join(keep, "\n"), ExitCode: rc}, nil
}

// Upload: WinRM не має «копіювання файлу» і обмежує довжину команди, тому дані йдуть base64 шматками
// по 7000 символів, кожен дописується в remote.b64 командою cmd «echo …>>» — усе в ОДНІЙ оболонці
// (набагато швидше, ніж нова оболонка на шматок); наприкінці PowerShell декодує .b64 у файл.
func (w *WinRM) Upload(ctx context.Context, data []byte, remote string) error {
	b64 := base64.StdEncoding.EncodeToString(data)
	shell, err := w.client.CreateShell()
	if err != nil {
		return err
	}
	cmd := func(c string) error {
		co, err := shell.ExecuteWithContext(ctx, c)
		if err != nil {
			return err
		}
		var errOut strings.Builder
		var wg sync.WaitGroup
		wg.Add(2)
		go func() { defer wg.Done(); io.Copy(io.Discard, co.Stdout) }()
		go func() { defer wg.Done(); io.Copy(&errOut, co.Stderr) }()
		co.Wait()
		wg.Wait()
		co.Close()
		if co.ExitCode() != 0 {
			return fmt.Errorf("%s", cut(errOut.String(), 200))
		}
		return nil
	}
	dir := remote[:max(strings.LastIndex(remote, `\`), 0)]
	err = cmd(fmt.Sprintf(`if not exist "%s" mkdir "%s"`, dir, dir))
	if err == nil {
		err = cmd(fmt.Sprintf(`del /q "%s.b64" 2>nul & ver >nul`, remote))
	}
	for i := 0; err == nil && i < len(b64); i += 7000 {
		err = cmd(fmt.Sprintf(`echo %s>>"%s.b64"`, b64[i:min(i+7000, len(b64))], remote))
	}
	shell.Close()
	if err != nil {
		return err
	}
	_, stderr, rc, err := w.client.RunPSWithContext(ctx, fmt.Sprintf(
		"$b=(Get-Content '%[1]s.b64') -join ''; [IO.File]::WriteAllBytes('%[1]s',[Convert]::FromBase64String($b)); Remove-Item '%[1]s.b64'", remote))
	if err == nil && rc != 0 {
		err = fmt.Errorf("%s", cut(stderr, 200))
	}
	return err
}

// Download: PowerShell читає файл і видає його base64-текстом (WinRM передає лише текст).
func (w *WinRM) Download(ctx context.Context, remote string) ([]byte, error) {
	stdout, stderr, rc, err := w.client.RunPSWithContext(ctx, "[Convert]::ToBase64String([IO.File]::ReadAllBytes('"+remote+"'))")
	if err == nil && rc != 0 {
		err = fmt.Errorf("%s", cut(stderr, 200))
	}
	if err != nil {
		return nil, err
	}
	return base64.StdEncoding.DecodeString(strings.NewReplacer("\r", "", "\n", "").Replace(stdout))
}

// cut прибирає пробіли по краях і обрізає рядок до n байтів.
func cut(s string, n int) string {
	s = strings.TrimSpace(s)
	if len(s) > n {
		return s[:n]
	}
	return s
}

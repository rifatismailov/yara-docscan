// Package transport — як cirun дістається до машини: локально, через SSH або через WinRM.
// Платформи (package platform) працюють лише через інтерфейс Transport, тож одна й та сама
// платформа може йти будь-яким підключенням, яке вміє її оболонку.
package transport

import (
	"context"
	"fmt"
	"net"
	"strconv"
	"time"

	"docscan/cirun/config"
)

// Result — результат команди: увесь вивід (stdout + stderr разом) і код виходу.
type Result struct {
	Output   string
	ExitCode int
}

// Transport — підключення до однієї машини.
type Transport interface {
	// Run виконує скрипт оболонки машини (sh для local/ssh, PowerShell для winrm). onLine, якщо
	// задано, отримує рядки виводу одразу, як вони з'являються (для ходу в терміналі); для WinRM —
	// після завершення команди. Помилка — лише якщо команду не вдалося запустити; ненульовий код
	// виходу — це Result.ExitCode, не помилка.
	Run(ctx context.Context, script string, onLine func(string)) (Result, error)
	// Upload кладе дані у файл на машині (теку створює, файл перезаписує).
	Upload(ctx context.Context, data []byte, remotePath string) error
	// Download читає файл з машини.
	Download(ctx context.Context, remotePath string) ([]byte, error)
	// Where — адреса машини для повідомлень ("10.0.0.5" або "local").
	Where() string
	Close() error
}

// New відкриває підключення за описом з конфігу; ім'я і пароль бере Resolver за посиланнями.
func New(ctx context.Context, c config.Connection, sec *config.Resolver) (Transport, error) {
	switch c.Type {
	case "local":
		return NewLocal(), nil
	case "ssh":
		return NewSSH(ctx, c, sec)
	case "winrm":
		return NewWinRM(c, sec)
	}
	return nil, fmt.Errorf("unknown connection type %q", c.Type)
}

// Reachable — чи відкритий порт підключення (за 4 с). Для local — завжди так.
func Reachable(c config.Connection) bool {
	if c.Type == "local" {
		return true
	}
	conn, err := net.DialTimeout("tcp", net.JoinHostPort(c.Host, strconv.Itoa(c.Port)), 4*time.Second)
	if err != nil {
		return false
	}
	conn.Close()
	return true
}

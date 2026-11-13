package transport

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net"
	"os"
	"path"
	"strconv"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/knownhosts"

	"docscan/cirun/config"
)

// SSH — машина з sh (macOS, Linux) через SSH. Ключ хоста ЗАВЖДИ перевіряється за known_hosts:
// невідомий або змінений ключ — помилка (один раз підключіться вручну: ssh user@host).
type SSH struct {
	host   string
	client *ssh.Client
}

// NewSSH підключається: ключ (key_file) і/або пароль (password_ref), ім'я — user / user_ref.
func NewSSH(ctx context.Context, c config.Connection, sec *config.Resolver) (*SSH, error) {
	user, err := sec.User(c)
	if err != nil {
		return nil, err
	}
	var auth []ssh.AuthMethod
	if c.KeyFile != "" {
		key, err := os.ReadFile(config.ExpandHome(c.KeyFile))
		if err != nil {
			return nil, err
		}
		signer, err := ssh.ParsePrivateKey(key)
		if err != nil {
			return nil, fmt.Errorf("%s: %w (a key with a passphrase: load it into ssh-agent)", c.KeyFile, err)
		}
		auth = append(auth, ssh.PublicKeys(signer))
	}
	if c.PasswordRef != "" {
		pw, err := sec.Get(c.PasswordRef)
		if err != nil {
			return nil, err
		}
		auth = append(auth, ssh.Password(pw))
	}
	if len(auth) == 0 {
		return nil, fmt.Errorf("ssh %s: neither key_file nor password_ref", c.Host)
	}
	hostKeys, err := knownhosts.New(config.ExpandHome(c.KnownHosts))
	if err != nil {
		return nil, fmt.Errorf("known_hosts %s: %w (connect once by hand: ssh %s@%s)", c.KnownHosts, err, user, c.Host)
	}
	addr := net.JoinHostPort(c.Host, strconv.Itoa(c.Port))
	d := net.Dialer{Timeout: 10 * time.Second}
	conn, err := d.DialContext(ctx, "tcp", addr)
	if err != nil {
		return nil, err
	}
	cc, chans, reqs, err := ssh.NewClientConn(conn, addr, &ssh.ClientConfig{
		User: user, Auth: auth, HostKeyCallback: hostKeys, Timeout: 10 * time.Second,
	})
	if err != nil {
		conn.Close()
		return nil, fmt.Errorf("ssh %s: %w", addr, err)
	}
	return &SSH{host: c.Host, client: ssh.NewClient(cc, chans, reqs)}, nil
}

func (s *SSH) Where() string { return s.host }
func (s *SSH) Close() error  { return s.client.Close() }

func (s *SSH) Run(ctx context.Context, script string, onLine func(string)) (Result, error) {
	sess, err := s.client.NewSession()
	if err != nil {
		return Result{}, err
	}
	defer sess.Close()
	pr, pw := io.Pipe()
	sess.Stdout, sess.Stderr = pw, pw
	var out strings.Builder
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		collect(pr, &out, onLine)
	}()
	// скасування контексту обриває сесію, щоб довгий крок не висів після Ctrl+C
	done := make(chan struct{})
	go func() {
		select {
		case <-ctx.Done():
			sess.Close()
		case <-done:
		}
	}()
	err = sess.Run(script)
	close(done)
	pw.Close()
	wg.Wait()
	if err != nil {
		if e, ok := err.(*ssh.ExitError); ok {
			return Result{Output: out.String(), ExitCode: e.ExitStatus()}, nil
		}
		return Result{Output: out.String()}, err
	}
	return Result{Output: out.String()}, nil
}

// Upload передає файл через stdin команди cat (на машині не потрібен sftp).
func (s *SSH) Upload(ctx context.Context, data []byte, remotePath string) error {
	sess, err := s.client.NewSession()
	if err != nil {
		return err
	}
	defer sess.Close()
	sess.Stdin = bytes.NewReader(data)
	var stderr bytes.Buffer
	sess.Stderr = &stderr
	if err := sess.Run(fmt.Sprintf("mkdir -p %s && cat > %s", shq(path.Dir(remotePath)), shq(remotePath))); err != nil {
		return fmt.Errorf("upload %s: %v %s", remotePath, err, strings.TrimSpace(stderr.String()))
	}
	return nil
}

// Download читає файл через stdout команди cat.
func (s *SSH) Download(ctx context.Context, remotePath string) ([]byte, error) {
	sess, err := s.client.NewSession()
	if err != nil {
		return nil, err
	}
	defer sess.Close()
	var out, stderr bytes.Buffer
	sess.Stdout, sess.Stderr = &out, &stderr
	if err := sess.Run("cat " + shq(remotePath)); err != nil {
		return nil, fmt.Errorf("download %s: %v %s", remotePath, err, strings.TrimSpace(stderr.String()))
	}
	return out.Bytes(), nil
}

// shq бере рядок в одинарні лапки для sh (усередині ' -> '\”).
func shq(s string) string { return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'" }

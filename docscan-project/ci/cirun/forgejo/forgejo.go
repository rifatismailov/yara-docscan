// Package forgejo — НЕобов'язкове доповнення після push на GitHub: якщо Forgejo увімкнено в конфігу і він
// доступний — підсмикнути дзеркало (mode: mirror) або запушити й туди (mode: push) і поставити статуси
// коміту cirun/<платформа>. Головна публікація — push на GitHub — від Forgejo не залежить (orchestrator).
package forgejo

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"strings"
	"time"

	"docscan/cirun/config"
	"docscan/cirun/gitops"
)

// Client — підключення до API Forgejo для одного репозиторію.
type Client struct {
	cfg   config.Forgejo
	token string
	say   func(string, ...any)
}

// New створює клієнта; токен — з посилання token_ref.
func New(cfg config.Forgejo, sec *config.Resolver, say func(string, ...any)) (*Client, error) {
	tok, err := sec.Get(cfg.TokenRef)
	if err != nil {
		return nil, err
	}
	return &Client{cfg: cfg, token: tok, say: say}, nil
}

// api — запит до /api/v1/repos/<repo><path>; body — JSON (nil — без тіла); статус 300+ — помилка.
func (c *Client) api(ctx context.Context, method, path string, body any) ([]byte, error) {
	var rd io.Reader
	if body != nil {
		b, _ := json.Marshal(body)
		rd = bytes.NewReader(b)
	}
	req, err := http.NewRequestWithContext(ctx, method, strings.TrimRight(c.cfg.URL, "/")+"/api/v1/repos/"+c.cfg.Repo+path, rd)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "token "+c.token)
	req.Header.Set("Content-Type", "application/json")
	r, err := (&http.Client{Timeout: time.Minute}).Do(req)
	if err != nil {
		return nil, err
	}
	defer r.Body.Close()
	data, _ := io.ReadAll(r.Body)
	if r.StatusCode >= 300 {
		return nil, fmt.Errorf("%s %s: %s", method, path, r.Status)
	}
	return data, nil
}

// Reachable — чи доступний Forgejo (за check.timeout): api — репозиторій через API з токеном;
// ls-remote — git ls-remote --heads <remote> без запиту пароля.
func (c *Client) Reachable(ctx context.Context) error {
	ctx, cancel := context.WithTimeout(ctx, c.cfg.Check.Timeout)
	defer cancel()
	if c.cfg.Check.Method == "ls-remote" {
		cmd := exec.CommandContext(ctx, "git", "ls-remote", "--heads", c.cfg.Remote)
		cmd.Env = append(os.Environ(), "GIT_TERMINAL_PROMPT=0")
		if out, err := cmd.CombinedOutput(); err != nil {
			return fmt.Errorf("git ls-remote %s: %v %s", c.cfg.Remote, err, strings.TrimSpace(string(out)))
		}
		return nil
	}
	_, err := c.api(ctx, "GET", "", nil)
	return err
}

// Sync — після push на GitHub: mode push — git push <remote> <branch>; mode mirror — mirror-sync і
// очікування (до 3 хв), поки гілка в дзеркалі не вкаже на sha.
func (c *Client) Sync(ctx context.Context, branch, sha string) error {
	if c.cfg.Mode == "push" {
		return gitops.Push(c.cfg.Remote, branch)
	}
	if _, err := c.api(ctx, "POST", "/mirror-sync", nil); err != nil {
		return err
	}
	for i := 0; i < 60; i++ {
		var br struct {
			Commit struct {
				ID string `json:"id"`
			} `json:"commit"`
		}
		if data, err := c.api(ctx, "GET", "/branches/"+url.PathEscape(branch), nil); err == nil && json.Unmarshal(data, &br) == nil && br.Commit.ID == sha {
			c.say("    Forgejo mirror has %s", sha[:8])
			return nil
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(3 * time.Second):
		}
	}
	return fmt.Errorf("the mirror did not get %s in 3 minutes", sha[:8])
}

// Status — стан однієї платформи для статусу коміту.
type Status struct {
	Platform    string
	State       string // success | failure | skipped
	Description string
}

// ReportStatuses ставить статус коміту на кожну платформу: context "cirun/<платформа>". Помилка — лише
// попередження.
func (c *Client) ReportStatuses(ctx context.Context, sha string, st []Status) {
	if !c.cfg.Report.CommitStatus {
		return
	}
	for _, s := range st {
		state := map[string]string{"success": "success", "failure": "failure"}[s.State]
		if state == "" {
			state = "warning" // skipped: не зелений, але й не провал
		}
		desc := s.Description
		if len(desc) > 140 {
			desc = desc[:140]
		}
		body := map[string]string{"state": state, "context": "cirun/" + s.Platform, "description": desc}
		if _, err := c.api(ctx, "POST", "/statuses/"+sha, body); err != nil {
			c.say("    ! commit status %s: %v", s.Platform, err)
		}
	}
}

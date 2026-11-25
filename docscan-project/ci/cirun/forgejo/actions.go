package forgejo

import (
	"context"
	"encoding/json"
	"fmt"
	"net/url"
	"strings"

	"docscan/cirun/config"
)

// Конвеєр Forgejo Actions: ▷ на Маку запускає workflow і завершується; завдання workflow ставлять статуси коміту
// з результатом кожного стенда (cirun/<стенд>) — їх видно у Forgejo.

// NewClient — клієнт без config.Forgejo (у завданнях workflow): адреса, репозиторій, токен.
func NewClient(baseURL, repo, token string) *Client {
	return &Client{cfg: config_(baseURL, repo), token: token, say: func(string, ...any) {}}
}

// Run — запущений прогін workflow.
type Run struct {
	ID        int64    `json:"id"`
	RunNumber int64    `json:"run_number"`
	Jobs      []string `json:"jobs"`
}

// Dispatch запускає workflow (workflow_dispatch) на гілці ref з inputs; return_run_info — одразу номер прогону.
func (c *Client) Dispatch(ctx context.Context, workflow, ref string, inputs map[string]string) (*Run, error) {
	data, err := c.api(ctx, "POST", "/actions/workflows/"+url.PathEscape(workflow)+"/dispatches",
		map[string]any{"ref": ref, "inputs": inputs, "return_run_info": true})
	if err != nil {
		return nil, err
	}
	var r Run
	if err := json.Unmarshal(data, &r); err != nil || r.ID == 0 {
		return nil, fmt.Errorf("dispatch: no run info in the reply (%s)", strings.TrimSpace(string(data)))
	}
	return &r, nil
}

// RunURL — посилання на прогін у вебінтерфейсі.
func (c *Client) RunURL(r *Run) string {
	n := r.RunNumber
	if n == 0 {
		n = r.ID
	}
	return fmt.Sprintf("%s/%s/actions/runs/%d", strings.TrimRight(c.cfg.URL, "/"), c.cfg.Repo, n)
}

// SetStatus ставить статус коміту: state pending | success | failure | warning | error.
func (c *Client) SetStatus(ctx context.Context, sha, context_, state, desc, target string) error {
	if len(desc) > 140 {
		desc = desc[:140]
	}
	_, err := c.api(ctx, "POST", "/statuses/"+sha, map[string]string{"state": state, "context": context_,
		"description": desc, "target_url": target})
	return err
}

func config_(baseURL, repo string) config.Forgejo { return config.Forgejo{URL: baseURL, Repo: repo} }

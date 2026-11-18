package forgejo

import (
	"context"
	"encoding/json"
	"fmt"
	"net/url"
	"strings"

	"docscan/cirun/config"
)

// Конвеєр Forgejo Actions: ▷ на Маку запускає workflow і стежить за ним, завдання workflow ставлять статуси
// коміту з результатом кожного стенда (cirun/<стенд>), а ▷ їх читає.

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

// Job — завдання прогону.
type Job struct {
	Name   string `json:"name"`
	Status string `json:"status"` // waiting | running | success | failure | cancelled | skipped | blocked
}

// RunState — стан прогону і його завдань.
func (c *Client) RunState(ctx context.Context, id int64) (status string, jobs []Job, err error) {
	data, err := c.api(ctx, "GET", fmt.Sprintf("/actions/runs/%d", id), nil)
	if err != nil {
		return "", nil, err
	}
	var r struct {
		Status string `json:"status"`
	}
	json.Unmarshal(data, &r)
	if data, err = c.api(ctx, "GET", fmt.Sprintf("/actions/runs/%d/jobs", id), nil); err == nil {
		jobs = listOf[Job](data, "jobs")
	}
	return r.Status, jobs, nil
}

// CommitStatus — статус коміту (context — cirun/<стенд>).
type CommitStatus struct {
	Context     string `json:"context"`
	State       string `json:"status"`
	Description string `json:"description"`
}

// Statuses — останній статус кожного context коміту sha.
func (c *Client) Statuses(ctx context.Context, sha string) ([]CommitStatus, error) {
	data, err := c.api(ctx, "GET", "/commits/"+sha+"/statuses?limit=50", nil)
	if err != nil {
		return nil, err
	}
	seen := map[string]bool{}
	var out []CommitStatus
	for _, s := range listOf[CommitStatus](data, "statuses") { // найновіші — першими
		if !seen[s.Context] {
			seen[s.Context] = true
			out = append(out, s)
		}
	}
	return out, nil
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

// listOf розбирає відповідь, яка буває або списком [...], або об'єктом {"<key>": [...]}.
func listOf[T any](data []byte, key string) []T {
	var l []T
	if json.Unmarshal(data, &l) == nil {
		return l
	}
	var w map[string]json.RawMessage
	json.Unmarshal(data, &w)
	json.Unmarshal(w[key], &l)
	return l
}

func config_(baseURL, repo string) config.Forgejo { return config.Forgejo{URL: baseURL, Repo: repo} }

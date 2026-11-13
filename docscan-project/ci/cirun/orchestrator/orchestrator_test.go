package orchestrator

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"docscan/cirun/config"
	"docscan/cirun/platform"
)

// fake — платформа без машин: успіх або провал збірки, записує порядок старту.
type fake struct {
	name  string
	fail  bool
	rep   platform.Reporter
	order *[]string
	mu    *sync.Mutex
}

func (f *fake) Name() string { return f.name }
func (f *fake) Prepare(context.Context) error {
	f.mu.Lock()
	*f.order = append(*f.order, f.name)
	f.mu.Unlock()
	return nil
}
func (f *fake) SyncSource(context.Context, platform.Source) error { return nil }
func (f *fake) Build(context.Context) (platform.StepResult, error) {
	time.Sleep(20 * time.Millisecond)
	if f.fail {
		return platform.StepResult{Name: "build", Status: "FAIL"}, nil
	}
	return platform.StepResult{Name: "build", Status: "PASS"}, nil
}
func (f *fake) Test(context.Context) ([]platform.StepResult, error) {
	return []platform.StepResult{{Name: "documents", Status: "PASS"}}, nil
}
func (f *fake) FetchArtifacts(context.Context, string) ([]string, error) { return nil, nil }
func (f *fake) Close() error                                             { return nil }

func run(t *testing.T, enabled map[string]bool, fail map[string]bool) (*Orchestrator, []string, bool) {
	cfg := &config.Config{Platforms: map[string]*config.Platform{
		"macos":   {Enabled: enabled["macos"], Connection: &config.Connection{Type: "local"}},
		"windows": {Enabled: enabled["windows"], Connection: &config.Connection{Type: "local"}},
		"linux":   {Enabled: enabled["linux"], Connection: &config.Connection{Type: "local"}, Requires: []string{"windows", "macos"}},
	}}
	var order []string
	var mu sync.Mutex
	o := &Orchestrator{Cfg: cfg, RunDir: t.TempDir(),
		Factory: func(n string, rep platform.Reporter) platform.Platform {
			return &fake{name: n, fail: fail[n], rep: rep, order: &order, mu: &mu}
		}}
	green := o.Build(context.Background(), platform.Source{SHA: "0123456789abcdef"})
	return o, order, green
}

func TestLinuxAfterGreenWindowsAndMacOS(t *testing.T) {
	o, order, green := run(t, map[string]bool{"macos": true, "windows": true, "linux": true}, nil)
	if !green {
		t.Fatalf("expected green, results %+v", o.Results)
	}
	if len(order) != 3 || order[2] != "linux" {
		t.Fatalf("linux must start last, order %v", order)
	}
}

func TestLinuxSkippedWhenWindowsFails(t *testing.T) {
	o, order, green := run(t, map[string]bool{"macos": true, "windows": true, "linux": true}, map[string]bool{"windows": true})
	if green {
		t.Fatal("expected not green")
	}
	if r := o.Results["linux"]; r.Status != "skipped" || r.Reason != "windows did not pass" {
		t.Fatalf("linux: %+v", r)
	}
	for _, n := range order {
		if n == "linux" {
			t.Fatal("linux must not start")
		}
	}
}

func TestLinuxSkippedWhenMacOSNotEnabled(t *testing.T) {
	o, _, green := run(t, map[string]bool{"windows": true, "linux": true}, nil)
	if green {
		t.Fatal("a skipped platform must make the run not green")
	}
	if r := o.Results["linux"]; r.Status != "skipped" || r.Reason != "macos is not enabled in this run" {
		t.Fatalf("linux: %+v", r)
	}
}

func TestOnlyFilter(t *testing.T) {
	cfg := &config.Config{Platforms: map[string]*config.Platform{
		"macos":   {Enabled: true, Connection: &config.Connection{Type: "local"}},
		"windows": {Enabled: true, Connection: &config.Connection{Type: "local"}},
	}}
	o := &Orchestrator{Cfg: cfg, Opt: Options{Only: []string{"windows"}}}
	if p := o.Plan(); len(p) != 1 || p[0] != "windows" {
		t.Fatalf("plan %v", p)
	}
}

func TestNotGreenError(t *testing.T) {
	if !errors.Is(ErrNotGreen, ErrNotGreen) {
		t.Fatal()
	}
}

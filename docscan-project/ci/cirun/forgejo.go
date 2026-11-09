package main

// Forgejo mode: sync the GitHub mirror, start the "build-test" workflow, follow its jobs and download
// the artifacts into ci-out/run-<id>/.

import (
	"archive/zip"
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// profile is one entry of ~/.docscan/hosts.json.
type profile map[string]any

func (p profile) s(key string) string {
	if v, ok := p[key].(string); ok {
		return v
	}
	return ""
}

func loadHosts() map[string]profile {
	h := map[string]profile{}
	if b, err := os.ReadFile(filepath.Join(home(), ".docscan", "hosts.json")); err == nil {
		json.Unmarshal(b, &h)
	}
	return h
}

type forgejo struct{ url, token, repo string }

func (f *forgejo) api(method, path string, body any) ([]byte, error) {
	var rd io.Reader
	if body != nil {
		b, _ := json.Marshal(body)
		rd = bytes.NewReader(b)
	}
	req, err := http.NewRequest(method, f.url+"/api/v1/repos/"+f.repo+path, rd)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "token "+f.token)
	req.Header.Set("Content-Type", "application/json")
	r, err := (&http.Client{Timeout: 10 * time.Minute}).Do(req)
	if err != nil {
		return nil, err
	}
	defer r.Body.Close()
	data, err := io.ReadAll(r.Body)
	if r.StatusCode >= 300 {
		return nil, fmt.Errorf("%s %s: %s", method, path, r.Status)
	}
	return data, err
}

// call is api() that decodes the JSON answer into v; stops on an error.
func (f *forgejo) call(method, path string, body, v any) {
	data, err := f.api(method, path, body)
	if err != nil {
		die("Forgejo: " + err.Error())
	}
	if v != nil && len(data) > 0 {
		if err := json.Unmarshal(data, v); err != nil {
			die("Forgejo: " + path + ": " + err.Error())
		}
	}
}

type fjJob struct {
	Name   string `json:"name"`
	Status string `json:"status"`
}

type fjArtifact struct {
	ID   int64  `json:"id"`
	Name string `json:"name"`
}

// listOf decodes an answer that is either a plain list or {"<key>": [...]} (Forgejo versions differ).
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

func (f *forgejo) run(branch, sha string) (string, bool) {
	say("Forgejo: sync the mirror")
	f.call("POST", "/mirror-sync", nil, nil)
	for i := 0; ; i++ {
		var br struct {
			Commit struct {
				ID string `json:"id"`
			} `json:"commit"`
		}
		f.call("GET", "/branches/"+url.PathEscape(branch), nil, &br)
		if br.Commit.ID == sha {
			break
		}
		if i == 60 {
			die(fmt.Sprintf("the mirror did not get %s in 3 minutes (is it pushed to GitHub?)", sha[:8]))
		}
		time.Sleep(3 * time.Second)
	}

	say("Forgejo: start the workflow build-test (fuzzing %ss per OS)", opt.fuzz)
	var info struct {
		ID        int64    `json:"id"`
		RunNumber int64    `json:"run_number"`
		Jobs      []string `json:"jobs"`
	}
	f.call("POST", "/actions/workflows/ci.yml/dispatches", map[string]any{
		"ref": branch, "inputs": map[string]string{"fuzz_seconds": opt.fuzz}, "return_run_info": true}, &info)
	num := info.RunNumber
	if num == 0 {
		num = info.ID
	}
	say("    run #%d: %s/%s/actions/runs/%d   jobs: %s", num, f.url, f.repo, info.ID, strings.Join(info.Jobs, ", "))

	runPath := fmt.Sprintf("/actions/runs/%d", info.ID)
	last := map[string]string{}
	status := ""
	for {
		// a short network hiccup must not stop the run: report it and ask again
		if data, err := f.api("GET", runPath+"/jobs", nil); err != nil {
			say("    (Forgejo: %v)", err)
		} else {
			for _, j := range listOf[fjJob](data, "jobs") {
				if last[j.Name] != j.Status {
					last[j.Name] = j.Status
					say("    %-10s %-12s %4ds", j.Name, j.Status, int(time.Since(started).Seconds()))
				}
			}
		}
		var r struct {
			Status string `json:"status"`
		}
		if data, err := f.api("GET", runPath, nil); err == nil && json.Unmarshal(data, &r) == nil {
			if s := r.Status; s == "success" || s == "failure" || s == "cancelled" || s == "skipped" {
				status = s
				break
			}
		}
		time.Sleep(15 * time.Second)
	}

	out := filepath.Join("ci-out", fmt.Sprintf("run-%d", info.ID))
	os.MkdirAll(out, 0o755)
	data, err := f.api("GET", runPath+"/artifacts", nil)
	if err != nil {
		say("    artifacts: %v", err)
	}
	for _, a := range listOf[fjArtifact](data, "artifacts") {
		z, err := f.api("GET", fmt.Sprintf("/actions/artifacts/%d/zip", a.ID), nil)
		if err == nil {
			err = unzip(z, filepath.Join(out, a.Name))
		}
		if err != nil {
			say("    artifact %s: %v", a.Name, err)
		}
	}
	return out, status == "success"
}

// unzip extracts a zip held in memory; entries that would land outside dst are refused.
func unzip(data []byte, dst string) error {
	zr, err := zip.NewReader(bytes.NewReader(data), int64(len(data)))
	if err != nil {
		return err
	}
	root := filepath.Clean(dst) + string(os.PathSeparator)
	for _, f := range zr.File {
		p := filepath.Join(dst, f.Name)
		if !strings.HasPrefix(p+string(os.PathSeparator), root) {
			return fmt.Errorf("bad path in zip: %s", f.Name)
		}
		if f.FileInfo().IsDir() {
			os.MkdirAll(p, 0o755)
			continue
		}
		os.MkdirAll(filepath.Dir(p), 0o755)
		rc, err := f.Open()
		if err != nil {
			return err
		}
		w, err := os.Create(p)
		if err == nil {
			_, err = io.Copy(w, rc)
			w.Close()
		}
		rc.Close()
		if err != nil {
			return err
		}
	}
	return nil
}

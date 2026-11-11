package main

// Режим Forgejo: синхронізувати дзеркало GitHub, запустити Дію «build-test» (файл
// .forgejo/workflows/ci.yml), стежити за її завданнями і завантажити артефакти в ci-out/run-<id>/.
// Тут же — читання ~/.docscan/hosts.json (профілі з адресами й обліковими записами).

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

// profile — один профіль з ~/.docscan/hosts.json: ім'я поля -> значення (JSON-об'єкт як є).
// Приклад профілю «fs»: {"host": "...", "user": "...", "password": "...", "deploy_dir": "..."}.
type profile map[string]any

// s повертає поле key профілю як рядок; якщо поля немає або воно не рядок — порожній рядок.
// Так код не падає, коли якогось поля в hosts.json немає (і профілю теж: s на nil-мапі працює).
func (p profile) s(key string) string {
	if v, ok := p[key].(string); ok {
		return v
	}
	return ""
}

// loadHosts читає ~/.docscan/hosts.json і повертає профілі за іменами. Немає файлу або він
// зіпсований — порожня мапа (тоді, наприклад, Forgejo вважається не налаштованим).
func loadHosts() map[string]profile {
	h := map[string]profile{}
	if b, err := os.ReadFile(filepath.Join(home(), ".docscan", "hosts.json")); err == nil {
		json.Unmarshal(b, &h)
	}
	return h
}

// forgejo — підключення до API Forgejo для одного репозиторію.
type forgejo struct {
	url   string // адреса сервера Forgejo, напр. http://<сервер>:3000 (без «/» у кінці)
	token string // API-токен Forgejo (з hosts.json «forgejo».token або FORGEJO_TOKEN)
	repo  string // власник/репозиторій, напр. rifat/yara-docscan
}

// api робить запит до API репозиторію: method — GET/POST, path — частина після
// /api/v1/repos/<repo> (напр. "/mirror-sync"), body — тіло JSON (nil — без тіла).
// Повертає сирі байти відповіді; HTTP-статус 300 і вище — помилка. Тайм-аут 10 хв (артефакти бувають великі).
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

// call — те саме, що api, але розбирає JSON-відповідь у v (nil — відповідь не потрібна).
// Будь-яка помилка зупиняє програму: без цих запитів продовжувати немає сенсу.
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

// fjJob — завдання прогону Дії (macos / windows / linux) з відповіді Forgejo.
type fjJob struct {
	Name   string `json:"name"`   // ім'я завдання з ci.yml
	Status string `json:"status"` // стан: waiting, running, success, failure, ...
}

// fjArtifact — артефакт прогону (zip, який завдання вивантажило через upload-artifact).
type fjArtifact struct {
	ID   int64  `json:"id"`   // номер артефакту для завантаження
	Name string `json:"name"` // ім'я (macos / windows / linux) — стає ім'ям підтеки в ci-out
}

// listOf розбирає відповідь, яка буває або простим списком [...], або об'єктом {"<key>": [...]}
// (різні версії Forgejo відповідають по-різному). T — тип елемента (fjJob, fjArtifact).
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

// run — увесь режим Forgejo. branch — гілка, sha — коміт, який має зібратися.
// Повертає теку прогону ci-out/run-<id> і true, якщо прогін завершився успіхом. Як:
//  1. mirror-sync — дзеркало підтягує свіжий push з GitHub; чекаємо (до 3 хв), поки гілка в
//     дзеркалі вкаже саме на sha, інакше зібрали б старий коміт;
//  2. запуск Дії ci.yml (workflow_dispatch) з fuzz_seconds; return_run_info — щоб одразу отримати
//     номер прогону, а не шукати його;
//  3. кожні 15 с — стан завдань (друкується лише зміна стану) і стан прогону, до кінцевого;
//  4. завантаження всіх артефактів і розпаковування в ci-out/run-<id>/<ім'я артефакту>/.
func (f *forgejo) run(branch, sha string) (string, bool) {
	say("Forgejo: sync the mirror")
	f.call("POST", "/mirror-sync", nil, nil)
	for i := 0; ; i++ {
		// br — відповідь «гілка»: нам потрібен лише хеш її останнього коміту
		var br struct {
			Commit struct {
				ID string `json:"id"`
			} `json:"commit"`
		}
		f.call("GET", "/branches/"+url.PathEscape(branch), nil, &br)
		if br.Commit.ID == sha {
			break
		}
		if i == 60 { // 60 спроб по 3 с = 3 хв
			die(fmt.Sprintf("the mirror did not get %s in 3 minutes (is it pushed to GitHub?)", sha[:8]))
		}
		time.Sleep(3 * time.Second)
	}

	say("Forgejo: start the workflow build-test (fuzzing %ss per OS)", opt.fuzz)
	// info — що Forgejo повертає про запущений прогін
	var info struct {
		ID        int64    `json:"id"`         // внутрішній номер прогону (для API і посилання)
		RunNumber int64    `json:"run_number"` // номер, який видно в інтерфейсі («#12»)
		Jobs      []string `json:"jobs"`       // імена завдань, які будуть виконані
	}
	f.call("POST", "/actions/workflows/ci.yml/dispatches", map[string]any{
		"ref": branch, "inputs": map[string]string{"fuzz_seconds": opt.fuzz}, "return_run_info": true}, &info)
	num := info.RunNumber
	if num == 0 { // старіші версії не повертають run_number — показуємо id
		num = info.ID
	}
	say("    run #%d: %s/%s/actions/runs/%d   jobs: %s", num, f.url, f.repo, info.ID, strings.Join(info.Jobs, ", "))

	runPath := fmt.Sprintf("/actions/runs/%d", info.ID)
	last := map[string]string{} // останній надрукований стан кожного завдання (друкуємо лише зміни)
	status := ""                // кінцевий стан прогону
	for {
		// коротка перерва в мережі не повинна зупиняти прогін: повідомляємо і питаємо знову
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
		// r — стан усього прогону
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

// unzip розпаковує zip, що вже лежить у пам'яті (data), у теку dst. Захист: запис, шлях якого після
// з'єднання з dst виходить за межі dst (напр. «../../файл»), відхиляється — архів не може записати
// щось поза текою прогону.
func unzip(data []byte, dst string) error {
	zr, err := zip.NewReader(bytes.NewReader(data), int64(len(data)))
	if err != nil {
		return err
	}
	root := filepath.Clean(dst) + string(os.PathSeparator) // dst з «/» у кінці: для перевірки префікса
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

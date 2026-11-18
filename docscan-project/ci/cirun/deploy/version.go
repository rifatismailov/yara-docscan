package deploy

import (
	"encoding/json"
	"fmt"
	"os/exec"
	"regexp"
	"strconv"
	"strings"
)

// Номери релізів: теги vMAJOR.MINOR.PATCH (SemVer). GitHub сортує такі теги за номером, тож найновіший реліз
// завжди вгорі (старі теги docscan-<дата>-<хеш> сортувалися за випадковим хешем). v0.x — релізи з
// PowerShell-watcher-ом (старі теги docscan-*), перший новий — v1.0.0. Кожен --release бере найбільший v-тег
// на GitHub і збільшує частину bump (patch за замовчуванням; minor / major — прапорцем --bump).
const FirstVersion = "v1.0.0"

var semverRe = regexp.MustCompile(`^v(\d+)\.(\d+)\.(\d+)$`)

type ghRelease struct {
	Tag    string `json:"tag_name"`
	Target string `json:"target_commitish"`
}

func listReleases(repo string) ([]ghRelease, error) {
	out, err := exec.Command("gh", "api", "--paginate", "repos/"+repo+"/releases?per_page=100").Output()
	if err != nil {
		if ee, ok := err.(*exec.ExitError); ok {
			return nil, fmt.Errorf("gh api releases: %s", strings.TrimSpace(string(ee.Stderr)))
		}
		return nil, fmt.Errorf("gh api releases: %w (is gh installed and logged in?)", err)
	}
	// --paginate склеює JSON-масиви сторінок: "][" -> ","
	s := strings.ReplaceAll(strings.TrimSpace(string(out)), "]\n[", ",")
	s = strings.ReplaceAll(s, "][", ",")
	var rs []ghRelease
	if err := json.Unmarshal([]byte(s), &rs); err != nil {
		return nil, fmt.Errorf("gh api releases: %w", err)
	}
	return rs, nil
}

// ReleaseTag — тег для релізу коміту sha: наявний v-тег, якщо цей коміт уже випущено (повторний --release /
// --release-run не плодить номерів), інакше наступний номер після найбільшого v-тега.
func ReleaseTag(repo, sha, bump string) (tag string, existing bool, err error) {
	rs, err := listReleases(repo)
	if err != nil {
		return "", false, err
	}
	return nextTag(rs, sha, bump)
}

func nextTag(rs []ghRelease, sha, bump string) (string, bool, error) {
	if bump != "" && bump != "patch" && bump != "minor" && bump != "major" {
		return "", false, fmt.Errorf("--bump %q: patch, minor or major", bump)
	}
	best := [3]int{-1, 0, 0}
	for _, r := range rs {
		m := semverRe.FindStringSubmatch(r.Tag)
		if m == nil {
			continue
		}
		if r.Target == sha {
			return r.Tag, true, nil
		}
		var v [3]int
		for i := range v {
			v[i], _ = strconv.Atoi(m[i+1])
		}
		if v[0] > best[0] || v[0] == best[0] && (v[1] > best[1] || v[1] == best[1] && v[2] > best[2]) {
			best = v
		}
	}
	if best[0] < 0 {
		return FirstVersion, false, nil
	}
	switch bump {
	case "", "patch":
		best[2]++
	case "minor":
		best[1], best[2] = best[1]+1, 0
	case "major":
		best[0], best[1], best[2] = best[0]+1, 0, 0
	default:
		return "", false, fmt.Errorf("--bump %q: patch, minor or major", bump)
	}
	return fmt.Sprintf("v%d.%d.%d", best[0], best[1], best[2]), false, nil
}

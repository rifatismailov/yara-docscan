package deploy

import "testing"

func TestNextTag(t *testing.T) {
	old := []ghRelease{{"docscan-20261116-53e5ce45", "53e5"}, {"docscan-20261116-505221b0", "5052"}}
	cases := []struct {
		rs        []ghRelease
		sha, bump string
		want      string
		existing  bool
	}{
		{old, "aaaa", "", "v1.0.0", false},
		{append(old, ghRelease{"v1.0.0", "a1"}), "b2", "", "v1.0.1", false},
		{[]ghRelease{{"v1.0.9", "a"}, {"v1.0.10", "b"}, {"v1.0.2", "c"}}, "d", "patch", "v1.0.11", false},
		{[]ghRelease{{"v1.2.3", "a"}}, "d", "minor", "v1.3.0", false},
		{[]ghRelease{{"v1.2.3", "a"}}, "d", "major", "v2.0.0", false},
		{[]ghRelease{{"v1.2.3", "a"}, {"v1.2.4", "d"}}, "d", "", "v1.2.4", true}, // this commit is already released
	}
	for _, c := range cases {
		got, ex, err := nextTag(c.rs, c.sha, c.bump)
		if err != nil || got != c.want || ex != c.existing {
			t.Errorf("nextTag(%v, %s, %s) = %s %v %v, want %s %v", c.rs, c.sha, c.bump, got, ex, err, c.want, c.existing)
		}
	}
	if _, _, err := nextTag(nil, "x", "huge"); err == nil {
		t.Error("bad --bump accepted")
	}
}

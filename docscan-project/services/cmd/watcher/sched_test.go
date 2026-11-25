package main

import (
	"fmt"
	"testing"
	"time"
)

func TestSchedFreshBeforeBulkAndRoundRobin(t *testing.T) {
	s := newSched([]string{`C:\Users`})
	now := time.Now()
	// user a copies 30 files into one folder, user b 30 into another: both become bulk after bulkPerDir
	for i := 0; i < 30; i++ {
		s.add(job{path: fmt.Sprintf(`C:\Users\a\Desktop\big\f%02d.docx`, i)}, now)
		s.add(job{path: fmt.Sprintf(`C:\Users\b\Desktop\big\f%02d.docx`, i)}, now)
	}
	// a single download of user c arrives later
	s.add(job{path: `C:\Users\c\Downloads\invoice.pdf`}, now)
	s.addRetry(job{path: `C:\Users\a\Documents\open.docm`, evt: "DisarmRetry", retry: true})

	if got := s.len(); got != 62 {
		t.Fatalf("len %d, want 62", got)
	}
	var order []string
	for {
		j, ok := s.next()
		if !ok {
			break
		}
		s.pop()
		order = append(order, j.path)
	}
	if len(order) != 62 || s.len() != 0 {
		t.Fatalf("drained %d, left %d", len(order), s.len())
	}
	if order[0] != `C:\Users\a\Documents\open.docm` {
		t.Errorf("retry not first: %s", order[0])
	}
	// the single download (the newest fresh file) right after the retry, before the burst's leftovers in the
	// fresh lane (the first bulkPerDir files of each folder) and before any bulk
	if order[1] != `C:\Users\c\Downloads\invoice.pdf` {
		t.Errorf("newest single file not served first: %s", order[1])
	}
	freshEnd := 1 + 2*bulkPerDir + 1
	// bulk: alternating users a / b
	for i := freshEnd; i+1 < len(order); i += 2 {
		ua, ub := s.userKey(order[i]), s.userKey(order[i+1])
		if ua == ub {
			t.Fatalf("bulk not round-robin at %d: %s, %s", i, order[i], order[i+1])
		}
	}
}

func TestUserKey(t *testing.T) {
	s := newSched([]string{`C:\Users`, `D:\Share\`})
	for p, want := range map[string]string{
		`C:\Users\lt01\Desktop\x.pdf`: `c:\users\lt01`,
		`c:\users\LT02\a\b\c.doc`:     `c:\users\lt02`,
		`D:\Share\dept\f.xlsx`:        `d:\share\dept`,
	} {
		if got := s.userKey(p); got != want {
			t.Errorf("userKey(%s) = %s, want %s", p, got, want)
		}
	}
}

// a copied tree of many small folders (< bulkPerDir each) must go to bulk once the branch is busy, while a
// download of the same user stays a single file
func TestSchedTreeOfSmallFoldersIsBulk(t *testing.T) {
	s := newSched([]string{`C:\Users`})
	now := time.Now()
	for d := 0; d < 40; d++ {
		for f := 0; f < 3; f++ {
			s.add(job{path: fmt.Sprintf(`C:\Users\a\Desktop\tree\corpus\d%02d\f%d.pdf`, d, f)}, now)
		}
	}
	s.add(job{path: `C:\Users\a\Downloads\invoice.pdf`}, now)
	s.add(job{path: `C:\Users\a\Desktop\report.docx`}, now)
	if got := len(s.fresh); got != bulkPerBranch+2 {
		t.Errorf("fresh %d, want %d (the first bulkPerBranch files of the tree + 2 single files)", got, bulkPerBranch+2)
	}
	if s.nBulk != 120-bulkPerBranch {
		t.Errorf("bulk %d, want %d", s.nBulk, 120-bulkPerBranch)
	}
	j, _ := s.next()
	if j.path != `C:\Users\a\Desktop\report.docx` {
		t.Errorf("newest single file not first: %s", j.path)
	}
	for _, c := range []struct{ p, want string }{
		{`C:\Users\a\Desktop\tree\corpus\d01\f.pdf`, `c:\users\a\desktop\tree`},
		{`C:\Users\a\Downloads\x.pdf`, `c:\users\a\downloads`},
		{`C:\Users\a\x.pdf`, `c:\users\a`},
	} {
		if got := s.branchKey(c.p); got != c.want {
			t.Errorf("branchKey(%s) = %s, want %s", c.p, got, c.want)
		}
	}
}

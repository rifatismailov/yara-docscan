package main

// Опис: docscan-project/DOCSCAN.md#watcher — порядок черги: повтори, поодинокі, масові, скани на вимогу.

// Scan order. A burst must not hide the file a user has just saved or downloaded:
//   retry  - disarm retries of locked files (few, and overdue)
//   fresh  - single files: a folder that got at most bulkPerDir files in the last minute AND a branch (profile +
//            two folders, e.g. C:\Users\a\Desktop\tree) that got at most bulkPerBranch - a download, a saved
//            document, an attachment. Scanned before any bulk, NEWEST FIRST. Why the branch: a copied tree has
//            hundreds of small folders (< bulkPerDir files each), which went to the fresh lane, and while the copy
//            was still running they stayed newer than a real download (load test: downloads waited up to 14 min
//            during the copy). Newest first still helps with the first files of each folder.
//   bulk   - mass copies (a folder copied, an archive unpacked, a sync): one FIFO per user profile, served
//            round-robin, so one user's 100 000 files do not stall everybody else's
//   scan   - files of an on-demand / USB scan (scanjob.go), only when nothing above waits: scanHi (a USB stick, a
//            given path) before scanLo (the full scan of the local disks)

import (
	"strings"
	"time"
)

const (
	bulkPerDir    = 10          // files settling in one folder within bulkWindow - more = bulk
	bulkPerBranch = 30          // ... or in one branch (profile + two folders), any subfolder
	bulkWindow    = time.Minute // window of those counts
)

type dirWin struct {
	start time.Time
	n     int
}

type sched struct {
	roots []string
	retry []job
	fresh []job
	bulk  map[string][]job // user key -> FIFO
	order []string         // users with a non-empty bulk queue (round-robin)
	rr    int
	nBulk int
	dirs  map[string]*dirWin

	scanHi, scanLo []job
}

func newSched(roots []string) *sched {
	return &sched{roots: roots, bulk: map[string][]job{}, dirs: map[string]*dirWin{}}
}

func (s *sched) len() int { return len(s.retry) + len(s.fresh) + s.nBulk + s.scanLen() }

func (s *sched) scanLen() int { return len(s.scanHi) + len(s.scanLo) }

func (s *sched) addScan(j job, full bool) {
	if full {
		s.scanLo = append(s.scanLo, j)
	} else {
		s.scanHi = append(s.scanHi, j)
	}
}

// dropScan - a scan was stopped: its files leave the queue (returns their paths)
func (s *sched) dropScan(id string) []string {
	var gone []string
	keep := func(q []job) []job {
		o := q[:0]
		for _, j := range q {
			if j.scan == id {
				gone = append(gone, j.path)
			} else {
				o = append(o, j)
			}
		}
		for i := len(o); i < len(q); i++ {
			q[i] = job{}
		}
		return o
	}
	s.scanHi, s.scanLo = keep(s.scanHi), keep(s.scanLo)
	return gone
}

// isBulk counts the file in its folder's and its branch's windows
func (s *sched) isBulk(p string, now time.Time) bool {
	a := s.count(dirOf(p), now) > bulkPerDir
	b := s.count("branch:"+s.branchKey(p), now) > bulkPerBranch
	return a || b
}

func (s *sched) count(d string, now time.Time) int {
	w := s.dirs[d]
	if w == nil || now.Sub(w.start) > bulkWindow {
		if len(s.dirs) > 20000 { // drop the old windows now and then
			for k, v := range s.dirs {
				if now.Sub(v.start) > bulkWindow {
					delete(s.dirs, k)
				}
			}
		}
		w = &dirWin{start: now}
		s.dirs[d] = w
	}
	w.n++
	return w.n
}

// branch: <user key>\<folder>\<folder> (C:\Users\a\Desktop\tree); a file higher up - its own folder
func (s *sched) branchKey(p string) string {
	u := s.userKey(p)
	d := dirOf(p)
	if len(d) <= len(u) || !strings.EqualFold(d[:len(u)], u) {
		return strings.ToLower(d)
	}
	rest := strings.FieldsFunc(d[len(u):], func(r rune) bool { return r == '\\' || r == '/' })
	if len(rest) > 2 {
		rest = rest[:2]
	}
	return strings.ToLower(u + "\\" + strings.Join(rest, "\\"))
}

// user key: <watch root>\<first folder> (C:\Users\lt01), or the folder itself outside the roots
func (s *sched) userKey(p string) string {
	for _, r := range s.roots {
		r = strings.TrimRight(r, `\/`)
		if len(p) > len(r)+1 && hasPrefixFold(p, r) && (p[len(r)] == '\\' || p[len(r)] == '/') {
			rest := p[len(r)+1:]
			if i := strings.IndexAny(rest, `\/`); i >= 0 {
				return strings.ToLower(r + string(p[len(r)]) + rest[:i])
			}
			return strings.ToLower(r)
		}
	}
	return strings.ToLower(dirOf(p))
}

// folder of a path, '\' or '/' (the same on every OS: the tests run on a Mac with Windows paths)
func dirOf(p string) string {
	if i := strings.LastIndexAny(p, `\/`); i >= 0 {
		return p[:i]
	}
	return "."
}

func (s *sched) addRetry(j job) { s.retry = append(s.retry, j) }

func (s *sched) add(j job, now time.Time) {
	if !s.isBulk(j.path, now) {
		s.fresh = append(s.fresh, j)
		return
	}
	u := s.userKey(j.path)
	if len(s.bulk[u]) == 0 {
		s.order = append(s.order, u)
	}
	s.bulk[u] = append(s.bulk[u], j)
	s.nBulk++
}

func (s *sched) next() (job, bool) {
	if len(s.retry) > 0 {
		return s.retry[0], true
	}
	if len(s.fresh) > 0 {
		return s.fresh[len(s.fresh)-1], true
	}
	if len(s.order) > 0 {
		return s.bulk[s.order[s.rr%len(s.order)]][0], true
	}
	if len(s.scanHi) > 0 {
		return s.scanHi[0], true
	}
	if len(s.scanLo) > 0 {
		return s.scanLo[0], true
	}
	return job{}, false
}

// pop removes what next() returned
func (s *sched) pop() {
	switch {
	case len(s.retry) > 0:
		s.retry[0] = job{}
		s.retry = s.retry[1:]
	case len(s.fresh) > 0:
		s.fresh[len(s.fresh)-1] = job{}
		s.fresh = s.fresh[:len(s.fresh)-1]
	case len(s.order) > 0:
		i := s.rr % len(s.order)
		u := s.order[i]
		q := s.bulk[u]
		q[0] = job{}
		q = q[1:]
		s.nBulk--
		if len(q) == 0 {
			delete(s.bulk, u)
			s.order = append(s.order[:i], s.order[i+1:]...)
			s.rr = i // the next user moved into slot i
		} else {
			s.bulk[u] = q
			s.rr = i + 1
		}
	case len(s.scanHi) > 0:
		s.scanHi[0] = job{}
		s.scanHi = s.scanHi[1:]
	case len(s.scanLo) > 0:
		s.scanLo[0] = job{}
		s.scanLo = s.scanLo[1:]
	}
}

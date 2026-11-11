package main

// Live progress for the local mode: both jobs write into log files, so ci-run reads those logs while
// they run and prints every finished step at once ("[windows 10.0.0.5] build PASS (57s)   45%") plus a
// status line every 30 s. The percentage is an estimate: every step has a weight = its usual duration
// in seconds (fuzzing takes most of the time, so counting steps alone would mislead).

import (
	"fmt"
	"net"
	"os"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"
)

type stepDef struct {
	name   string
	weight float64 // usual duration, seconds
}

// macSteps / winSteps: the steps of build-test-unix.sh and of "ci-run windows", in order.
func macSteps(fuzz string) []stepDef {
	f, _ := strconv.Atoi(fuzz)
	fuzzW := 1.0
	if f > 0 {
		fuzzW = float64(f)/2 + 40 // the two fuzzers run in parallel for fuzz/2 s each, + their build
	}
	return []stepDef{{"build", 90}, {"documents", 20}, {"critical", 5}, {"hostile", 20}, {"fuzz", fuzzW}}
}

func winSteps() []stepDef {
	return []stepDef{{"checkout", 15}, {"build", 70}, {"documents", 90}, {"critical", 10}, {"package", 40}}
}

type tracker struct {
	job, where, log string
	steps           []stepDef
	done            map[string]bool
	cur             string
	curStart        time.Time
	finished        bool
	offset          int64
	partial         string
}

var (
	stepLineRx = regexp.MustCompile(`^(\S+)\s+(PASS|FAIL|SKIP)\b\s*(.*)$`)
	machineRx  = regexp.MustCompile(`^Windows build machine: (.+) (\S+)$`)
)

func (t *tracker) weight(name string) float64 {
	for _, s := range t.steps {
		if s.name == name {
			return s.weight
		}
	}
	return 0
}

// percentParts: finished weight and total weight of this job; the running step counts by its elapsed
// time, at most 95 % of its weight (it is not done until its PASS/FAIL line).
func (t *tracker) percentParts() (float64, float64) {
	var have, total float64
	for _, s := range t.steps {
		total += s.weight
		switch {
		case t.finished || t.done[s.name]:
			have += s.weight
		case s.name == t.cur:
			have += min(time.Since(t.curStart).Seconds(), 0.95*s.weight)
		}
	}
	return have, total
}

// poll reads the new part of the log and returns the lines to print for finished steps.
func (t *tracker) poll(percent func() int) []string {
	f, err := os.Open(t.log)
	if err != nil {
		return nil
	}
	defer f.Close()
	st, err := f.Stat()
	if err != nil || st.Size() <= t.offset {
		return nil
	}
	buf := make([]byte, st.Size()-t.offset)
	n, _ := f.ReadAt(buf, t.offset)
	t.offset += int64(n)
	text := t.partial + string(buf[:n])
	lines := strings.Split(text, "\n")
	t.partial = lines[len(lines)-1] // an unfinished line waits for the next poll
	var events []string
	for _, l := range lines[:len(lines)-1] {
		l = strings.TrimRight(l, "\r")
		if m := machineRx.FindStringSubmatch(l); m != nil {
			t.where = m[2] + " (" + m[1] + ")"
			events = append(events, fmt.Sprintf("    [%s] build machine: %s", t.job, t.where))
			continue
		}
		if strings.HasPrefix(l, "::group::") {
			name := strings.TrimPrefix(strings.TrimPrefix(l, "::group::"), "windows ")
			if t.weight(name) > 0 && !t.done[name] {
				t.cur, t.curStart = name, time.Now()
			}
			continue
		}
		if m := stepLineRx.FindStringSubmatch(l); m != nil && t.weight(m[1]) > 0 && !t.done[m[1]] {
			t.done[m[1]] = true
			if t.cur == m[1] {
				t.cur = ""
			}
			events = append(events, fmt.Sprintf("    [%s %s] %-10s %s %s   %d%%", t.job, t.where, m[1], m[2], m[3], percent()))
		}
	}
	return events
}

func (t *tracker) status() string {
	switch {
	case t.finished:
		return t.job + ": finished"
	case t.cur == "fuzz":
		return fmt.Sprintf("%s: fuzz %ds/%ds", t.job, int(time.Since(t.curStart).Seconds()), int(t.weight("fuzz")))
	case t.cur != "":
		return fmt.Sprintf("%s: %s %ds", t.job, t.cur, int(time.Since(t.curStart).Seconds()))
	}
	return t.job + ": starting"
}

// progress follows several job logs; start() prints until stop() is called.
type progress struct {
	mu       *sync.Mutex // shared with the job goroutines, so the lines do not interleave
	trackers []*tracker
	quit     chan struct{}
	wg       sync.WaitGroup
}

func newProgress(mu *sync.Mutex, trackers ...*tracker) *progress {
	return &progress{mu: mu, trackers: trackers, quit: make(chan struct{})}
}

func (p *progress) percent() int {
	var have, total float64
	for _, t := range p.trackers {
		h, tt := t.percentParts()
		have, total = have+h, total+tt
	}
	if total == 0 {
		return 0
	}
	return int(100 * have / total)
}

func (p *progress) tick() {
	for _, t := range p.trackers {
		for _, e := range t.poll(p.percent) {
			say("%s", e)
		}
	}
}

func (p *progress) start() {
	p.wg.Add(1)
	go func() {
		defer p.wg.Done()
		poll := time.NewTicker(2 * time.Second)
		beat := time.NewTicker(30 * time.Second)
		defer poll.Stop()
		defer beat.Stop()
		for {
			select {
			case <-p.quit:
				return
			case <-poll.C:
				p.mu.Lock()
				p.tick()
				p.mu.Unlock()
			case <-beat.C:
				p.mu.Lock()
				var parts []string
				for _, t := range p.trackers {
					parts = append(parts, t.status())
				}
				say("    ... %s   ~%d%%   (%s)", strings.Join(parts, " | "), p.percent(), time.Since(started).Round(time.Second))
				p.mu.Unlock()
			}
		}
	}()
}

// finish marks a job as ended (called under mu): its remaining log lines are printed first.
func (p *progress) finish(job string) {
	for _, t := range p.trackers {
		if t.job == job {
			for _, e := range t.poll(p.percent) {
				say("%s", e)
			}
			t.finished = true
		}
	}
}

func (p *progress) stop() {
	close(p.quit)
	p.wg.Wait()
}

// thisMac: host name and the address used for the LAN (no packet is sent by a UDP "dial").
func thisMac() string {
	h, _ := os.Hostname()
	h = strings.TrimSuffix(h, ".local")
	if c, err := net.Dial("udp", "192.0.2.1:9"); err == nil {
		defer c.Close()
		return c.LocalAddr().(*net.UDPAddr).IP.String() + " (" + h + ")"
	}
	return h
}

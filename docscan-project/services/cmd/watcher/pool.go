package main

// Опис: docscan-project/DOCSCAN.md#watcher — паралельні скани і їхня кількість.

// Worker pool with automatic size. Every scaleEvery the coordinator looks at the queue, the CPU of the whole
// machine and the scans done since the last look:
//   - queue empty for 2 min                  -> back towards -MinWorkers
//   - CPU >= -CpuHigh                         -> fewer workers (the users of a terminal server come first)
//   - queue > 4 x workers and CPU < -CpuTarget -> +2 workers, up to -MaxWorkers ...
//   - ... unless the last +2 brought no more scans (disk / antivirus / process start is the limit, not the
//     number of workers): back to the previous size and no growth above it for 10 min
// yara64 runs with below-normal priority (Windows), so the users' programs get the CPU first anyway.
// Every change is logged: "workers 8 -> 10 (queue 102849, CPU 34%, 630 scans in 30 s)".

import (
	"fmt"
	"path/filepath"
	"time"
)

const scaleEvery = 30 * time.Second

type pool struct {
	w       *Watcher
	jobs    chan job
	results chan result
	quits   []chan struct{}
}

func newPool(w *Watcher) *pool {
	return &pool{w: w, jobs: make(chan job), results: make(chan result, w.c.MaxWorkers)}
}

func (p *pool) size() int { return len(p.quits) }

func (p *pool) resize(n int) {
	c := p.w.c
	if n < c.MinWorkers {
		n = c.MinWorkers
	}
	if n > c.MaxWorkers {
		n = c.MaxWorkers
	}
	for len(p.quits) < n {
		id := len(p.quits)
		q := make(chan struct{})
		p.quits = append(p.quits, q)
		wk := &worker{id: id,
			macroTmp: filepath.Join(c.MacroDir, fmt.Sprintf("extract-%d.tmp", id)),
			critTmp:  filepath.Join(filepath.Dir(c.CriticalOut), fmt.Sprintf("critical-%d.part", id))}
		go func() {
			for {
				select {
				case <-q: // a worker stops only between two files
					return
				case j := <-p.jobs:
					p.results <- p.w.work(j, wk)
				}
			}
		}()
	}
	for len(p.quits) > n {
		last := len(p.quits) - 1
		close(p.quits[last])
		p.quits = p.quits[:last]
	}
}

type scaler struct {
	cpu          cpuMeter
	prevDone     int
	grew         bool
	plateau      int
	plateauUntil time.Time
	emptySince   time.Time
}

func (co *coordinator) autoscale(now time.Time, done int) {
	c, p, sc := co.w.c, co.pool, &co.scale
	cpu := sc.cpu.busy() // % of the whole machine since the last call, -1 if unknown
	prevDone := sc.prevDone
	sc.prevDone = done
	if c.MinWorkers == c.MaxWorkers {
		return
	}
	cur, backlog := p.size(), co.s.len()
	set := func(n int, why string) {
		if n < c.MinWorkers {
			n = c.MinWorkers
		}
		if n > c.MaxWorkers {
			n = c.MaxWorkers
		}
		if n == cur {
			return
		}
		p.resize(n)
		co.w.log.Log("INFO", "workers %d -> %d (%s; queue %d, CPU %s, %d scans in %ds)", cur, n, why, backlog, pctStr(cpu), done, int(scaleEvery.Seconds()))
	}
	grew := sc.grew
	sc.grew = false
	if backlog == 0 && len(co.inflight) == 0 {
		if sc.emptySince.IsZero() {
			sc.emptySince = now
		}
		if now.Sub(sc.emptySince) >= 2*time.Minute {
			set(cur-2, "no queue")
		}
		return
	}
	sc.emptySince = time.Time{}
	switch {
	case cpu >= float64(c.CpuHigh):
		set(cur-2, "CPU high")
	case backlog > 4*cur && (cpu < 0 || cpu < float64(c.CpuTarget)):
		if grew && done*100 <= prevDone*105 {
			sc.plateau, sc.plateauUntil = cur-2, now.Add(10*time.Minute)
			set(cur-2, "more workers gave no more scans")
			return
		}
		if now.Before(sc.plateauUntil) && cur >= sc.plateau {
			return
		}
		if cur < c.MaxWorkers {
			set(cur+2, "queue grows")
			sc.grew = true
		}
	}
}

func pctStr(v float64) string {
	if v < 0 {
		return "?"
	}
	return fmt.Sprintf("%.0f%%", v)
}

package main

// Прохід по наявних файлах за чорним списком. Watcher бачить лише нові й змінені файли, тож заборонений файл, що
// лежав на диску ДО появи запису (або до встановлення DocScan), інакше лишився б непоміченим. Тому при старті й
// після кожної зміни списків (раз на 30 с перевіряється, чи змінились) watcher обходить теки під масками path
// чорного списку і ставить кожен файл, що підпадає, у звичайну чергу з подією ListSweep: далі — той самий шлях,
// що й для нового файлу (applyLists: білий список сильніший за чорний path, HIGH, карантин або detect-only).
//
// Обходяться лише теки, під якими маска може щось знайти (orglists.CouldContain): для C:\Users\*\Downloads\**\*.exe
// — Downloads кожного профілю, не весь C:\Users. Записи без path (лише sha256 чи lnk_target) тут не шукаються —
// довелося б хешувати або сканувати все підряд; вони діють на нових і змінених файлах.

import (
	"io/fs"
	"path/filepath"
	"time"

	"docscan/watcher/orglists"
)

const listCheckEvery = 30 * time.Second

// sweepCheck — з onTick: списки змінились після останнього проходу — новий прохід (по одному за раз).
func (co *coordinator) sweepCheck(now time.Time) {
	if co.w.lists == nil || co.sweeping || now.Before(co.nextListCheck) {
		return
	}
	co.nextListCheck = now.Add(listCheckEvery)
	white, black, gen := co.w.lists.generation()
	if gen == co.sweptGen {
		return
	}
	co.sweptGen = gen
	if len(black.PathMasks()) == 0 {
		return
	}
	co.sweeping = true
	go co.sweep(white, black)
}

// sweep — обхід (у своїй горутині); файли — у rescanCh, кількість — у sweepN.
func (co *coordinator) sweep(white, black *orglists.List) {
	masks := black.PathMasks()
	n := 0
	for _, wp := range co.w.c.WatchPath {
		filepath.WalkDir(wp, func(p string, d fs.DirEntry, err error) error {
			if err != nil {
				return nil // тека без доступу — далі
			}
			if d.IsDir() {
				for _, m := range masks {
					if orglists.CouldContain(m, p) {
						return nil
					}
				}
				return fs.SkipDir
			}
			if !d.Type().IsRegular() || co.w.category(p) == "" || co.w.excluded(p) {
				return nil
			}
			if orglists.SweepCandidate(white, black, p) {
				co.rescanCh <- fsEvent{path: p, evt: "ListSweep", t: time.Now()}
				n++
			}
			return nil
		})
	}
	co.sweepN <- n
}

package main

// Хід прогону в локальному режимі. Обидві задачі (macos і windows) пишуть увесь вивід у лог-файли,
// тому ci-run читає ці логи, поки задачі йдуть, і друкує:
//   - кожен завершений крок одразу: «[windows 10.0.0.5 (fallback PC)] build PASS (57s)   45%»;
//   - раз на 30 с рядок стану: «... macos: fuzz 95s/190s | windows: documents 40s   ~63%».
//
// Відсоток — оцінка: кожен крок має вагу = його звичайну тривалість у секундах. Фазинг займає більшу
// частину часу, тому простий підрахунок «зроблено 4 кроки з 10» вводив би в оману.

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

// stepDef — опис кроку задачі для підрахунку відсотка.
type stepDef struct {
	name   string  // ім'я кроку так, як воно в лозі («build», «fuzz», ...)
	weight float64 // звичайна тривалість кроку в секундах (вага у відсотку)
}

// macSteps — кроки build-test-unix.sh на Маку, по порядку. fuzz — значення --fuzz (секунди): обидва
// фазери йдуть паралельно по fuzz/2 с, плюс ~40 с на їх збірку; без фазингу (0) крок майже нічого не важить.
func macSteps(fuzz string) []stepDef {
	f, _ := strconv.Atoi(fuzz)
	fuzzW := 1.0
	if f > 0 {
		fuzzW = float64(f)/2 + 40 // the two fuzzers run in parallel for fuzz/2 s each, + their build
	}
	return []stepDef{{"build", 90}, {"documents", 20}, {"critical", 5}, {"hostile", 20}, {"fuzz", fuzzW}}
}

// winSteps — кроки задачі windows (windows.go), по порядку, з їх звичайною тривалістю.
func winSteps() []stepDef {
	return []stepDef{{"checkout", 15}, {"build", 70}, {"documents", 90}, {"critical", 10}, {"package", 40}}
}

// tracker стежить за логом однієї задачі.
type tracker struct {
	job      string          // ім'я задачі: «macos» або «windows» (у квадратних дужках у виводі)
	where    string          // де йде задача: «IP (ім'я)»; для windows спершу «?», поки не прочитаємо з логу
	log      string          // шлях до лог-файлу задачі
	steps    []stepDef       // кроки задачі з вагами (macSteps / winSteps)
	done     map[string]bool // кроки, для яких уже був рядок PASS/FAIL/SKIP
	cur      string          // крок, що виконується зараз (з рядка «::group::<крок>»); "" — жоден
	curStart time.Time       // коли почався поточний крок (коли ми побачили його «::group::»)
	finished bool            // задача завершилась (усі її кроки рахуються як зроблені)
	offset   int64           // скільки байтів логу вже прочитано (наступне читання — з цього місця)
	partial  string          // незакінчений останній рядок логу (без «\n»), чекає наступного читання
}

var (
	// stepLineRx — рядок підсумку кроку: «build          PASS  (57s)» -> ім'я, результат, решта («(57s)»).
	stepLineRx = regexp.MustCompile(`^(\S+)\s+(PASS|FAIL|SKIP)\b\s*(.*)$`)
	// machineRx — рядок windows.go «Windows build machine: <опис> <адреса>» -> опис і адреса машини.
	machineRx = regexp.MustCompile(`^Windows build machine: (.+) (\S+)$`)
)

// weight повертає вагу кроку name; 0 — такого кроку в задачі немає (рядок логу — не про крок).
func (t *tracker) weight(name string) float64 {
	for _, s := range t.steps {
		if s.name == name {
			return s.weight
		}
	}
	return 0
}

// percentParts повертає «зроблену» вагу і загальну вагу задачі. Завершені кроки (або вся задача, якщо
// вона скінчилась) — повною вагою; поточний крок — за часом, що минув, але не більше 95 % ваги
// (він не зроблений, доки немає його рядка PASS/FAIL); решта — 0.
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

// poll дочитує нову частину логу (від offset) і повертає рядки для друку про події: знайдено машину
// Windows, завершився крок. percent — функція загального відсотка (по всіх задачах) для рядка кроку.
// Також оновлює cur/curStart, коли в лозі починається новий крок («::group::...»).
func (t *tracker) poll(percent func() int) []string {
	f, err := os.Open(t.log)
	if err != nil {
		return nil // лог ще не створено — задача тільки стартує
	}
	defer f.Close()
	st, err := f.Stat()
	if err != nil || st.Size() <= t.offset {
		return nil // нічого нового
	}
	buf := make([]byte, st.Size()-t.offset)
	n, _ := f.ReadAt(buf, t.offset)
	t.offset += int64(n)
	text := t.partial + string(buf[:n])
	lines := strings.Split(text, "\n")
	t.partial = lines[len(lines)-1] // незакінчений рядок чекає наступного poll
	var events []string
	for _, l := range lines[:len(lines)-1] {
		l = strings.TrimRight(l, "\r")
		// windows.go повідомив, яку машину вибрано
		if m := machineRx.FindStringSubmatch(l); m != nil {
			t.where = m[2] + " (" + m[1] + ")"
			events = append(events, fmt.Sprintf("    [%s] build machine: %s", t.job, t.where))
			continue
		}
		// початок кроку: на Маку «::group::build», у windows.go «::group::windows build»
		if strings.HasPrefix(l, "::group::") {
			name := strings.TrimPrefix(strings.TrimPrefix(l, "::group::"), "windows ")
			if t.weight(name) > 0 && !t.done[name] {
				t.cur, t.curStart = name, time.Now()
			}
			continue
		}
		// кінець кроку: рядок підсумку. Кожен крок рахуємо один раз — наприкінці логу підсумок повторюється.
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

// status — коротко, що задача робить зараз (для рядка стану раз на 30 с): «finished», «fuzz 95s/190s»
// (для фазингу видно, скільки пройшло із запланованого), «<крок> 40s» або «starting».
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

// progress стежить за кількома задачами одразу: start() запускає фоновий друк, stop() його зупиняє.
type progress struct {
	mu       *sync.Mutex    // спільний з горутинами задач (runLocal), щоб рядки в терміналі не перемішувались
	trackers []*tracker     // по одному на задачу
	quit     chan struct{}  // закриття каналу = сигнал фоновій горутині завершитись
	wg       sync.WaitGroup // stop() чекає, поки фонова горутина справді завершиться
}

// newProgress створює progress для заданих трекерів; mu — той самий м'ютекс, під яким друкує runLocal.
func newProgress(mu *sync.Mutex, trackers ...*tracker) *progress {
	return &progress{mu: mu, trackers: trackers, quit: make(chan struct{})}
}

// percent — загальний відсоток по всіх задачах: сума зробленої ваги / сума загальної ваги × 100.
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

// tick один раз дочитує логи всіх задач і друкує їхні події (викликається під mu).
func (p *progress) tick() {
	for _, t := range p.trackers {
		for _, e := range t.poll(p.percent) {
			say("%s", e)
		}
	}
}

// start запускає фонову горутину: кожні 2 с — tick (нові завершені кроки), кожні 30 с — рядок стану
// всіх задач із загальним відсотком і часом від старту. Друк — під mu.
func (p *progress) start() {
	p.wg.Add(1)
	go func() {
		defer p.wg.Done()
		poll := time.NewTicker(2 * time.Second)  // як часто читати логи
		beat := time.NewTicker(30 * time.Second) // як часто друкувати рядок стану
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

// finish позначає задачу job завершеною (викликається під mu, коли її процес закінчився): спершу
// дочитує і друкує останні рядки її логу, щоб жоден крок не загубився, потім finished = true.
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

// stop зупиняє фонову горутину і чекає її завершення.
func (p *progress) stop() {
	close(p.quit)
	p.wg.Wait()
}

// thisMac повертає «IP (ім'я)» цього Мака. IP — адреса, з якої Мак ходить у мережу: її показує
// «з'єднання» UDP на зарезервовану тестову адресу 192.0.2.1 (для UDP Dial пакет не відправляється,
// система лише вибирає маршрут і свою адресу). Не вдалося — лише ім'я хоста.
func thisMac() string {
	h, _ := os.Hostname()
	h = strings.TrimSuffix(h, ".local")
	if c, err := net.Dial("udp", "192.0.2.1:9"); err == nil {
		defer c.Close()
		return c.LocalAddr().(*net.UDPAddr).IP.String() + " (" + h + ")"
	}
	return h
}

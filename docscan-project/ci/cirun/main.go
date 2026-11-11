// ci-run — «кнопка Запуск» проєкту DocScan (VS Code ▷ / задача «DocScan CI»).
//
// Що робить за один запуск:
//
//	коміт локальних змін -> git push -> збірка і всі тести на кожній системі ->
//	набір для розгортання -> публікація на сервер розгортання.
//
// Запуск (з кореня репозиторію):
//
//	go run -C docscan-project/ci/cirun . [--fuzz СЕКУНДИ] [-m "повідомлення"] [--no-commit] [--no-push]
//	                                     [--local] [--no-publish] [--publish-dir ТЕКА]
//	go run -C docscan-project/ci/cirun . windows      (лише задача Windows, див. windows.go)
//
// Два режими, вибираються автоматично:
//   - Forgejo доступний -> у Forgejo запускається Дія «build-test» (runner-и: цей Мак, Windows через
//     WinRM, Ubuntu, коли з'явиться); ci-run стежить за нею і завантажує артефакти (forgejo.go).
//   - Forgejo НЕдоступний (або --local) -> ті самі кроки прямо з цього Мака: build-test-unix.sh тут і
//     задача Windows по WinRM на першу доступну Windows-машину (ВМ на Proxmox, інакше запасний ПК «216»).
//
// Після «зеленого» прогону в ci-out/<прогін>/deploy/ складається набір для розгортання: пакет Windows
// DocScan-<дата>-<коміт>.zip + .sha256, DocScan-latest.txt, DocScan-Install.ps1 і завантажувачі
// DocScan-Setup.ps1 / -Pilot / -Critical з уже підставленою адресою сервера (+ critical-rules.yar).
// Далі набір викладається на сервер (за замовчуванням; --no-publish — не викладати) і DocScan-latest.txt
// перемикається на новий пакет: «irm http://<сервер>:8080/docscan/DocScan-Setup.ps1 | iex» ставить його.
//
// Автокоміт: усі зміни, які git не ігнорує (git add -A), ідуть одним комітом — якщо перевірка безпеки
// не знайде того, що не можна пускати в публічний репозиторій (внутрішні адреси, імена хостів і
// користувачів, паролі, токени, файли > 5 МБ). Інакше нічого не комітиться і ci-run зупиняється.
//
// Налаштування: ~/.docscan/hosts.json — профіль «forgejo» (url, token, ci_checkout_token), «vm» і «216»
// (host, user, password: Windows-машини для збірки, локальний режим), «fs» (host, user, password,
// deploy_dir, deploy_url, critical_rules: сервер розгортання). Репозиторій у Forgejo: змінна середовища
// FORGEJO_REPO (за замовчуванням rifat/yara-docscan).
package main

import (
	"flag"
	"fmt"
	"io"
	"io/fs"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"
)

// options — значення прапорців командного рядка (заповнюються в main через пакет flag).
type options struct {
	// fuzz — скільки секунд фазингу на кожну ОС (рядком, бо так його передаємо далі в змінну
	// середовища FUZZ_SECONDS і в Дію Forgejo); "0" — без фазингу.
	fuzz string
	// message — повідомлення для автокоміту (-m / --message); порожнє — складається автоматично
	// з імен змінених файлів: «ci: a.go, b.ps1 ...».
	message string
	// remote — ім'я git remote, куди робиться push (GitHub; за замовчуванням "docscan").
	remote string
	// publishDir — якщо задано (--publish-dir), нічого не збирати, а лише викласти вже готовий набір
	// для розгортання з цієї теки (ci-out/<прогін>/deploy).
	publishDir string
	// noPush — не робити git push (--no-push).
	noPush bool
	// noCommit — не комітити локальні зміни (--no-commit); тоді збирається останній коміт.
	noCommit bool
	// local — не використовувати Forgejo навіть якщо він доступний (--local): усе прямо з Мака.
	local bool
	// noPublish — не викладати набір на сервер розгортання (--no-publish).
	noPublish bool
}

var (
	// opt — розібрані прапорці запуску (див. options).
	opt options
	// hosts — профілі з ~/.docscan/hosts.json: ключ — ім'я профілю ("forgejo", "vm", "216", "fs"),
	// значення — його поля (host, user, password, ...). Паролі живуть лише там, не в репозиторії.
	hosts map[string]profile
	// started — час старту програми: для підсумкового «(N min)» і рядків стану в progress.go.
	started = time.Now()
)

// main — точка входу. Порядок: перейти в корінь репозиторію -> (якщо перший аргумент "windows" —
// виконати лише задачу Windows і вийти) -> розібрати прапорці -> коміт і push -> збірка й тести
// (Forgejo або локально) -> показати підсумки -> набір для розгортання -> публікація -> RESULT.
// Код виходу: 0 — усе зелене (і опубліковано, якщо публікацію просили), 1 — інакше.
func main() {
	// "go run -C docscan-project/ci/cirun ." стартує в теці модуля, тому спершу переходимо в корінь
	// репозиторію: усі шляхи нижче (docscan-project/..., ci-out/...) відносні до нього.
	root := strings.TrimSpace(mustGit("rev-parse", "--show-toplevel"))
	if err := os.Chdir(root); err != nil {
		die(err.Error())
	}
	// Підкоманда "windows": той самий бінарник запускає себе так у локальному режимі (runLocal),
	// а Forgejo — у завданні windows (ci.yml). Далі main тоді не йде.
	if len(os.Args) > 1 && os.Args[1] == "windows" {
		os.Exit(runWindows())
	}
	flag.StringVar(&opt.fuzz, "fuzz", "300", "fuzzing seconds per OS (0 = none)")
	flag.BoolVar(&opt.noPush, "no-push", false, "do not git push")
	flag.BoolVar(&opt.noCommit, "no-commit", false, "do not commit local changes (CI builds the last commit)")
	flag.StringVar(&opt.message, "m", "", "commit message for the auto-commit")
	flag.StringVar(&opt.message, "message", "", "same as -m")
	flag.StringVar(&opt.remote, "remote", "docscan", "git remote of GitHub")
	flag.BoolVar(&opt.local, "local", false, "do not use Forgejo: build and test from this Mac")
	flag.BoolVar(&opt.noPublish, "no-publish", false, "do not upload the deployment set to the server")
	// --publish лишився від старих задач VS Code: публікація тепер і так за замовчуванням.
	flag.Bool("publish", false, "the default now; kept for old tasks")
	flag.StringVar(&opt.publishDir, "publish-dir", "", "only publish an existing deployment set (ci-out/<run>/deploy), no build")
	flag.Parse()

	hosts = loadHosts()
	// fj — профіль Forgejo; адресу і токен можна перекрити змінними середовища FORGEJO_URL / FORGEJO_TOKEN.
	fj := hosts["forgejo"]
	forgejoURL := strings.TrimRight(envOr("FORGEJO_URL", fj.s("url")), "/")
	forgejoToken := envOr("FORGEJO_TOKEN", fj.s("token"))
	repo := envOr("FORGEJO_REPO", "rifat/yara-docscan")

	// Режим «лише викласти готовий набір» — без коміту, push і збірки.
	if opt.publishDir != "" {
		publishOnly(opt.publishDir)
		return
	}

	// ---- коміт і push
	branch := mustGit("rev-parse", "--abbrev-ref", "HEAD") // поточна гілка (її і пушимо)
	changes := mustGit("status", "--porcelain")            // незакомічені зміни, порожньо — немає
	if changes != "" && !opt.noCommit {
		commit(changes)
	} else if changes != "" {
		say("! uncommitted changes (--no-commit) - the last COMMIT %s is built", mustGit("rev-parse", "--short", "HEAD"))
	}
	sha := mustGit("rev-parse", "HEAD") // повний хеш коміту, який збираємо
	if !opt.noPush {
		say("git push %s %s", opt.remote, branch)
		// Помилка push не зупиняє: локальний режим може зібрати й локальний коміт.
		if runCmd(nil, "git", "push", opt.remote, branch) != 0 {
			say("! git push failed - continuing with the local commit")
		}
	}

	// ---- збірка і тести
	var out string // тека прогону з артефактами: ci-out/run-<N> або ci-out/local-<час>
	var green bool // true — усі задачі пройшли
	// Forgejo використовуємо, лише якщо не просили --local, він налаштований і відповідає по TCP.
	useForgejo := !opt.local && forgejoURL != "" && forgejoToken != "" && reachable(forgejoURL)
	if useForgejo {
		f := &forgejo{url: forgejoURL, token: forgejoToken, repo: repo}
		out, green = f.run(branch, sha)
	} else {
		if !opt.local {
			say("Forgejo (%s) is not reachable - local mode", orStr(forgejoURL, "not configured"))
		}
		// gitURL — звідки Windows-машина може взяти код через git (якщо бачить Forgejo);
		// інакше windows.go відправить код zip-архівом.
		gitURL := "http://localhost/"
		if forgejoURL != "" {
			gitURL = forgejoURL + "/" + repo + ".git"
		}
		out, green = runLocal(sha, gitURL, fj.s("ci_checkout_token"))
	}

	// Підсумок кожної задачі: кожна кладе summary.txt у свою підтеку артефактів.
	entries, _ := os.ReadDir(out)
	for _, e := range entries {
		if b, err := os.ReadFile(filepath.Join(out, e.Name(), "summary.txt")); err == nil {
			say("\n----- %s\n%s", e.Name(), strings.TrimRight(string(b), "\n"))
		}
	}

	// ---- набір для розгортання і публікація
	var dep *deployment // nil — набору немає (прогін не зелений або без пакета Windows)
	if green {
		dep = deploySet(out)
	}
	published := "" // "" — публікацію не просили (--no-publish), "yes" — опубліковано, "no" — ні
	if !opt.noPublish {
		published = "no"
		if !green {
			say("\n! publishing skipped: the run is not green")
		} else if dep != nil && publish(dep) {
			published = "yes"
		}
	}
	tail := map[string]string{"": "", "yes": "   PUBLISHED", "no": "   NOT published"}[published]
	abs, _ := filepath.Abs(out)
	say("\nRESULT: %s   (%d min)   artifacts: %s%s", map[bool]string{true: "SUCCESS", false: "FAILURE"}[green],
		int(time.Since(started).Minutes()), abs, tail)
	if !green || published == "no" {
		os.Exit(1)
	}
}

// ------------------------------------------------------------------ коміт --

// forbidden — правила перевірки безпеки для публічного репозиторію: кожне — регулярний вираз (rx)
// і що саме він ловить (what, друкується в повідомленні). Перевіряються лише ДОДАНІ рядки коміту.
// Внутрішні імена в самих виразах розбиті на шматки ("ab" + "cd"), щоб цей публічний файл
// сам не містив їх цілком і не спрацьовував на собі.
var forbidden = []struct {
	rx   *regexp.Regexp // що шукати в доданому рядку
	what string         // опис знахідки для повідомлення («internal IP address» тощо)
}{
	// внутрішні підмережі (адреси серверів і ПК мережі)
	{regexp.MustCompile(`\b(192\.168\.(1|17|88|129)|10\.10\.67|172\.118\.18)\.\d{1,3}\b`), "internal IP address"},
	// внутрішні імена хостів / домени
	{regexp.MustCompile(`(?i)(` + "fort" + "una" + `|` + "odessa" + `\.ua)`), "internal host / user name"},
	// пароль або токен у лапках після «password=» / «token:» тощо (від 6 символів)
	{regexp.MustCompile(`(?i)(password|passwd|pwd|secret|token)['"]?\s*[:=]\s*['"][^'"\s]{6,}['"]`), "password / token value"},
	// 40 шістнадцяткових символів — так виглядають токени Forgejo / GitHub
	{regexp.MustCompile(`\b[0-9a-f]{40}\b`), "40-hex token (Forgejo/GitHub)"},
}

// surname — прізвище користувача (розбите на шматки, див. forbidden). Окремо від forbidden, бо Go
// (RE2) не вміє «не після rifat»; цю умову перевіряє internalSurname.
var surname = regexp.MustCompile(`(?i)` + "isma" + "ilov")

// maxFile — найбільший дозволений розмір файлу в коміті (5 МБ): більші — найчастіше випадкові
// бінарники (зібрана програма, архів), їм не місце в git.
const maxFile = 5 * 1024 * 1024

// internalSurname повертає true, якщо в рядку є прізвище НЕ як частина публічного імені облікового
// запису GitHub. Як: шукає всі входження surname і для кожного дивиться 5 символів перед ним —
// якщо там не "rifat" (або входження на початку рядка), це знахідка.
func internalSurname(line string) bool {
	for _, m := range surname.FindAllStringIndex(line, -1) {
		if m[0] < 5 || !strings.EqualFold(line[m[0]-5:m[0]], "rifat") {
			return true
		}
	}
	return false
}

// safetyCheck перевіряє те, що вже додано в індекс git (git add), і повертає список проблем (порожній —
// можна комітити). Як: 1) розміри файлів з «git diff --cached --name-only» проти maxFile;
// 2) кожен доданий рядок («+» у «git diff --cached -U0») проти forbidden і internalSurname.
// Ім'я файлу для повідомлення береться з останнього рядка «+++ b/<файл>».
func safetyCheck() []string {
	var problems []string
	for _, f := range strings.Split(mustGit("diff", "--cached", "--name-only", "-z"), "\x00") {
		if st, err := os.Stat(f); f != "" && err == nil && st.Mode().IsRegular() && st.Size() > maxFile {
			problems = append(problems, f+": file larger than 5 MB")
		}
	}
	cur := "?" // файл, до якого належать поточні рядки diff
	for _, line := range strings.Split(mustGit("diff", "--cached", "-U0", "--no-color"), "\n") {
		switch {
		case strings.HasPrefix(line, "+++ "):
			cur = strings.TrimPrefix(strings.TrimPrefix(line, "+++ "), "b/")
		case strings.HasPrefix(line, "+"):
			// text — сам рядок без «+», обрізаний до 100 символів, щоб повідомлення було коротким
			text := strings.TrimSpace(line[1:])
			if len(text) > 100 {
				text = text[:100]
			}
			for _, f := range forbidden {
				if f.rx.MatchString(line) {
					problems = append(problems, fmt.Sprintf("%s: %s:  %s", cur, f.what, text))
				}
			}
			if internalSurname(line) {
				problems = append(problems, fmt.Sprintf("%s: internal host / user name:  %s", cur, text))
			}
		}
	}
	return problems
}

// commit робить автокоміт. changes — вивід «git status --porcelain» (показуємо перші 30 рядків).
// Як: git add -A -> safetyCheck; якщо є проблеми — git reset (зміни лишаються у файлах, лише
// знімаються з індексу), друкує до 20 знахідок і завершує програму. Інакше — один коміт з
// повідомленням opt.message або автоматичним «ci: <до 6 імен файлів> ...».
func commit(changes string) {
	say("commit local changes:")
	for i, l := range strings.Split(changes, "\n") {
		if i == 30 {
			break
		}
		say("    %s", l)
	}
	mustRun("git", "add", "-A")
	if problems := safetyCheck(); len(problems) > 0 {
		mustRun("git", "reset", "-q")
		say("\n! NOT committed - the public repository must not get:")
		for i, p := range problems {
			if i == 20 {
				break
			}
			say("    %s", p)
		}
		die("fix these changes (or commit by hand with --no-commit) and press Run again")
	}
	files := strings.Split(mustGit("diff", "--cached", "--name-only"), "\n") // що увійде в коміт
	msg := opt.message
	if msg == "" {
		var names []string
		for i, f := range files {
			if i == 6 {
				break
			}
			names = append(names, filepath.Base(f))
		}
		msg = "ci: " + strings.Join(names, ", ")
		if len(files) > 6 {
			msg += " ..."
		}
	}
	mustRun("git", "commit", "-q", "-m", msg)
	say("    committed: %s  (%s)", mustGit("rev-parse", "--short", "HEAD"), msg)
}

// ------------------------------------------------------------ локальний режим --

// runLocal — локальний режим (без Forgejo). Паралельно запускає дві задачі:
//   - macos:   sh docscan-project/ci/build-test-unix.sh на цьому Маку;
//   - windows: цей самий бінарник з аргументом "windows" (windows.go), який по WinRM збирає на Windows.
//
// Параметри: sha — коміт, який збирати; gitURL / gitToken — звідки і з яким токеном Windows може
// взяти код через git (якщо бачить Forgejo). Повертає теку прогону ci-out/local-<час> і true, якщо
// обидві задачі завершилися з кодом 0.
//
// Як: кожна задача пише весь вивід у <тека>/<задача>.log і свої артефакти в <тека>/<задача>-work/
// artifacts; після завершення артефакти копіюються в <тека>/<задача>/, а робочі теки (дерево збірки
// фазерів тощо) видаляються. Хід у терміналі показує progress.go, читаючи ці логи.
func runLocal(sha, gitURL, gitToken string) (string, bool) {
	out := filepath.Join("ci-out", "local-"+time.Now().Format("20060102-150405"))
	if err := os.MkdirAll(out, 0o755); err != nil {
		die(err.Error())
	}
	absOut, _ := filepath.Abs(out)
	// seeds — корпус документів для тесту «ворожі файли» (hostile); немає теки — крок пропускається.
	seeds := filepath.Join(home(), "docscan-ci", "seeds")
	if !isDir(seeds) {
		seeds = ""
	}
	// self — шлях до цієї програми (при go run — тимчасовий бінарник у кеші Go): так задача windows
	// запускає той самий код, що й зараз виконується.
	self, err := os.Executable()
	if err != nil {
		die(err.Error())
	}
	// winEnv — середовище задачі windows: коміт, тека виводу, доступ до git і облікові записи обох
	// Windows-машин з hosts.json (WIN11_* — ВМ, WIN216_* — запасний ПК). Паролі йдуть лише в
	// середовище дочірнього процесу, ніде не друкуються.
	winEnv := append(os.Environ(), "SHA="+sha, "CI_OUT="+filepath.Join(absOut, "windows-work"),
		"GIT_URL="+gitURL, "GIT_TOKEN="+gitToken)
	for _, m := range [][2]string{{"WIN11", "vm"}, {"WIN216", "216"}} {
		if p := hosts[m[1]]; p.s("host") != "" {
			winEnv = append(winEnv, m[0]+"_HOST="+p.s("host"), m[0]+"_USER="+p.s("user"), m[0]+"_PASS="+p.s("password"))
		}
	}
	// jobs — що запускати: ім'я задачі (воно ж ім'я логу і теки артефактів), команда і її середовище.
	jobs := []struct {
		name string   // "macos" або "windows"
		cmd  []string // програма і аргументи
		env  []string // змінні середовища для неї
	}{
		{"macos", []string{"sh", "docscan-project/ci/build-test-unix.sh"},
			append(os.Environ(), "CI_OUT="+filepath.Join(absOut, "macos-work"), "FUZZ_SECONDS="+opt.fuzz, "CI_SEEDS="+seeds)},
		{"windows", []string{self, "windows"}, winEnv},
	}

	say("local mode: macOS here + Windows over WinRM (fuzzing %ss)", opt.fuzz)
	var wg sync.WaitGroup // чекає завершення обох задач
	var mu sync.Mutex     // один друк у термінал за раз (задачі й progress пишуть з різних горутин)
	allOK := true         // стає false, якщо хоч одна задача завершилась не з 0
	// Трекери ходу (progress.go): що показувати для кожної задачі й де лежить її лог.
	mac := &tracker{job: "macos", where: thisMac(), log: filepath.Join(out, "macos.log"), steps: macSteps(opt.fuzz), done: map[string]bool{}}
	win := &tracker{job: "windows", where: "?", log: filepath.Join(out, "windows.log"), steps: winSteps(), done: map[string]bool{}}
	say("    [macos] this Mac: %s", mac.where)
	say("    [windows] picking the build machine (VM, else the fallback PC) ...")
	prog := newProgress(&mu, mac, win)
	prog.start()
	for _, j := range jobs {
		wg.Add(1)
		// Кожна задача — окрема горутина: запускає команду з виводом у лог, чекає її, забирає артефакти.
		go func(name string, cmd, env []string) {
			defer wg.Done()
			t := time.Now()
			work := filepath.Join(out, name+"-work")
			os.MkdirAll(work, 0o755)
			logPath := filepath.Join(out, name+".log")
			rc := 1 // код виходу задачі; 1 — якщо лог навіть не вдалося створити
			if log, err := os.Create(logPath); err == nil {
				c := exec.Command(cmd[0], cmd[1:]...)
				c.Env, c.Stdout, c.Stderr = env, log, log
				rc = exitCode(c.Run())
				log.Close()
			}
			if isDir(filepath.Join(work, "artifacts")) {
				copyDir(filepath.Join(work, "artifacts"), filepath.Join(out, name))
			}
			mu.Lock()
			prog.finish(name) // спершу дочитати лог (останні кроки), потім рядок про задачу
			allOK = allOK && rc == 0
			say("    %-10s %-8s %4ds   %d%%   (log: %s)", name, map[bool]string{true: "success", false: "failure"}[rc == 0],
				int(time.Since(t).Seconds()), prog.percent(), logPath)
			mu.Unlock()
		}(j.name, j.cmd, j.env)
	}
	wg.Wait()
	prog.stop()
	for _, j := range jobs { // артефакти вже скопійовано; робочі теки (дерево збірки фазерів тощо) видаляємо
		os.RemoveAll(filepath.Join(out, j.name+"-work"))
	}
	return out, allOK
}

// --------------------------------------------------------- набір для розгортання --

// deployment — готовий набір для розгортання і куди його викладати.
type deployment struct {
	dir  string  // тека набору (ci-out/<прогін>/deploy або --publish-dir)
	pkg  string  // ім'я файлу пакета, напр. DocScan-20261111-179a8839.zip
	base string  // HTTP-адреса теки на сервері, напр. http://<сервер>:8080/docscan
	fs   profile // профіль «fs» з hosts.json: host, user, password, deploy_dir — для scp/ssh
}

// deployBase повертає HTTP-адресу теки розгортання: deploy_url з профілю «fs», а якщо його немає —
// http://<host>:8080/docscan (або заглушку <server>, якщо немає й host). Без «/» у кінці.
func deployBase(fs profile) string {
	if u := fs.s("deploy_url"); u != "" {
		return strings.TrimRight(u, "/")
	}
	return "http://" + orStr(fs.s("host"), "<server>") + ":8080/docscan"
}

// deploySet складає набір для розгортання в <out>/deploy і повертає його опис (nil — у прогоні немає
// пакета Windows). Як:
//  1. бере найновіший <out>/*/DocScan-*.zip (його зробила задача windows) і його .sha256;
//  2. пише DocScan-latest.txt з іменем пакета (його читає DocScan-Install.ps1 на ПК);
//  3. копіює DocScan-Install.ps1;
//  4. з шаблону DocScan-Setup.ps1 робить три завантажувачі з підставленою адресою сервера:
//     звичайний, -Pilot (лише детект, '-DetectOnly') і -Critical (з третім проходом, '-Critical');
//     шаблон має бути лише ASCII (його виконує «irm | iex»), рядки — CRLF для Windows;
//  5. якщо задано правила E5Search (DOCSCAN_CRITICAL_RULES або critical_rules у «fs») — critical-rules.yar.
func deploySet(out string) *deployment {
	zips, _ := filepath.Glob(filepath.Join(out, "*", "DocScan-*.zip"))
	if len(zips) == 0 {
		say("\n(no Windows package in this run - no deployment set)")
		return nil
	}
	sort.Strings(zips)
	zipPath := zips[len(zips)-1] // імена містять дату, тому останній після сортування — найновіший
	fs := hosts["fs"]
	base := deployBase(fs)
	d := filepath.Join(out, "deploy")
	os.RemoveAll(d)
	if err := os.MkdirAll(d, 0o755); err != nil {
		die(err.Error())
	}
	pkg := filepath.Base(zipPath)
	mustCopy(zipPath, filepath.Join(d, pkg))
	mustCopy(zipPath+".sha256", filepath.Join(d, pkg+".sha256"))
	mustWrite(filepath.Join(d, "DocScan-latest.txt"), pkg+"\n")
	deploy := filepath.Join("docscan-project", "deploy") // тека з джерелами скриптів розгортання
	mustCopy(filepath.Join(deploy, "DocScan-Install.ps1"), filepath.Join(d, "DocScan-Install.ps1"))

	raw, err := os.ReadFile(filepath.Join(deploy, "DocScan-Setup.ps1"))
	if err != nil {
		die(err.Error())
	}
	for _, b := range raw {
		if b > 127 {
			die("DocScan-Setup.ps1 must be ASCII only (it is run by irm | iex)")
		}
	}
	// tpl — шаблон з LF-рядками і вже підставленою адресою (і в лапках, і без)
	tpl := strings.ReplaceAll(string(raw), "\r\n", "\n")
	tpl = strings.ReplaceAll(tpl, "'http://<server>:8080/docscan'", "'"+base+"'")
	tpl = strings.ReplaceAll(tpl, "http://<server>:8080/docscan", base)
	// v[0] — ім'я файлу, v[1] — аргумент для інсталятора ($InstallArg), порожньо — без аргументу
	for _, v := range [][2]string{{"DocScan-Setup.ps1", ""}, {"DocScan-Setup-Pilot.ps1", "'-DetectOnly'"}, {"DocScan-Setup-Critical.ps1", "'-Critical'"}} {
		t := tpl
		if v[1] != "" {
			t = strings.Replace(tpl, "$InstallArg = @()", "$InstallArg = @("+v[1]+")", 1)
		}
		mustWrite(filepath.Join(d, v[0]), strings.ReplaceAll(t, "\n", "\r\n"))
	}
	crit := envOr("DOCSCAN_CRITICAL_RULES", fs.s("critical_rules"))
	if crit != "" {
		crit = expandHome(crit)
		if st, err := os.Stat(crit); err == nil && st.Mode().IsRegular() {
			mustCopy(crit, filepath.Join(d, "critical-rules.yar"))
		}
	}
	abs, _ := filepath.Abs(d)
	say("\ndeployment set: %s", abs)
	entries, _ := os.ReadDir(d)
	for _, e := range entries {
		if st, err := e.Info(); err == nil {
			say("    %-34s %8d bytes", e.Name(), st.Size())
		}
	}
	return &deployment{dir: d, pkg: pkg, base: base, fs: fs}
}

// publishOnly — режим --publish-dir: викладає вже готовий набір з теки dir без збірки. Пакетом
// вважається найновіший DocScan-*.zip у теці. Друкує RESULT і завершується з кодом 1, якщо не вдалося.
func publishOnly(dir string) {
	dir, _ = filepath.Abs(dir)
	zips, _ := filepath.Glob(filepath.Join(dir, "DocScan-*.zip"))
	if len(zips) == 0 {
		die("no DocScan-*.zip in " + dir)
	}
	sort.Strings(zips)
	fs := hosts["fs"]
	ok := publish(&deployment{dir: dir, pkg: filepath.Base(zips[len(zips)-1]), base: deployBase(fs), fs: fs})
	say("\nRESULT: %s", map[bool]string{true: "PUBLISHED", false: "NOT published"}[ok])
	if !ok {
		os.Exit(1)
	}
}

// publish викладає набір d на сервер розгортання і повертає true, якщо все перевірено. Як:
//  1. ssh: mkdir -p <deploy_dir> на сервері;
//  2. scp: усі файли набору, КРІМ DocScan-latest.txt (пароль з hosts.json через sshpass -e,
//     тобто через змінну SSHPASS, а не в командному рядку);
//  3. ssh: sha256sum -c — пакет на сервері збігається з його .sha256? Ні — стоп, latest не чіпаємо;
//  4. scp: DocScan-latest.txt — лише тепер ПК почнуть ставити новий пакет (ніхто не отримає
//     недокачаний чи пошкоджений архів);
//  5. HTTP: DocScan-latest.txt віддає ім'я нового пакета, а DocScan-Setup.ps1 містить адресу сервера.
func publish(d *deployment) bool {
	host, user, pass := d.fs.s("host"), d.fs.s("user"), d.fs.s("password")
	if host == "" || user == "" || pass == "" {
		say("! publishing: no server in ~/.docscan/hosts.json profile 'fs' (host, user, password)")
		return false
	}
	rdir := orStr(d.fs.s("deploy_dir"), "scripts/docscan") // тека на сервері (відносно домашньої)
	target := user + "@" + host
	env := append(os.Environ(), "SSHPASS="+pass) // середовище для sshpass -e
	var files []string                           // усі файли набору, крім DocScan-latest.txt
	entries, _ := os.ReadDir(d.dir)
	for _, e := range entries {
		if e.Name() != "DocScan-latest.txt" {
			files = append(files, filepath.Join(d.dir, e.Name()))
		}
	}
	say("\npublish to %s:%s", target, rdir)
	// ssh — початок команди ssh до сервера; новий ключ хоста приймається автоматично (accept-new),
	// змінений — ні; 10 с на з'єднання.
	ssh := []string{"sshpass", "-e", "ssh", "-o", "StrictHostKeyChecking=accept-new", "-o", "ConnectTimeout=10", target}
	// scp копіює файли src у теку rdir на сервері; true — успішно.
	scp := func(src ...string) bool {
		args := append([]string{"-e", "scp", "-q"}, src...)
		return runCmd(env, "sshpass", append(args, target+":"+rdir+"/")...) == 0
	}
	if runCmd(env, ssh[0], append(ssh[1:], "mkdir -p '"+rdir+"'")...) != 0 || !scp(files...) {
		say("! publish failed (ssh/scp; is sshpass installed?)")
		return false
	}
	c := exec.Command(ssh[0], append(ssh[1:], "cd '"+rdir+"' && sha256sum -c '"+d.pkg+".sha256'")...)
	c.Env = env
	chk, err := c.CombinedOutput()
	say("    %s", strings.TrimSpace(string(chk)))
	if err != nil {
		say("! the package on the server does not match its sha256 - DocScan-latest.txt NOT switched")
		return false
	}
	if !scp(filepath.Join(d.dir, "DocScan-latest.txt")) {
		say("! publish failed: DocScan-latest.txt")
		return false
	}
	latest, err1 := httpGet(d.base + "/DocScan-latest.txt")
	setup, err2 := httpGet(d.base + "/DocScan-Setup.ps1")
	if err1 != nil || err2 != nil {
		say("    HTTP check failed: %v %v", err1, err2)
		return false
	}
	ok := strings.TrimSpace(latest) == d.pkg && strings.Contains(setup, d.base)
	say("    %s/DocScan-latest.txt -> %s   %s", d.base, strings.TrimSpace(latest), map[bool]string{true: "OK", false: "MISMATCH"}[ok])
	say("    install on a PC:  irm %s/DocScan-Setup.ps1 | iex", d.base)
	return ok
}

// ---------------------------------------------------------------- допоміжні --

// say друкує рядок у термінал (як Printf, але з переводом рядка в кінці).
func say(format string, a ...any) { fmt.Printf(format+"\n", a...) }

// die друкує повідомлення в stderr і завершує програму з кодом 1.
func die(msg string) {
	fmt.Fprintln(os.Stderr, msg)
	os.Exit(1)
}

// envOr повертає значення змінної середовища name, а якщо вона порожня або не задана — def.
func envOr(name, def string) string {
	if v := os.Getenv(name); v != "" {
		return v
	}
	return def
}

// orStr повертає s, а якщо s порожній — def.
func orStr(s, def string) string {
	if s != "" {
		return s
	}
	return def
}

// home повертає домашню теку користувача (напр. /Users/<ім'я>).
func home() string {
	h, _ := os.UserHomeDir()
	return h
}

// expandHome розгортає «~/...» у повний шлях від домашньої теки; інші шляхи повертає як є.
func expandHome(p string) string {
	if strings.HasPrefix(p, "~/") {
		return filepath.Join(home(), p[2:])
	}
	return p
}

// isDir повертає true, якщо p існує і це тека.
func isDir(p string) bool {
	st, err := os.Stat(p)
	return err == nil && st.IsDir()
}

// mustGit запускає git з аргументами і повертає його вивід без кінцевого переводу рядка.
// Якщо git завершився з помилкою — програма зупиняється (die).
func mustGit(args ...string) string {
	b, err := exec.Command("git", args...).Output()
	if err != nil {
		die("git " + strings.Join(args, " ") + ": " + err.Error())
	}
	return strings.TrimRight(string(b), "\r\n")
}

// mustRun запускає команду з виводом у термінал; не 0 — програма зупиняється.
func mustRun(name string, args ...string) {
	if runCmd(nil, name, args...) != 0 {
		die(name + " " + strings.Join(args, " ") + " failed")
	}
}

// runCmd запускає команду з виводом у цей термінал і повертає її код виходу.
// env — змінні середовища (nil — успадкувати поточні).
func runCmd(env []string, name string, args ...string) int {
	c := exec.Command(name, args...)
	c.Env, c.Stdout, c.Stderr = env, os.Stdout, os.Stderr
	return exitCode(c.Run())
}

// exitCode перетворює помилку exec на код виходу: nil — 0, програма завершилась з кодом N — N,
// програму не вдалося навіть запустити (немає файлу тощо) — 127, як у shell.
func exitCode(err error) int {
	if err == nil {
		return 0
	}
	if e, ok := err.(*exec.ExitError); ok {
		return e.ExitCode()
	}
	return 127
}

// reachable перевіряє, чи відповідає сервер з адреси raw (http://host:port/...) на TCP-з'єднання.
// Без порту в адресі — 443 для https, 80 для http. Сам HTTP-запит не робиться.
func reachable(raw string) bool {
	u, err := url.Parse(raw)
	if err != nil || u.Hostname() == "" {
		return false
	}
	port := u.Port()
	if port == "" {
		port = map[bool]string{true: "443", false: "80"}[u.Scheme == "https"]
	}
	return tcpOpen(net.JoinHostPort(u.Hostname(), port))
}

// tcpOpen повертає true, якщо на addr ("host:port") вдалося відкрити TCP-з'єднання за 4 секунди.
// З'єднання одразу закривається — це лише перевірка «машина і порт живі».
func tcpOpen(addr string) bool {
	c, err := net.DialTimeout("tcp", addr, 4*time.Second)
	if err != nil {
		return false
	}
	c.Close()
	return true
}

// httpGet завантажує сторінку u і повертає її текст (тайм-аут 15 с). Відповідь не 200 — помилка.
func httpGet(u string) (string, error) {
	c := http.Client{Timeout: 15 * time.Second}
	r, err := c.Get(u)
	if err != nil {
		return "", err
	}
	defer r.Body.Close()
	if r.StatusCode != 200 {
		return "", fmt.Errorf("%s: %s", u, r.Status)
	}
	b, err := io.ReadAll(r.Body)
	return string(b), err
}

// mustWrite записує текст у файл (створює або перезаписує); помилка — програма зупиняється.
func mustWrite(path, text string) {
	if err := os.WriteFile(path, []byte(text), 0o644); err != nil {
		die(err.Error())
	}
}

// mustCopy копіює файл src у dst; помилка — програма зупиняється.
func mustCopy(src, dst string) {
	if err := copyFile(src, dst); err != nil {
		die(err.Error())
	}
}

// copyFile копіює вміст файлу src у dst (dst створюється або перезаписується).
func copyFile(src, dst string) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()
	out, err := os.Create(dst)
	if err != nil {
		return err
	}
	if _, err = io.Copy(out, in); err != nil {
		out.Close()
		return err
	}
	return out.Close()
}

// copyDir рекурсивно копіює теку src у dst (зі збереженням підтек). Так задачі локального режиму
// віддають свої артефакти з робочої теки в теку прогону.
func copyDir(src, dst string) error {
	return filepath.WalkDir(src, func(p string, e fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, _ := filepath.Rel(src, p)
		target := filepath.Join(dst, rel)
		if e.IsDir() {
			return os.MkdirAll(target, 0o755)
		}
		return copyFile(p, target)
	})
}

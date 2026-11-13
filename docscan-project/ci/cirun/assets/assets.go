// Package assets — тестові файли, яких немає в git (сторонні корпуси, корпус для ворожих файлів,
// справжнє шкідливе ПЗ), і доставка їх на машини тестів.
//
// На Маку з них збираються два архіви:
//
//	corpus.tar.gz — corpus/<файли документів з корпусів фазингу> + seeds/<корпус для ворожих файлів>
//	malware.zip   — зразки шкідливого ПЗ + expected.txt, запаролений (пароль "infected"), щоб антивірус
//	                не чіпав архів при зберіганні й передачі
//
// Обидва викладаються в ПРИВАТНИЙ сховок пакетів Forgejo (generic package) під версією = хеш вмісту;
// віддалені машини (ВМ Windows, ВМ Linux) завантажують їх перед тестами і видаляють після. Мак тестує
// розпаковану копію того самого архіву — набір файлів на всіх платформах однаковий.
package assets

import (
	"archive/tar"
	"compress/gzip"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"docscan/cirun/config"
)

// MalwareZipKey — пароль zip з шкідливим ПЗ (загальноприйнятий для обміну зразками).
const MalwareZipKey = "infected"

// docExt — які файли корпусів фазингу йдуть у корпус для тестів (формати, які перевіряє DocScan).
var docExt = map[string]bool{}

func init() {
	for _, e := range strings.Fields(`.doc .dot .docx .docm .dotx .dotm .xls .xlt .xlsx .xlsm .xltx .xltm .xlsb
		.xla .xlam .ppt .pps .pot .pptx .pptm .potx .potm .ppsx .ppsm .ppa .ppam .rtf .pdf .lnk .one .iqy .slk
		.odt .ods .odp .zip`) {
		docExt[e] = true
	}
}

// Assets — готові тестові файли цього прогону.
type Assets struct {
	Version      string // хеш вмісту обох архівів (16 символів)
	CorpusURL    string // завантаження corpus.tar.gz зі сховку (для віддалених машин)
	MalwareURL   string // завантаження malware.zip ("" — шкідливе ПЗ вимкнено)
	Token        string // токен лише на пакети (заголовок Authorization: token …)
	LocalCorpus  string // Мак: розпакований corpus/
	LocalSeeds   string // Мак: розпакований seeds/
	LocalMalware string // Мак: тека зразків шкідливого ПЗ (той самий вміст, що в malware.zip)
}

// file — один файл архіву: шлях в архіві і на диску.
type file struct{ arc, disk string }

// collect — файли корпусу (лише документи) і seeds, відсортовані; відбиток = імена, розміри, дати.
func collect(t config.Tests) ([]file, string, error) {
	var files []file
	h := sha256.New()
	add := func(arc, disk string, st os.FileInfo) {
		files = append(files, file{arc, disk})
		fmt.Fprintf(h, "%s\t%d\t%d\n", arc, st.Size(), st.ModTime().Unix())
	}
	for _, src := range t.CorpusDirs {
		root := config.ExpandHome(src)
		err := filepath.Walk(root, func(p string, st os.FileInfo, err error) error {
			if err != nil {
				return nil // недоступна підтека — пропускаємо
			}
			if st.IsDir() && st.Name() == ".git" {
				return filepath.SkipDir
			}
			if st.Mode().IsRegular() && docExt[strings.ToLower(filepath.Ext(p))] {
				rel, _ := filepath.Rel(root, p)
				add("corpus/"+filepath.Base(root)+"/"+filepath.ToSlash(rel), p, st)
			}
			return nil
		})
		if err != nil {
			return nil, "", err
		}
	}
	if t.Seeds != "" {
		root := config.ExpandHome(t.Seeds)
		entries, _ := os.ReadDir(root)
		for _, e := range entries {
			if st, err := e.Info(); err == nil && st.Mode().IsRegular() {
				add("seeds/"+e.Name(), filepath.Join(root, e.Name()), st)
			}
		}
	}
	sort.Slice(files, func(i, j int) bool { return files[i].arc < files[j].arc })
	return files, hex.EncodeToString(h.Sum(nil)), nil
}

// writeTarGz пише відтворюваний tar.gz: порядок за іменем, однакові власник і час у всіх записах.
func writeTarGz(dst string, files []file) error {
	f, err := os.Create(dst)
	if err != nil {
		return err
	}
	gz := gzip.NewWriter(f)
	tw := tar.NewWriter(gz)
	epoch := time.Unix(0, 0)
	for _, fl := range files {
		st, err := os.Stat(fl.disk)
		if err != nil {
			continue
		}
		hdr := &tar.Header{Name: fl.arc, Mode: 0o644, Size: st.Size(), ModTime: epoch, Typeflag: tar.TypeReg, Format: tar.FormatPAX}
		if err := tw.WriteHeader(hdr); err != nil {
			f.Close()
			return err
		}
		in, err := os.Open(fl.disk)
		if err != nil {
			f.Close()
			return err
		}
		_, err = io.Copy(tw, in)
		in.Close()
		if err != nil {
			f.Close()
			return err
		}
	}
	if err := tw.Close(); err != nil {
		f.Close()
		return err
	}
	if err := gz.Close(); err != nil {
		f.Close()
		return err
	}
	return f.Close()
}

// fingerprintDir — відбиток теки (імена, розміри, дати) для перезбирання malware.zip лише при змінах.
func fingerprintDir(root string) (string, error) {
	h := sha256.New()
	err := filepath.Walk(root, func(p string, st os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if st.Mode().IsRegular() && st.Name() != ".DS_Store" {
			rel, _ := filepath.Rel(root, p)
			fmt.Fprintf(h, "%s\t%d\t%d\n", filepath.ToSlash(rel), st.Size(), st.ModTime().Unix())
		}
		return nil
	})
	return hex.EncodeToString(h.Sum(nil)), err
}

// Prepare збирає (або бере зі сховку на диску) обидва архіви, розпаковує корпус для Мака і викладає
// архіви в сховок Forgejo, якщо їх там ще немає. say — повідомлення в термінал.
func Prepare(t config.Tests, sec *config.Resolver, say func(string, ...any)) (*Assets, error) {
	if !t.Enabled {
		return nil, nil
	}
	local := config.ExpandHome(t.LocalDir)
	if err := os.MkdirAll(local, 0o700); err != nil {
		return nil, err
	}
	files, fpCorpus, err := collect(t)
	if err != nil {
		return nil, err
	}
	fpMal := ""
	malDir := config.ExpandHome(t.Malware)
	if t.Malware != "" {
		if fpMal, err = fingerprintDir(malDir); err != nil {
			return nil, fmt.Errorf("malware folder %s: %w", t.Malware, err)
		}
	}
	sum := sha256.Sum256([]byte(fpCorpus + fpMal))
	a := &Assets{Version: hex.EncodeToString(sum[:])[:16]}
	dir := filepath.Join(local, a.Version)
	corpus := filepath.Join(dir, "corpus.tar.gz")
	malware := filepath.Join(dir, "malware.zip")

	// ---- архіви: збираються лише для нової версії
	if _, err := os.Stat(corpus); err != nil {
		say("test assets: new version %s - packing %d files", a.Version, len(files))
		os.MkdirAll(dir, 0o700)
		if err := writeTarGz(corpus+".tmp", files); err != nil {
			return nil, err
		}
		os.Rename(corpus+".tmp", corpus)
		if t.Malware != "" {
			// zip -P: ZipCrypto з паролем — Python (zipfile) на ВМ розпаковує його без сторонніх програм
			c := exec.Command("zip", "-q", "-r", "-P", MalwareZipKey, malware+".tmp", ".", "-x", ".DS_Store")
			c.Dir = malDir
			if out, err := c.CombinedOutput(); err != nil {
				return nil, fmt.Errorf("zip malware: %v %s", err, strings.TrimSpace(string(out)))
			}
			os.Rename(malware+".tmp", malware)
		}
		// розпакована копія для Мака
		if err := untarGz(corpus, filepath.Join(dir, "unpacked")); err != nil {
			return nil, err
		}
		cleanOld(local, a.Version)
	}
	a.LocalCorpus = filepath.Join(dir, "unpacked", "corpus")
	a.LocalSeeds = filepath.Join(dir, "unpacked", "seeds")
	if t.Malware != "" {
		a.LocalMalware = malDir
	}

	// ---- сховок Forgejo: для віддалених машин
	if t.Store.URL == "" {
		return a, nil
	}
	// помилка тут не скасовує тести Мака: повертаємо локальну частину, віддалені машини ці кроки пропустять
	if a.Token, err = sec.Get(t.Store.TokenRef); err != nil {
		return a, err
	}
	base := fmt.Sprintf("%s/api/packages/%s/generic/%s/%s/", strings.TrimRight(t.Store.URL, "/"), t.Store.Owner, t.Store.Package, a.Version)
	if err := upload(base+"corpus.tar.gz", corpus, a.Token, say); err != nil {
		return a, err
	}
	if t.Malware != "" {
		if err := upload(base+"malware.zip", malware, a.Token, say); err != nil {
			return a, err
		}
		a.MalwareURL = base + "malware.zip"
	}
	a.CorpusURL = base + "corpus.tar.gz"
	return a, nil
}

// upload кладе файл у generic package Forgejo, якщо його там ще немає (версія = хеш, тож вміст не міняється).
func upload(url, path, token string, say func(string, ...any)) error {
	req, _ := http.NewRequest("HEAD", url, nil)
	req.Header.Set("Authorization", "token "+token)
	if r, err := (&http.Client{Timeout: 20 * time.Second}).Do(req); err == nil {
		r.Body.Close()
		if r.StatusCode == http.StatusOK {
			return nil // уже є
		}
	}
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()
	st, _ := f.Stat()
	say("test assets: upload %s (%d MB)", filepath.Base(path), st.Size()>>20)
	req, _ = http.NewRequest("PUT", url, f)
	req.ContentLength = st.Size()
	req.Header.Set("Authorization", "token "+token)
	r, err := (&http.Client{Timeout: 30 * time.Minute}).Do(req)
	if err != nil {
		return err
	}
	defer r.Body.Close()
	if r.StatusCode != http.StatusCreated && r.StatusCode != http.StatusConflict {
		b, _ := io.ReadAll(r.Body)
		return fmt.Errorf("upload %s: %s %s", filepath.Base(path), r.Status, strings.TrimSpace(string(b)))
	}
	return nil
}

// untarGz розпаковує tar.gz у dst (шляхи поза dst відхиляються).
func untarGz(src, dst string) error {
	f, err := os.Open(src)
	if err != nil {
		return err
	}
	defer f.Close()
	gz, err := gzip.NewReader(f)
	if err != nil {
		return err
	}
	root := filepath.Clean(dst) + string(os.PathSeparator)
	tr := tar.NewReader(gz)
	for {
		h, err := tr.Next()
		if err == io.EOF {
			return nil
		}
		if err != nil {
			return err
		}
		p := filepath.Join(dst, h.Name)
		if !strings.HasPrefix(p, root) {
			return fmt.Errorf("bad path in archive: %s", h.Name)
		}
		if h.Typeflag != tar.TypeReg {
			continue
		}
		os.MkdirAll(filepath.Dir(p), 0o755)
		out, err := os.Create(p)
		if err != nil {
			return err
		}
		_, err = io.Copy(out, tr)
		out.Close()
		if err != nil {
			return err
		}
	}
}

// cleanOld видаляє локальні копії попередніх версій (лишає лише keep).
func cleanOld(local, keep string) {
	entries, _ := os.ReadDir(local)
	for _, e := range entries {
		if e.IsDir() && e.Name() != keep && len(e.Name()) == 16 {
			os.RemoveAll(filepath.Join(local, e.Name()))
		}
	}
}

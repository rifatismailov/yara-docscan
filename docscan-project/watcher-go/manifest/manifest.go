// Package manifest — підписаний маніфест релізу DocScan: що в релізі і як перевірити, що це справді наш реліз.
//
// CI (cirun publish) після зеленого прогону кладе в реліз поруч із пакетом:
//
//	manifest.json  версія, збірка, коміт; пакет (ім'я, розмір, sha256); sha256 кожного файлу всередині пакета
//	manifest.sig   "ed25519 <key_id> <підпис base64>" — підпис байтів manifest.json приватним ключем CI
//
// Updater на ПК (docscan-updater) приймає оновлення ЛИШЕ з дійсним підписом одного з довірених ключів
// (OfficialKeys + extra_public_keys з конфігу) — неважливо, звідки прийшли файли (GitHub, дзеркало, адреса з
// маркера агента): підмінене дзеркало чи підроблений маркер нічого чужого не встановлять.
package manifest

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"regexp"
	"strconv"
	"strings"
)

// Продукти маніфесту: updater не прийме маніфест чужого продукту / платформи (пакет правил — не програма).
const (
	Product      = "docscan-windows-x64" // програма (реліз yara-docscan): manifest.json / manifest.sig
	ProductRules = "docscan-rules"       // пакет правил (реліз yara-docscan-rules): rules-manifest.json / rules-manifest.sig
)

// Schema — версія формату маніфесту.
const Schema = 1

// OfficialKeys — публічні ключі CI DocScan (приватний — KeePassXC CI/Release/signing-key, секрет Forgejo
// CI_SIGNING_KEY). Новий ключ додається сюди ДО того, як ним почнуть підписувати (ПК мають його знати).
var OfficialKeys = []string{
	"ed25519:Z8A8gqmTQqgU4o2fnmrPp8iTHjYbtzUMHLaOmU8sX4s=", // dbd897f7, 2026-11-19
}

// Manifest — вміст manifest.json.
type Manifest struct {
	Schema  int               `json:"schema"`
	Product string            `json:"product"`
	Version string            `json:"version"` // vX.Y.Z
	Build   string            `json:"build"`   // <дата>-<коміт>
	Commit  string            `json:"commit"`
	Created string            `json:"created"` // RFC 3339
	Package File              `json:"package"`
	Files   map[string]string `json:"files"` // шлях у пакеті (з "/") -> sha256
}

// File — файл релізу.
type File struct {
	Name   string `json:"name"`
	Size   int64  `json:"size"`
	SHA256 string `json:"sha256"`
}

var versionRe = regexp.MustCompile(`^v(\d+)\.(\d+)\.(\d+)$`)
var hexRe = regexp.MustCompile(`^[0-9a-f]{64}$`)

// Check — маніфест цілісний: продукт, формат, версія, хеші.
func (m *Manifest) Check() error {
	switch {
	case m.Schema != Schema:
		return fmt.Errorf("manifest schema %d, expected %d", m.Schema, Schema)
	case m.Product != Product && m.Product != ProductRules:
		return fmt.Errorf("manifest product %q is not a DocScan product", m.Product)
	case !versionRe.MatchString(m.Version):
		return fmt.Errorf("manifest version %q is not vX.Y.Z", m.Version)
	case m.Package.Name == "" || strings.ContainsAny(m.Package.Name, `/\`) || m.Package.Size <= 0 || !hexRe.MatchString(m.Package.SHA256):
		return fmt.Errorf("manifest package entry is invalid")
	case len(m.Files) == 0:
		return fmt.Errorf("manifest lists no files")
	}
	for p, h := range m.Files {
		if !SafePath(p) || !hexRe.MatchString(h) {
			return fmt.Errorf("manifest file entry %q is invalid", p)
		}
	}
	return nil
}

// SafePath — відносний шлях без "..", без диска і без кореня (захист від zip-slip).
func SafePath(p string) bool {
	if p == "" || strings.Contains(p, `\`) || strings.HasPrefix(p, "/") || strings.Contains(p, ":") {
		return false
	}
	for _, s := range strings.Split(p, "/") {
		if s == "" || s == "." || s == ".." {
			return false
		}
	}
	return true
}

// KeyID — перші 4 байти sha256 публічного ключа (hex).
func KeyID(pub ed25519.PublicKey) string {
	h := sha256.Sum256(pub)
	return hex.EncodeToString(h[:4])
}

// ParseKey — "ed25519:<base64>" -> ключ.
func ParseKey(s string) (ed25519.PublicKey, error) {
	b64, ok := strings.CutPrefix(strings.TrimSpace(s), "ed25519:")
	if !ok {
		return nil, fmt.Errorf("public key %q: expected ed25519:<base64>", s)
	}
	b, err := base64.StdEncoding.DecodeString(b64)
	if err != nil || len(b) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("public key %q: not a 32-byte ed25519 key", s)
	}
	return ed25519.PublicKey(b), nil
}

// Sign — підпис для manifest.sig. seed — 32 байти (base64 у KeePassXC / секреті CI).
func Sign(data []byte, seedB64 string) (string, error) {
	seed, err := base64.StdEncoding.DecodeString(strings.TrimSpace(seedB64))
	if err != nil || len(seed) != ed25519.SeedSize {
		return "", fmt.Errorf("signing key: expected a base64 32-byte ed25519 seed")
	}
	priv := ed25519.NewKeyFromSeed(seed)
	pub := priv.Public().(ed25519.PublicKey)
	return fmt.Sprintf("ed25519 %s %s\n", KeyID(pub), base64.StdEncoding.EncodeToString(ed25519.Sign(priv, data))), nil
}

// PublicKeyOf — "ed25519:<base64>" публічного ключа для seed (щоб CI перевірив, що ключ — один з OfficialKeys).
func PublicKeyOf(seedB64 string) (string, error) {
	seed, err := base64.StdEncoding.DecodeString(strings.TrimSpace(seedB64))
	if err != nil || len(seed) != ed25519.SeedSize {
		return "", fmt.Errorf("signing key: expected a base64 32-byte ed25519 seed")
	}
	pub := ed25519.NewKeyFromSeed(seed).Public().(ed25519.PublicKey)
	return "ed25519:" + base64.StdEncoding.EncodeToString(pub), nil
}

// Verify перевіряє підпис data ключем з keys і розбирає маніфест. Повертає маніфест і key_id ключа.
func Verify(data []byte, sig string, keys []string) (*Manifest, string, error) {
	f := strings.Fields(sig)
	if len(f) != 3 || f[0] != "ed25519" {
		return nil, "", fmt.Errorf("manifest.sig: expected \"ed25519 <key_id> <signature>\"")
	}
	s, err := base64.StdEncoding.DecodeString(f[2])
	if err != nil || len(s) != ed25519.SignatureSize {
		return nil, "", fmt.Errorf("manifest.sig: bad signature")
	}
	ok := false
	for _, k := range keys {
		pub, err := ParseKey(k)
		if err != nil {
			continue
		}
		if KeyID(pub) == f[1] && ed25519.Verify(pub, data, s) {
			ok = true
			break
		}
	}
	if !ok {
		return nil, "", fmt.Errorf("manifest signature is not valid for any trusted key (key_id %s)", f[1])
	}
	var m Manifest
	if err := json.Unmarshal(data, &m); err != nil {
		return nil, "", fmt.Errorf("manifest.json: %w", err)
	}
	if err := m.Check(); err != nil {
		return nil, "", err
	}
	return &m, f[1], nil
}

// VerifyProduct — Verify + маніфест саме цього продукту.
func VerifyProduct(data []byte, sig string, keys []string, product string) (*Manifest, string, error) {
	m, id, err := Verify(data, sig, keys)
	if err != nil {
		return nil, "", err
	}
	if m.Product != product {
		return nil, "", fmt.Errorf("manifest product %q, expected %q", m.Product, product)
	}
	return m, id, nil
}

// Compare — порівняння версій vX.Y.Z: -1, 0, 1. Невідома / порожня версія менша за будь-яку правильну.
func Compare(a, b string) int {
	pa, pb := parse(a), parse(b)
	for i := 0; i < 3; i++ {
		switch {
		case pa[i] < pb[i]:
			return -1
		case pa[i] > pb[i]:
			return 1
		}
	}
	return 0
}

func parse(v string) [3]int {
	m := versionRe.FindStringSubmatch(v)
	if m == nil {
		return [3]int{-1, -1, -1}
	}
	var r [3]int
	for i := 0; i < 3; i++ {
		r[i], _ = strconv.Atoi(m[i+1])
	}
	return r
}

// ValidVersion — рядок має вигляд vX.Y.Z.
func ValidVersion(v string) bool { return versionRe.MatchString(v) }

// VersionFromTitle — vX.Y.Z з першого рядка VERSION.txt пакета ("DocScan v1.0.3 (build 20261119-7182ee86)").
func VersionFromTitle(line string) string {
	for _, f := range strings.Fields(line) {
		if versionRe.MatchString(f) {
			return f
		}
	}
	return ""
}

// VerifySig — підпис "ed25519 <key_id> <base64>" над data будь-яким з keys (без розбору вмісту: для інших
// підписаних файлів, напр. списків організації). Повертає key_id.
func VerifySig(data []byte, sig string, keys []string) (string, error) {
	f := strings.Fields(sig)
	if len(f) != 3 || f[0] != "ed25519" {
		return "", fmt.Errorf("signature: expected \"ed25519 <key_id> <signature>\"")
	}
	s, err := base64.StdEncoding.DecodeString(f[2])
	if err != nil || len(s) != ed25519.SignatureSize {
		return "", fmt.Errorf("signature: bad signature")
	}
	for _, k := range keys {
		pub, err := ParseKey(k)
		if err != nil {
			continue
		}
		if KeyID(pub) == f[1] && ed25519.Verify(pub, data, s) {
			return f[1], nil
		}
	}
	return "", fmt.Errorf("signature is not valid for any trusted key (key_id %s)", f[1])
}

// NewSeed — новий ключ ed25519: seed (base64, тримати в секреті) і публічний ключ "ed25519:<base64>".
func NewSeed() (seedB64, pub string, err error) {
	p, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		return "", "", err
	}
	return base64.StdEncoding.EncodeToString(priv.Seed()), "ed25519:" + base64.StdEncoding.EncodeToString(p), nil
}

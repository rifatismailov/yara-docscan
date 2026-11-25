package main

// Сертифікат HTTPS для 127.0.0.1: самопідписаний, НЕ CA (не може підписати інші сертифікати), лише для 127.0.0.1 /
// ::1 / localhost. install.ps1 кладе його публічну частину (cert.cer) у довірені кореневі Windows
// (Cert:\LocalMachine\Root), щоб браузер не попереджав; uninstall.ps1 прибирає.

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha1"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/pem"
	"math/big"
	"net"
	"os"
	"strings"
	"time"
)

// CertCN — ім'я в сертифікаті (за ним install.ps1 / uninstall.ps1 знаходять старі копії в Root).
const CertCN = "DocScan Web 127.0.0.1"

const (
	certLife  = 5 * 365 * 24 * time.Hour
	certRenew = 90 * 24 * time.Hour // менше — новий сертифікат під час встановлення
)

// ensureCert — сертифікат є і дійсний ще certRenew — лишити; інакше новий. Повертає SHA-1 відбиток (як у Windows).
func ensureCert(p paths, now time.Time) (thumb string, made bool, err error) {
	if b, err := os.ReadFile(p.certPEM()); err == nil {
		if c := parseCert(b); c != nil && c.NotAfter.Sub(now) > certRenew && fileExists(p.keyPEM()) {
			if !fileExists(p.certDER()) {
				os.WriteFile(p.certDER(), c.Raw, 0o644)
			}
			return thumbprint(c.Raw), false, nil
		}
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return "", false, err
	}
	serial, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 127))
	host, _ := os.Hostname()
	tpl := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: CertCN, Organization: []string{"DocScan"}, OrganizationalUnit: []string{host}},
		NotBefore:             now.Add(-time.Hour),
		NotAfter:              now.Add(certLife),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IsCA:                  false,
		DNSNames:              []string{"localhost"},
		IPAddresses:           []net.IP{net.ParseIP("127.0.0.1"), net.ParseIP("::1")},
	}
	der, err := x509.CreateCertificate(rand.Reader, tpl, tpl, &key.PublicKey, key)
	if err != nil {
		return "", false, err
	}
	kb, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return "", false, err
	}
	for _, f := range []struct {
		path string
		b    []byte
		mode os.FileMode
	}{
		{p.keyPEM(), pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: kb}), 0o600},
		{p.certPEM(), pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o644},
		{p.certDER(), der, 0o644},
	} {
		if err := writeFileAtomic(f.path, f.b, f.mode); err != nil {
			return "", false, err
		}
	}
	return thumbprint(der), true, nil
}

func parseCert(pemBytes []byte) *x509.Certificate {
	if blk, _ := pem.Decode(pemBytes); blk != nil {
		if c, err := x509.ParseCertificate(blk.Bytes); err == nil {
			return c
		}
	}
	return nil
}

// certNotAfter — до коли дійсний сертифікат (PEM).
func certNotAfter(b []byte) time.Time {
	if c := parseCert(b); c != nil {
		return c.NotAfter
	}
	return time.Time{}
}

func thumbprint(der []byte) string {
	h := sha1.Sum(der) // відбиток сертифіката у Windows — SHA-1 (лише ідентифікатор, не перевірка)
	return strings.ToUpper(hex.EncodeToString(h[:]))
}

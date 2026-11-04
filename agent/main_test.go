package main

import (
	"bytes"
	"compress/gzip"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestEnvelopeRecipientIntegrityAndNoPlaintext(t *testing.T) {
	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	der, _ := x509.MarshalPKIXPublicKey(&key.PublicKey)
	token := bytes.Repeat([]byte{7}, 32)
	cfg := Config{TaskID: "fixture-task", PublicKey: string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der})), Token: hex.EncodeToString(token)}
	raw, err := seal(cfg, "snapshot", map[string]any{"fixture": "sensitive-local-fixture"})
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(raw, []byte("sensitive-local-fixture")) {
		t.Fatal("plaintext exposed")
	}
	var e Envelope
	json.Unmarshal(raw, &e)
	if e.MAC != envelopeMAC(e, token) {
		t.Fatal("MAC")
	}
	ek, _ := base64.StdEncoding.DecodeString(e.EncryptedKey)
	symmetric, err := rsa.DecryptOAEP(sha256.New(), rand.Reader, key, ek, []byte("gaga-envelope/1"))
	if err != nil {
		t.Fatal(err)
	}
	block, _ := aes.NewCipher(symmetric)
	gcm, _ := cipher.NewGCM(block)
	nonce, _ := base64.StdEncoding.DecodeString(e.Nonce)
	ct, _ := base64.StdEncoding.DecodeString(e.Ciphertext)
	aad := []byte(strings.Join([]string{e.TaskID, e.Sequence, e.CreatedAt}, "\n"))
	z, err := gcm.Open(nil, nonce, ct, aad)
	if err != nil {
		t.Fatal(err)
	}
	reader, _ := gzip.NewReader(bytes.NewReader(z))
	plain, _ := io.ReadAll(reader)
	if !bytes.Contains(plain, []byte("sensitive-local-fixture")) {
		t.Fatal("missing content")
	}
	ct[0] ^= 1
	if _, err = gcm.Open(nil, nonce, ct, aad); err == nil {
		t.Fatal("tamper accepted")
	}
	wrong, _ := rsa.GenerateKey(rand.Reader, 2048)
	if _, err = rsa.DecryptOAEP(sha256.New(), rand.Reader, wrong, ek, []byte("gaga-envelope/1")); err == nil {
		t.Fatal("wrong recipient accepted")
	}
}

func TestWriteCrossLanguageFixture(t *testing.T) {
	dir := os.Getenv("GAGA_INTEROP_DIR")
	if dir == "" {
		t.Skip("fixture regeneration is opt-in")
	}
	if err := os.MkdirAll(dir, 0700); err != nil {
		t.Fatal(err)
	}
	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	der, _ := x509.MarshalPKIXPublicKey(&key.PublicKey)
	priv, _ := x509.MarshalPKCS8PrivateKey(key)
	cfg := Config{TaskID: "37b6d5e5-4e54-42c2-a1b3-3ae109733d2f", PublicKey: string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der})), Token: strings.Repeat("07", 32)}
	raw, err := seal(cfg, "snapshot", map[string]any{"fixture": "Go-generated offline test vector, no real host evidence", "commands": []any{}, "files": []any{}})
	if err != nil {
		t.Fatal(err)
	}
	for name, data := range map[string][]byte{"test-only-private.pem": pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: priv}), "envelope.json": raw, "public.pem": []byte(cfg.PublicKey)} {
		if err := os.WriteFile(filepath.Join(dir, name), data, 0600); err != nil {
			t.Fatal(err)
		}
	}
}

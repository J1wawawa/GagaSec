package main

import (
	"bytes"
	"compress/gzip"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"time"
)

type Config struct {
	Format          string `json:"format"`
	TaskID          string `json:"taskId"`
	PublicKey       string `json:"publicKey"`
	Token           string `json:"token"`
	ExpiresAt       string `json:"expiresAt"`
	Mode            string `json:"mode"`
	Interface       string `json:"interface"`
	DurationSeconds int    `json:"durationSeconds"`
	BatchSeconds    int    `json:"batchSeconds"`
	Snaplen         int    `json:"snaplen"`
	IncludeHTTP     bool   `json:"includeHttp"`
	CallbackURL     string `json:"callbackUrl"`
	Certificate     string `json:"certificate"`
	MaxOutputBytes  int64  `json:"maxOutputBytes"`
}
type Envelope struct {
	Format       string `json:"format"`
	TaskID       string `json:"taskId"`
	Sequence     string `json:"sequence"`
	CreatedAt    string `json:"createdAt"`
	EncryptedKey string `json:"encryptedKey"`
	Nonce        string `json:"nonce"`
	Ciphertext   string `json:"ciphertext"`
	MAC          string `json:"mac"`
}

const agentVersion = "0.10.1"

func randomID() string {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	return hex.EncodeToString(b)
}
func envelopeMAC(e Envelope, token []byte) string {
	mac := hmac.New(sha256.New, token)
	io.WriteString(mac, strings.Join([]string{e.TaskID, e.Sequence, e.CreatedAt, e.EncryptedKey, e.Nonce, e.Ciphertext}, "\n"))
	return hex.EncodeToString(mac.Sum(nil))
}
func seal(cfg Config, kind string, body any) ([]byte, error) {
	block, _ := pem.Decode([]byte(cfg.PublicKey))
	if block == nil {
		return nil, errors.New("invalid recipient key")
	}
	parsed, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, err
	}
	key, ok := parsed.(*rsa.PublicKey)
	if !ok {
		return nil, errors.New("recipient must be RSA")
	}
	token, err := hex.DecodeString(cfg.Token)
	if err != nil || len(token) != 32 {
		return nil, errors.New("invalid task credential")
	}
	hostname, _ := os.Hostname()
	plain, err := json.Marshal(map[string]any{"format": "gaga-collection/1", "kind": kind, "taskId": cfg.TaskID, "hostname": hostname, "collectedAt": time.Now().UTC().Format(time.RFC3339Nano), "os": runtime.GOOS, "architecture": runtime.GOARCH, "body": body, "limitations": []string{"Task credential and encryption verify package integrity and possession of a task credential, not an uncompromised host or trusted attribution.", "eBPF observes only this network namespace and configured interface; TLS is ciphertext, no TCP reassembly or process attribution is provided."}})
	if err != nil {
		return nil, err
	}
	if len(plain) > 16<<20 {
		return nil, errors.New("plaintext exceeds 16 MiB")
	}
	var zipped bytes.Buffer
	zipper := gzip.NewWriter(&zipped)
	if _, err = zipper.Write(plain); err != nil {
		return nil, err
	}
	if err = zipper.Close(); err != nil {
		return nil, err
	}
	symmetric := make([]byte, 32)
	if _, err = rand.Read(symmetric); err != nil {
		return nil, err
	}
	encrypted, err := rsa.EncryptOAEP(sha256.New(), rand.Reader, key, symmetric, []byte("gaga-envelope/1"))
	if err != nil {
		return nil, err
	}
	blockCipher, err := aes.NewCipher(symmetric)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(blockCipher)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err = rand.Read(nonce); err != nil {
		return nil, err
	}
	e := Envelope{Format: "gaga-envelope/1", TaskID: cfg.TaskID, Sequence: randomID(), CreatedAt: time.Now().UTC().Format(time.RFC3339Nano), EncryptedKey: base64.StdEncoding.EncodeToString(encrypted), Nonce: base64.StdEncoding.EncodeToString(nonce)}
	aad := strings.Join([]string{e.TaskID, e.Sequence, e.CreatedAt}, "\n")
	e.Ciphertext = base64.StdEncoding.EncodeToString(gcm.Seal(nil, nonce, zipped.Bytes(), []byte(aad)))
	e.MAC = envelopeMAC(e, token)
	return json.Marshal(e)
}

type limitWriter struct {
	data      bytes.Buffer
	max       int
	truncated bool
}

func (w *limitWriter) Write(p []byte) (int, error) {
	n := len(p)
	left := w.max - w.data.Len()
	if left > 0 {
		if left < len(p) {
			w.data.Write(p[:left])
			w.truncated = true
		} else {
			w.data.Write(p)
		}
	} else {
		w.truncated = true
	}
	return n, nil
}
func command(name string, args ...string) map[string]any {
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, name, args...)
	out := &limitWriter{max: 256 << 10}
	cmd.Stdout = out
	cmd.Stderr = out
	err := cmd.Run()
	record := map[string]any{"command": append([]string{name}, args...), "output": out.data.String(), "truncated": out.truncated}
	if err != nil {
		record["error"] = err.Error()
	}
	record["sha256"] = fmt.Sprintf("%x", sha256.Sum256(out.data.Bytes()))
	return record
}
func collectionMetadata(files []string, commands []string, network string, duration int) map[string]any {
	zone, offset := time.Now().Zone()
	missing := []any{}
	permissions := []any{}
	for _, name := range commands {
		status := "granted"
		detail := "tool is present; command output is still bounded and may report a runtime permission error"
		if _, err := exec.LookPath(name); err != nil {
			status = "denied"
			detail = "tool is not installed or is not on PATH"
			missing = append(missing, map[string]any{"name": name, "reason": detail, "requiredPermission": "executable"})
		}
		permissions = append(permissions, map[string]any{"name": name, "status": status, "detail": detail})
	}
	return map[string]any{
		"collector":   map[string]any{"name": "gaga-agent", "version": agentVersion, "build": runtime.Version(), "platform": runtime.GOOS, "architecture": runtime.GOARCH},
		"permissions": permissions,
		"timezone":    zone,
		// A receiver reference is required to measure clock skew. Keep the
		// field explicit and unknown instead of confusing UTC timezone offset
		// with clock drift; utcOffsetSeconds remains useful for normalization.
		"clockOffsetSeconds": nil,
		"utcOffsetSeconds":   offset,
		"clockOffsetSource":  "not measured; receiver clock reference unavailable",
		"collectionScope":    map[string]any{"files": files, "commands": commands, "network": network, "durationSeconds": duration},
		"missingItems":       missing,
	}
}
func snapshot() map[string]any {
	meta := collectionMetadata(
		[]string{"/etc/os-release", "/proc/version", "/proc/meminfo", "/proc/mounts", "/proc/net/tcp", "/proc/net/udp"},
		[]string{"ps", "ss", "docker", "tasklist.exe", "netstat.exe", "systeminfo.exe"},
		"configured host snapshot only",
		0,
	)
	body := map[string]any{
		"readOnly":    true,
		"environment": map[string]string{"os": runtime.GOOS, "architecture": runtime.GOARCH},
		"files":       []any{}, "commands": []any{},
		"collector": meta["collector"], "permissions": meta["permissions"], "timezone": meta["timezone"],
		"clockOffsetSeconds": meta["clockOffsetSeconds"], "utcOffsetSeconds": meta["utcOffsetSeconds"],
		"clockOffsetSource": meta["clockOffsetSource"], "collectionScope": meta["collectionScope"], "missingItems": meta["missingItems"],
	}
	files := []any{}
	commands := []any{}
	if runtime.GOOS == "linux" {
		for _, path := range []string{"/etc/os-release", "/proc/version", "/proc/meminfo", "/proc/mounts", "/proc/net/tcp", "/proc/net/udp"} {
			f, err := os.Open(path)
			if err != nil {
				files = append(files, map[string]any{"path": path, "error": err.Error()})
				body["missingItems"] = append(body["missingItems"].([]any), map[string]any{"name": path, "reason": err.Error(), "requiredPermission": "read"})
				continue
			}
			data, err := io.ReadAll(io.LimitReader(f, (256<<10)+1))
			f.Close()
			truncated := len(data) > 256<<10
			if truncated {
				data = data[:256<<10]
			}
			record := map[string]any{"path": path, "text": string(data), "sha256": fmt.Sprintf("%x", sha256.Sum256(data)), "truncated": truncated}
			if err != nil {
				record["error"] = err.Error()
			}
			files = append(files, record)
		}
		commands = append(commands, command("ps", "-eo", "pid,ppid,user,comm"), command("ss", "-tunap"), command("docker", "ps", "--no-trunc", "--format", "{{json .}}"), command("docker", "info", "--format", "{{json .SecurityOptions}}"))
	} else if runtime.GOOS == "windows" {
		commands = append(commands, command("tasklist.exe", "/FO", "CSV"), command("netstat.exe", "-ano"), command("systeminfo.exe", "/FO", "CSV"))
	} else {
		commands = append(commands, command("ps", "-axo", "pid,ppid,user,comm"))
	}
	body["files"] = files
	body["commands"] = commands
	scope := body["collectionScope"].(map[string]any)
	scope["files"] = []string{"/etc/os-release", "/proc/version", "/proc/meminfo", "/proc/mounts", "/proc/net/tcp", "/proc/net/udp"}
	scope["commands"] = []string{"ps", "ss", "docker"}
	if runtime.GOOS != "linux" {
		body["missingItems"] = append(body["missingItems"].([]any), map[string]any{"name": "linux-network-files", "reason": "platform does not expose /proc network files", "requiredPermission": "linux"})
	}
	body["limitations"] = []string{"Fixed read-only metadata collection; no passwords, browser data, environment variables, shell history, sample execution, arbitrary command dispatch or persistence.", "Missing tools, permissions and truncation are reported per section. This is not exhaustive forensics or proof that the host is clean."}
	return body
}

type writer struct {
	cfg    Config
	dir    string
	bytes  int64
	client *http.Client
}

func newWriter(cfg Config, dir string) (*writer, error) {
	if err := os.MkdirAll(dir, 0700); err != nil {
		return nil, err
	}
	w := &writer{cfg: cfg, dir: dir}
	if cfg.CallbackURL != "" {
		if !strings.HasPrefix(cfg.CallbackURL, "https://") {
			return nil, errors.New("callback requires HTTPS")
		}
		roots := x509.NewCertPool()
		if !roots.AppendCertsFromPEM([]byte(cfg.Certificate)) {
			return nil, errors.New("receiver certificate is required")
		}
		w.client = &http.Client{Timeout: 15 * time.Second, Transport: &http.Transport{TLSClientConfig: &tls.Config{RootCAs: roots, MinVersion: tls.VersionTLS12}}, CheckRedirect: func(_ *http.Request, _ []*http.Request) error { return http.ErrUseLastResponse }}
	}
	return w, nil
}
func (w *writer) save(kind string, body any) error {
	data, err := seal(w.cfg, kind, body)
	if err != nil {
		return err
	}
	if w.bytes+int64(len(data)) > w.cfg.MaxOutputBytes {
		return errors.New("encrypted output budget reached; collection stopped")
	}
	var e Envelope
	if err = json.Unmarshal(data, &e); err != nil {
		return err
	}
	path := filepath.Join(w.dir, "gaga-"+e.Sequence+".json")
	if err = os.WriteFile(path, data, 0600); err != nil {
		return err
	}
	w.bytes += int64(len(data))
	fmt.Printf("Encrypted batch %s (%d bytes)\n", e.Sequence, len(data))
	if w.client != nil {
		req, err := http.NewRequest("POST", strings.TrimRight(w.cfg.CallbackURL, "/")+"/v1/collect/"+w.cfg.TaskID, bytes.NewReader(data))
		if err != nil {
			return err
		}
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Authorization", "Bearer "+w.cfg.Token)
		res, err := w.client.Do(req)
		if err != nil {
			fmt.Fprintln(os.Stderr, "Upload unavailable; encrypted file retained:", err)
			return nil
		}
		io.Copy(io.Discard, io.LimitReader(res.Body, 4096))
		res.Body.Close()
		if res.StatusCode != http.StatusAccepted && res.StatusCode != http.StatusConflict {
			fmt.Fprintln(os.Stderr, "Upload rejected; encrypted file retained, HTTP", res.StatusCode)
		} else {
			fmt.Println("Receiver accepted encrypted batch; offline copy retained")
		}
	}
	return nil
}
func main() {
	path := flag.String("config", "gaga-task.json", "task configuration")
	out := flag.String("out", "gaga-output", "encrypted output directory")
	check := flag.Bool("check", false, "inspect runtime requirements without collecting")
	flag.Parse()
	data, err := os.ReadFile(*path)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	var cfg Config
	if err = json.Unmarshal(data, &cfg); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	expiry, err := time.Parse(time.RFC3339, cfg.ExpiresAt)
	if err != nil || !time.Now().Before(expiry) || cfg.Format != "gaga-task/1" || cfg.DurationSeconds < 5 || cfg.DurationSeconds > 86400 || cfg.BatchSeconds < 5 || cfg.BatchSeconds > 300 || cfg.Snaplen < 128 || cfg.Snaplen > 4096 || cfg.MaxOutputBytes < 1 || cfg.MaxOutputBytes > 512<<20 {
		fmt.Fprintln(os.Stderr, "Invalid or expired task configuration")
		os.Exit(1)
	}
	if *check {
		json.NewEncoder(os.Stdout).Encode(map[string]any{"os": runtime.GOOS, "arch": runtime.GOARCH, "mode": cfg.Mode, "runtime": captureRequirements(), "taskExpired": false})
		return
	}
	w, err := newWriter(cfg, *out)
	if err == nil {
		switch cfg.Mode {
		case "snapshot":
			err = w.save("snapshot", snapshot())
		case "ebpf":
			err = capture(cfg, w)
		default:
			err = errors.New("unknown task mode")
		}
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

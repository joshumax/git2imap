package gitbackend

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"sort"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/ssh"
)

var scpRemotePattern = regexp.MustCompile(`^[A-Za-z0-9._-]+@(\[[^\]]+\]|[A-Za-z0-9.-]+):[^\s]+$`)

type Auth struct {
	Username   string `json:"username,omitempty"`
	Password   string `json:"password,omitempty"`
	PrivateKey string `json:"private_key,omitempty"`
	Passphrase string `json:"passphrase,omitempty"`
}

func EncodeAuth(auth Auth) ([]byte, error) {
	return json.Marshal(auth)
}

func DecodeAuth(data []byte) (Auth, error) {
	var auth Auth
	err := json.Unmarshal(data, &auth)
	return auth, err
}

type Commit struct {
	OID         string
	Subject     string
	AuthorName  string
	AuthorEmail string
	AuthoredAt  time.Time
}

type Branch struct {
	Name string
	OID  string
}

type Backend struct {
	GitCommand   string
	SSHCommand   string
	KnownHosts   string
	CloneTimeout time.Duration
	Timeout      time.Duration
	Logger       *slog.Logger
}

func ValidateRemote(raw string) error {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return errors.New("repository URL is required")
	}
	if strings.HasPrefix(raw, "-") || strings.ContainsAny(raw, "\r\n\x00") {
		return errors.New("invalid repository URL")
	}
	if scpRemotePattern.MatchString(raw) {
		return nil
	}
	u, err := url.Parse(raw)
	if err != nil || u.Scheme == "" {
		return errors.New("repository URL must use http, https, ssh, or SCP-style SSH syntax")
	}
	switch strings.ToLower(u.Scheme) {
	case "http", "https":
		if u.Host == "" {
			return errors.New("HTTP repository URL requires a host")
		}
		if u.User != nil {
			return errors.New("put HTTP credentials in the authentication fields, not in the repository URL")
		}
	case "ssh":
		if u.Host == "" || u.User == nil {
			return errors.New("SSH repository URL requires a user and host")
		}
	default:
		return fmt.Errorf("unsupported repository URL scheme %q", u.Scheme)
	}
	return nil
}

func RemoteHost(raw string) (string, string, bool) {
	if match := scpRemotePattern.FindStringSubmatch(raw); len(match) == 2 {
		return strings.Trim(match[1], "[]"), "22", true
	}
	u, err := url.Parse(raw)
	if err != nil || strings.ToLower(u.Scheme) != "ssh" {
		return "", "", false
	}
	host := u.Hostname()
	port := u.Port()
	if port == "" {
		port = "22"
	}
	return host, port, host != ""
}

func (b *Backend) Clone(ctx context.Context, remote, target, authType string, auth Auth) (string, error) {
	if err := ValidateRemote(remote); err != nil {
		return "", err
	}
	if err := os.MkdirAll(filepath.Dir(target), 0o700); err != nil {
		return "", err
	}
	tmp, err := os.MkdirTemp(filepath.Dir(target), filepath.Base(target)+".tmp-")
	if err != nil {
		return "", fmt.Errorf("create temporary repository cache: %w", err)
	}
	defer os.RemoveAll(tmp)

	cloneTimeout := b.CloneTimeout
	if cloneTimeout <= 0 {
		cloneTimeout = b.Timeout
	}
	cmdCtx, cancel := context.WithTimeout(ctx, cloneTimeout)
	defer cancel()
	args := []string{"clone", "--mirror", "--progress", "--", remote, tmp}
	cmd, cleanup, err := b.command(cmdCtx, "", args, remote, authType, auth)
	if err != nil {
		return "", err
	}
	defer cleanup()
	cacheName := filepath.Base(target)
	output := newGitCommandOutput(b.Logger, cacheName, auth)
	cmd.Stdout = output
	cmd.Stderr = output
	started := time.Now()
	if b.Logger != nil {
		b.Logger.Info("git clone started", "repository_cache", cacheName)
	}
	err = cmd.Run()
	output.Flush()
	if err != nil {
		if cmdCtx.Err() != nil {
			err = fmt.Errorf("%w after %s", cmdCtx.Err(), cloneTimeout)
		}
		if b.Logger != nil {
			b.Logger.Error("git clone failed",
				"repository_cache", cacheName,
				"duration", time.Since(started).Round(time.Millisecond),
				"error", err,
			)
		}
		return "", commandError("clone repository", output.Bytes(), err)
	}
	if err := renameWithRetry(ctx, tmp, target); err != nil {
		return "", fmt.Errorf("publish repository cache: %w", err)
	}
	_ = os.RemoveAll(target + ".tmp")
	if b.Logger != nil {
		b.Logger.Info("git clone completed",
			"repository_cache", cacheName,
			"duration", time.Since(started).Round(time.Millisecond),
		)
	}
	return b.hostFingerprint(remote)
}

type gitCommandOutput struct {
	mu         sync.Mutex
	output     bytes.Buffer
	pending    bytes.Buffer
	logger     *slog.Logger
	cacheName  string
	redactions []string
}

func newGitCommandOutput(logger *slog.Logger, cacheName string, auth Auth) *gitCommandOutput {
	redactions := make([]string, 0, 3)
	for _, secret := range []string{auth.Password, auth.Passphrase, auth.PrivateKey} {
		if secret != "" {
			redactions = append(redactions, secret)
		}
	}
	return &gitCommandOutput{
		logger: logger, cacheName: cacheName, redactions: redactions,
	}
}

func (w *gitCommandOutput) Write(p []byte) (int, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	_, _ = w.output.Write(p)
	for _, value := range p {
		switch value {
		case '\r', '\n':
			w.logPending()
		default:
			_ = w.pending.WriteByte(value)
		}
	}
	return len(p), nil
}

func (w *gitCommandOutput) Flush() {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.logPending()
}

func (w *gitCommandOutput) Bytes() []byte {
	w.mu.Lock()
	defer w.mu.Unlock()
	return []byte(w.redact(w.output.String()))
}

func (w *gitCommandOutput) logPending() {
	line := strings.TrimSpace(w.pending.String())
	w.pending.Reset()
	if line == "" || w.logger == nil {
		return
	}
	line = w.redact(line)
	if len(line) > 4096 {
		line = line[:4096] + "..."
	}
	w.logger.Info("git clone output", "repository_cache", w.cacheName, "output", line)
}

func (w *gitCommandOutput) redact(value string) string {
	for _, secret := range w.redactions {
		value = strings.ReplaceAll(value, secret, "[REDACTED]")
	}
	return value
}

func renameWithRetry(ctx context.Context, oldPath, newPath string) error {
	var lastErr error
	for attempt := 0; attempt < 20; attempt++ {
		if err := os.Rename(oldPath, newPath); err == nil {
			return nil
		} else {
			lastErr = err
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(100 * time.Millisecond):
		}
	}
	return lastErr
}

func (b *Backend) Fetch(ctx context.Context, remote, repoPath, authType string, auth Auth) (string, error) {
	cmdCtx, cancel := context.WithTimeout(ctx, b.Timeout)
	defer cancel()
	cmd, cleanup, err := b.command(cmdCtx, repoPath, []string{"remote", "update", "--prune"}, remote, authType, auth)
	if err != nil {
		return "", err
	}
	defer cleanup()
	output, err := cmd.CombinedOutput()
	if err != nil {
		return "", commandError("fetch repository", output, err)
	}
	return b.hostFingerprint(remote)
}

func (b *Backend) DefaultBranch(ctx context.Context, remote, repoPath, authType string, auth Auth) (string, error) {
	cmdCtx, cancel := context.WithTimeout(ctx, b.Timeout)
	defer cancel()
	cmd, cleanup, err := b.command(cmdCtx, repoPath, []string{"ls-remote", "--symref", "origin", "HEAD"}, remote, authType, auth)
	if err != nil {
		return "", err
	}
	defer cleanup()
	output, err := cmd.Output()
	if err != nil {
		return "", fmt.Errorf("discover default branch: %w", err)
	}
	for _, line := range strings.Split(string(output), "\n") {
		fields := strings.Fields(line)
		if len(fields) >= 3 && fields[0] == "ref:" && fields[2] == "HEAD" {
			return strings.TrimPrefix(fields[1], "refs/heads/"), nil
		}
	}
	return "", errors.New("remote did not advertise a default branch")
}

func (b *Backend) Branches(ctx context.Context, repoPath string) ([]Branch, error) {
	output, err := b.runLocal(ctx, repoPath, "for-each-ref", "--format=%(refname:strip=2)%00%(objectname)", "refs/heads/")
	if err != nil {
		return nil, err
	}
	var branches []Branch
	for _, line := range bytes.Split(bytes.TrimSpace(output), []byte{'\n'}) {
		fields := bytes.SplitN(line, []byte{0}, 2)
		if len(fields) == 2 {
			branches = append(branches, Branch{Name: string(fields[0]), OID: string(fields[1])})
		}
	}
	sort.Slice(branches, func(i, j int) bool { return branches[i].Name < branches[j].Name })
	return branches, nil
}

func (b *Backend) IsAncestor(ctx context.Context, repoPath, oldOID, newOID string) bool {
	if oldOID == "" || newOID == "" {
		return false
	}
	cmdCtx, cancel := context.WithTimeout(ctx, b.Timeout)
	defer cancel()
	cmd := exec.CommandContext(cmdCtx, b.GitCommand, "-C", repoPath, "merge-base", "--is-ancestor", oldOID, newOID)
	return cmd.Run() == nil
}

func (b *Backend) Commits(ctx context.Context, repoPath, revision string) ([]Commit, error) {
	output, err := b.runLocal(ctx, repoPath, "log", "--reverse", "--topo-order",
		"--format=%H%x00%s%x00%an%x00%ae%x00%aI", revision)
	if err != nil {
		return nil, err
	}
	var commits []Commit
	scanner := bufio.NewScanner(bytes.NewReader(output))
	scanner.Buffer(make([]byte, 64*1024), 4*1024*1024)
	for scanner.Scan() {
		fields := strings.Split(scanner.Text(), "\x00")
		if len(fields) != 5 {
			continue
		}
		authored, err := time.Parse(time.RFC3339, fields[4])
		if err != nil {
			return nil, fmt.Errorf("parse author date for %s: %w", fields[0], err)
		}
		commits = append(commits, Commit{
			OID: fields[0], Subject: fields[1], AuthorName: fields[2],
			AuthorEmail: fields[3], AuthoredAt: authored,
		})
	}
	return commits, scanner.Err()
}

func (b *Backend) RenderCommit(ctx context.Context, repoPath, oid string) ([]byte, error) {
	return b.runLocal(ctx, repoPath, "show", "--no-ext-diff", "--no-color", "--format=fuller",
		"--patch", "--binary", "--cc", oid)
}

func (b *Backend) runLocal(ctx context.Context, repoPath string, args ...string) ([]byte, error) {
	cmdCtx, cancel := context.WithTimeout(ctx, b.Timeout)
	defer cancel()
	fullArgs := append([]string{"-C", repoPath}, args...)
	cmd := exec.CommandContext(cmdCtx, b.GitCommand, fullArgs...)
	cmd.Env = append(os.Environ(), "GIT_TERMINAL_PROMPT=0")
	output, err := cmd.Output()
	if err != nil {
		var exitErr *exec.ExitError
		if errors.As(err, &exitErr) {
			return nil, commandError("run git", exitErr.Stderr, err)
		}
		return nil, err
	}
	return output, nil
}

func (b *Backend) command(ctx context.Context, repoPath string, args []string, remote, authType string, auth Auth) (*exec.Cmd, func(), error) {
	if repoPath != "" {
		args = append([]string{"-C", repoPath}, args...)
	}
	cmd := exec.CommandContext(ctx, b.GitCommand, args...)
	env := append(os.Environ(), "GIT_TERMINAL_PROMPT=0")
	cleanup := func() {}
	executable, err := os.Executable()
	if err != nil {
		return nil, cleanup, err
	}
	askpass, err := writeAskpass(executable)
	if err != nil {
		return nil, cleanup, err
	}
	cleanups := []func(){func() { _ = os.Remove(askpass) }}
	cleanup = func() {
		for _, fn := range cleanups {
			fn()
		}
	}
	switch authType {
	case "", "none":
	case "http":
		env = append(env,
			"GIT_ASKPASS="+askpass,
			"GIT2IMAP_ASKPASS_MODE=http",
			"GIT2IMAP_ASKPASS_USERNAME="+auth.Username,
			"GIT2IMAP_ASKPASS_PASSWORD="+auth.Password,
		)
	case "ssh":
		if auth.PrivateKey == "" {
			return nil, cleanup, errors.New("SSH private key is required")
		}
		if err := os.MkdirAll(filepath.Dir(b.KnownHosts), 0o700); err != nil {
			return nil, cleanup, err
		}
		keyFile, err := os.CreateTemp("", "git2imap-key-*")
		if err != nil {
			return nil, cleanup, err
		}
		if err := keyFile.Chmod(0o600); err != nil {
			keyFile.Close()
			os.Remove(keyFile.Name())
			return nil, cleanup, err
		}
		if _, err := keyFile.WriteString(auth.PrivateKey); err != nil {
			keyFile.Close()
			os.Remove(keyFile.Name())
			return nil, cleanup, err
		}
		keyFile.Close()
		cleanups = append(cleanups, func() { _ = os.Remove(keyFile.Name()) })
		nullKnownHosts := "/dev/null"
		if runtime.GOOS == "windows" {
			nullKnownHosts = "NUL"
		}
		sshArgs := []string{
			quoteSSHArg(b.SSHCommand), "-i", quoteSSHArg(keyFile.Name()), "-o", "IdentitiesOnly=yes",
			"-o", "StrictHostKeyChecking=accept-new", "-o", "UserKnownHostsFile=" + quoteSSHArg(b.KnownHosts),
			"-o", "GlobalKnownHostsFile=" + quoteSSHArg(nullKnownHosts),
		}
		env = append(env,
			"GIT_SSH_COMMAND="+strings.Join(sshArgs, " "),
			"SSH_ASKPASS="+askpass,
			"SSH_ASKPASS_REQUIRE=force",
			"GIT2IMAP_ASKPASS_MODE=ssh",
			"GIT2IMAP_ASKPASS_PASSWORD="+auth.Passphrase,
		)
		if runtime.GOOS != "windows" {
			env = append(env, "DISPLAY=git2imap")
		}
	default:
		return nil, cleanup, fmt.Errorf("unknown authentication type %q", authType)
	}
	cmd.Env = env
	return cmd, cleanup, nil
}

func writeAskpass(executable string) (string, error) {
	extension := ""
	body := "#!/bin/sh\nexec " + quoteShellArg(executable) + " git-askpass \"$@\"\n"
	if runtime.GOOS == "windows" {
		extension = ".cmd"
		body = "@echo off\r\n\"" + executable + "\" git-askpass %*\r\n"
	}
	file, err := os.CreateTemp("", "git2imap-askpass-*"+extension)
	if err != nil {
		return "", err
	}
	name := file.Name()
	if _, err := file.WriteString(body); err != nil {
		file.Close()
		os.Remove(name)
		return "", err
	}
	if err := file.Close(); err != nil {
		os.Remove(name)
		return "", err
	}
	if err := os.Chmod(name, 0o700); err != nil {
		os.Remove(name)
		return "", err
	}
	return name, nil
}

func quoteShellArg(value string) string {
	return "'" + strings.ReplaceAll(value, "'", "'\"'\"'") + "'"
}

func quoteSSHArg(value string) string {
	return `"` + strings.ReplaceAll(value, `"`, `\"`) + `"`
}

func commandError(action string, output []byte, err error) error {
	message := lastCommandOutput(output)
	if message == "" {
		return fmt.Errorf("%s: %w", action, err)
	}
	return fmt.Errorf("%s: %w; last git output: %s", action, err, message)
}

func lastCommandOutput(output []byte) string {
	text := strings.ReplaceAll(string(output), "\r", "\n")
	lines := strings.Split(text, "\n")
	message := ""
	for i := len(lines) - 1; i >= 0; i-- {
		if line := strings.TrimSpace(lines[i]); line != "" {
			message = line
			break
		}
	}
	if len(message) > 600 {
		message = message[:600] + "..."
	}
	return message
}

func (b *Backend) hostFingerprint(remote string) (string, error) {
	host, port, ok := RemoteHost(remote)
	if !ok {
		return "", nil
	}
	data, err := os.ReadFile(b.KnownHosts)
	if err != nil {
		return "", err
	}
	target := host
	if port != "22" {
		target = net.JoinHostPort(host, port)
	}
	for len(data) > 0 {
		_, hosts, key, _, rest, err := ssh.ParseKnownHosts(data)
		if err != nil {
			break
		}
		data = rest
		for _, knownHost := range hosts {
			if knownHost == host || knownHost == target || knownHost == "["+target+"]" {
				return ssh.FingerprintSHA256(key), nil
			}
		}
	}
	return "", nil
}

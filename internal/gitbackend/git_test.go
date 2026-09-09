package gitbackend

import (
	"bytes"
	"context"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestValidateRemote(t *testing.T) {
	valid := []string{
		"https://github.com/example/project.git",
		"http://git.example/project.git",
		"ssh://git@example.com/project.git",
		"git@example.com:project.git",
	}
	for _, value := range valid {
		if err := ValidateRemote(value); err != nil {
			t.Errorf("ValidateRemote(%q): %v", value, err)
		}
	}
	invalid := []string{"", "../repo", "file:///tmp/repo", "-uploader", "git://example.com/repo"}
	for _, value := range invalid {
		if err := ValidateRemote(value); err == nil {
			t.Errorf("ValidateRemote(%q) succeeded", value)
		}
	}
}

func TestHTTPMirrorLifecycle(t *testing.T) {
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git is not installed")
	}
	root := t.TempDir()
	work := filepath.Join(root, "work")
	runGit(t, "", "init", "-b", "main", work)
	runGit(t, work, "config", "user.name", "Example Author")
	runGit(t, work, "config", "user.email", "author@example.com")
	if err := os.WriteFile(filepath.Join(work, "README.md"), []byte("hello\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	runGit(t, work, "add", "README.md")
	runGit(t, work, "commit", "-m", "Initial commit")
	remoteDir := filepath.Join(root, "remote.git")
	runGit(t, "", "clone", "--bare", work, remoteDir)
	runGit(t, remoteDir, "update-server-info")

	server := httptest.NewServer(http.FileServer(http.Dir(root)))
	defer server.Close()
	cache := filepath.Join(t.TempDir(), "cache.git")
	var logs bytes.Buffer
	backend := &Backend{
		GitCommand: "git", SSHCommand: "ssh",
		KnownHosts: filepath.Join(t.TempDir(), "known_hosts"), Timeout: 30 * time.Second,
		Logger: slog.New(slog.NewTextHandler(&logs, nil)),
	}
	if _, err := backend.Clone(context.Background(), server.URL+"/remote.git", cache, "none", Auth{}); err != nil {
		t.Fatal(err)
	}
	for _, expected := range []string{"git clone started", "git clone output", "git clone completed"} {
		if !strings.Contains(logs.String(), expected) {
			t.Fatalf("clone logs do not contain %q:\n%s", expected, logs.String())
		}
	}
	defaultBranch, err := backend.DefaultBranch(context.Background(), server.URL+"/remote.git", cache, "none", Auth{})
	if err != nil {
		t.Fatal(err)
	}
	if defaultBranch != "main" {
		t.Fatalf("default branch = %q", defaultBranch)
	}
	branches, err := backend.Branches(context.Background(), cache)
	if err != nil {
		t.Fatal(err)
	}
	if len(branches) != 1 || branches[0].Name != "main" {
		t.Fatalf("branches = %#v", branches)
	}
	commits, err := backend.Commits(context.Background(), cache, branches[0].OID)
	if err != nil {
		t.Fatal(err)
	}
	if len(commits) != 1 || commits[0].Subject != "Initial commit" {
		t.Fatalf("commits = %#v", commits)
	}
	patch, err := backend.RenderCommit(context.Background(), cache, commits[0].OID)
	if err != nil {
		t.Fatal(err)
	}
	if len(patch) == 0 {
		t.Fatal("empty patch")
	}
}

func TestCloneRecoversWithStaleTemporaryCache(t *testing.T) {
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git is not installed")
	}
	root := t.TempDir()
	work := filepath.Join(root, "work")
	runGit(t, "", "init", "-b", "main", work)
	runGit(t, work, "config", "user.name", "Example Author")
	runGit(t, work, "config", "user.email", "author@example.com")
	if err := os.WriteFile(filepath.Join(work, "README.md"), []byte("hello\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	runGit(t, work, "add", "README.md")
	runGit(t, work, "commit", "-m", "Initial commit")
	remoteDir := filepath.Join(root, "remote.git")
	runGit(t, "", "clone", "--bare", work, remoteDir)
	runGit(t, remoteDir, "update-server-info")

	server := httptest.NewServer(http.FileServer(http.Dir(root)))
	defer server.Close()
	cache := filepath.Join(root, "cache.git")
	stale := cache + ".tmp"
	if err := os.MkdirAll(stale, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(stale, "partial-clone"), []byte("stale"), 0o600); err != nil {
		t.Fatal(err)
	}
	backend := &Backend{
		GitCommand: "git", SSHCommand: "ssh",
		KnownHosts: filepath.Join(root, "known_hosts"), Timeout: 30 * time.Second,
	}
	if _, err := backend.Clone(context.Background(), server.URL+"/remote.git", cache, "none", Auth{}); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(cache, "HEAD")); err != nil {
		t.Fatalf("published mirror is incomplete: %v", err)
	}
	if _, err := os.Stat(stale); !os.IsNotExist(err) {
		t.Fatalf("stale temporary cache was not removed: %v", err)
	}
}

func TestGitCommandOutputRedactsSecrets(t *testing.T) {
	var logs bytes.Buffer
	output := newGitCommandOutput(
		slog.New(slog.NewTextHandler(&logs, nil)),
		"repository.git",
		Auth{Password: "http-secret", Passphrase: "ssh-secret"},
	)
	_, _ = output.Write([]byte("remote: using http-secret\rkey ssh-secret\n"))
	output.Flush()
	for _, text := range []string{logs.String(), string(output.Bytes())} {
		if strings.Contains(text, "http-secret") || strings.Contains(text, "ssh-secret") {
			t.Fatalf("command output leaked a credential: %s", text)
		}
		if !strings.Contains(text, "[REDACTED]") {
			t.Fatalf("command output did not contain a redaction marker: %s", text)
		}
	}
}

func TestCommandErrorIncludesCauseAndLastOutput(t *testing.T) {
	err := commandError(
		"clone repository",
		[]byte("Receiving objects: 99%\rResolving deltas: 100%, done.\n"),
		context.DeadlineExceeded,
	)
	message := err.Error()
	if !strings.Contains(message, "context deadline exceeded") {
		t.Fatalf("command error omitted its cause: %s", message)
	}
	if !strings.Contains(message, "last git output: Resolving deltas: 100%, done.") {
		t.Fatalf("command error omitted the final Git output: %s", message)
	}
	if strings.Contains(message, "Receiving objects") {
		t.Fatalf("command error included stale progress output: %s", message)
	}
}

func runGit(t *testing.T, dir string, args ...string) {
	t.Helper()
	cmd := exec.Command("git", args...)
	cmd.Dir = dir
	if output, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("git %v: %v\n%s", args, err, output)
	}
}

package service

import (
	"bytes"
	"context"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"git2imap/internal/gitbackend"
	"git2imap/internal/secure"
	"git2imap/internal/store"
)

func TestBuildMessage(t *testing.T) {
	authored := time.Date(2026, 9, 8, 12, 0, 0, 0, time.UTC)
	data := buildMessage(store.Repository{
		ID: "repo-id", Name: "project", MailUsername: "git2imap+project@mail.example",
	},
		store.Mailbox{Branch: "main"}, store.Message{
			CommitOID: "0123456789abcdef", Subject: "Fix headers",
			AuthorName: "Example Author", AuthorEmail: "author@example.com", AuthoredAt: authored,
		}, []byte("commit 0123456789abcdef\n\ndiff --git a/a b/a\n"))
	text := string(data)
	for _, expected := range []string{
		"From: Example Author <author@example.com>\r\n",
		"To: git2imap+project@mail.example\r\n",
		"Subject: Fix headers\r\n",
		"X-Git-Branch: main\r\n",
		"diff --git a/a b/a\r\n",
	} {
		if !strings.Contains(text, expected) {
			t.Errorf("message does not contain %q", expected)
		}
	}
	if strings.Contains(strings.ReplaceAll(text, "\r\n", ""), "\n") {
		t.Fatal("message contains bare LF")
	}
}

func TestProjectSlug(t *testing.T) {
	tests := map[string]string{
		"My Project":      "my-project",
		"API___Gateway":   "api-gateway",
		"  spaced name  ": "spaced-name",
		"release/v2":      "release-v2",
		"Already---Clean": "already-clean",
		"___":             "repo",
		"日本語":             "repo",
	}
	for input, expected := range tests {
		if actual := projectSlug(input); actual != expected {
			t.Errorf("projectSlug(%q) = %q, want %q", input, actual, expected)
		}
	}
}

func TestPurgeLegacyRepositories(t *testing.T) {
	ctx := context.Background()
	root := t.TempDir()
	st, err := store.Open(filepath.Join(root, "data", "git2imap.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	box, _ := secure.NewBox(bytes.Repeat([]byte{6}, 32))
	now := time.Now().UTC()
	repo := store.Repository{
		ID: "legacy-repo", Name: "legacy", RemoteURL: "https://example.test/legacy.git",
		AuthType: "none", Status: "ready", MailUsername: "legacy-deadbeef",
		MailPasswordHash: "hash", MailPasswordCipher: "cipher", CreatedAt: now, UpdatedAt: now,
	}
	if err := st.CreateRepository(ctx, repo); err != nil {
		t.Fatal(err)
	}
	cache := filepath.Join(root, "cache")
	legacyCache := filepath.Join(cache, repo.ID+".git")
	if err := os.MkdirAll(legacyCache, 0o700); err != nil {
		t.Fatal(err)
	}
	svc := NewRepositoryService(st, box, &gitbackend.Backend{}, cache, "mail.example",
		slog.New(slog.NewTextHandler(io.Discard, nil)))
	deleted, err := svc.PurgeLegacyRepositories(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if deleted != 1 {
		t.Fatalf("deleted = %d", deleted)
	}
	if _, err := svc.Repository(ctx, repo.ID); !store.IsNotFound(err) {
		t.Fatalf("legacy repository still exists: %v", err)
	}
	if _, err := os.Stat(legacyCache); !os.IsNotExist(err) {
		t.Fatalf("legacy cache still exists: %v", err)
	}
}

func TestRepositoryLifecycle(t *testing.T) {
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git is not installed")
	}
	ctx := context.Background()
	root := t.TempDir()
	work := filepath.Join(root, "work")
	runGit(t, "", "init", "-b", "main", work)
	runGit(t, work, "config", "user.name", "Example Author")
	runGit(t, work, "config", "user.email", "author@example.com")
	if err := os.WriteFile(filepath.Join(work, "README.md"), []byte("one\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	runGit(t, work, "add", "README.md")
	runGit(t, work, "commit", "-m", "Initial commit")
	remoteDir := filepath.Join(root, "remote.git")
	runGit(t, "", "clone", "--bare", work, remoteDir)
	runGit(t, work, "remote", "add", "origin", remoteDir)
	runGit(t, remoteDir, "update-server-info")
	httpServer := httptest.NewServer(http.FileServer(http.Dir(root)))
	defer httpServer.Close()

	st, err := store.Open(filepath.Join(root, "data", "git2imap.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	box, _ := secure.NewBox(bytes.Repeat([]byte{3}, 32))
	cache := filepath.Join(root, "cache")
	svc := NewRepositoryService(st, box, &gitbackend.Backend{
		GitCommand: "git", SSHCommand: "ssh", KnownHosts: filepath.Join(root, "known_hosts"),
		Timeout: 30 * time.Second,
	}, cache, "mail.example", slog.New(slog.NewTextHandler(io.Discard, nil)))

	repo, password, err := svc.AddRepository(ctx, AddRepositoryInput{
		Name: "project", RemoteURL: httpServer.URL + "/remote.git", AuthType: "none",
	})
	if err != nil {
		t.Fatal(err)
	}
	repo = waitForRepository(t, svc, repo.ID, "ready")
	if repo.MailUsername != "git2imap+project@mail.example" {
		t.Fatalf("mail username = %q", repo.MailUsername)
	}
	collision, err := svc.availableMailAddress(ctx, "Project!", "12345678-0000-0000-0000-000000000000")
	if err != nil {
		t.Fatal(err)
	}
	if collision != "git2imap+project-12345678@mail.example" {
		t.Fatalf("collision address = %q", collision)
	}
	revealed, err := svc.RevealMailCredential(ctx, repo.ID)
	if err != nil || revealed != password {
		t.Fatalf("revealed password = %q, err = %v", revealed, err)
	}
	mailbox, err := svc.Mailbox(ctx, repo.ID, "INBOX")
	if err != nil {
		t.Fatal(err)
	}
	messages, err := svc.Messages(ctx, mailbox.ID)
	if err != nil || len(messages) != 1 {
		t.Fatalf("initial messages = %#v, err = %v", messages, err)
	}
	firstValidity := mailbox.UIDValidity
	rendered, err := svc.RenderMessage(ctx, repo, mailbox, messages[0])
	if err != nil || !strings.Contains(string(rendered), "diff --git") {
		t.Fatalf("rendered commit missing patch: %v", err)
	}

	if err := os.WriteFile(filepath.Join(work, "README.md"), []byte("two\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	runGit(t, work, "add", "README.md")
	runGit(t, work, "commit", "-m", "Second commit")
	runGit(t, work, "push", "origin", "main")
	runGit(t, remoteDir, "update-server-info")
	if err := svc.RefreshRepository(ctx, repo.ID); err != nil {
		t.Fatal(err)
	}
	mailbox, _ = svc.Mailbox(ctx, repo.ID, "INBOX")
	messages, _ = svc.Messages(ctx, mailbox.ID)
	if len(messages) != 2 || messages[1].UID != 2 || mailbox.UIDValidity != firstValidity {
		t.Fatalf("fast-forward state mailbox=%#v messages=%#v", mailbox, messages)
	}

	runGit(t, work, "switch", "--orphan", "rewritten")
	runGit(t, work, "rm", "-rf", "--ignore-unmatch", ".")
	runGit(t, work, "commit", "--allow-empty", "-m", "Rewritten history")
	runGit(t, work, "push", "--force", "origin", "HEAD:main")
	runGit(t, remoteDir, "update-server-info")
	if err := svc.RefreshRepository(ctx, repo.ID); err != nil {
		t.Fatal(err)
	}
	mailbox, _ = svc.Mailbox(ctx, repo.ID, "INBOX")
	messages, _ = svc.Messages(ctx, mailbox.ID)
	if len(messages) != 1 || messages[0].UID != 1 || mailbox.UIDValidity == firstValidity {
		t.Fatalf("rewrite state mailbox=%#v messages=%#v", mailbox, messages)
	}

	if err := svc.DeleteRepository(ctx, repo.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(svc.RepositoryPath(repo.ID)); !os.IsNotExist(err) {
		t.Fatalf("cache still exists: %v", err)
	}
	if _, err := svc.Repository(ctx, repo.ID); !store.IsNotFound(err) {
		t.Fatalf("repository still exists: %v", err)
	}
}

func waitForRepository(t *testing.T, svc *RepositoryService, id, status string) store.Repository {
	t.Helper()
	deadline := time.Now().Add(20 * time.Second)
	for time.Now().Before(deadline) {
		repo, err := svc.Repository(context.Background(), id)
		if err != nil {
			t.Fatal(err)
		}
		if repo.Status == status {
			return repo
		}
		if repo.Status == "error" {
			t.Fatalf("repository entered error state: %s", repo.StatusMessage)
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatalf("repository did not reach %q", status)
	return store.Repository{}
}

func runGit(t *testing.T, dir string, args ...string) string {
	t.Helper()
	cmd := exec.Command("git", args...)
	cmd.Dir = dir
	output, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("git %v: %v\n%s", args, err, output)
	}
	return string(output)
}

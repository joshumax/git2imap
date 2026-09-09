package imapserver

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"io"
	"log/slog"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/emersion/go-imap/v2/imapserver"

	"git2imap/internal/gitbackend"
	"git2imap/internal/secure"
	"git2imap/internal/service"
	"git2imap/internal/store"
)

func TestIMAPReadOnlyCommitFlow(t *testing.T) {
	repositories, username, password, closeFixture := protocolFixture(t)
	defer closeFixture()

	server := imapserver.New(&imapserver.Options{
		NewSession: func(*imapserver.Conn) (imapserver.Session, *imapserver.GreetingData, error) {
			return &session{
				repositories: repositories,
				idleInterval: time.Hour,
			}, &imapserver.GreetingData{}, nil
		},
		InsecureAuth: true,
	})
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer server.Close()
	go func() { _ = server.Serve(listener) }()

	conn, err := net.Dial("tcp", listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	reader := bufio.NewReader(conn)
	if greeting, err := reader.ReadString('\n'); err != nil || !strings.Contains(greeting, "OK") {
		t.Fatalf("greeting = %q, %v", greeting, err)
	}

	response := imapCommand(t, conn, reader, "a", fmt.Sprintf("LOGIN %s %s", username, password))
	if !strings.Contains(response, "a OK") {
		t.Fatalf("LOGIN response:\n%s", response)
	}
	response = imapCommand(t, conn, reader, "b", `LIST "" "*"`)
	if !strings.Contains(response, " INBOX") {
		t.Fatalf("LIST response:\n%s", response)
	}
	response = imapCommand(t, conn, reader, "c", "EXAMINE INBOX")
	if !strings.Contains(response, "1 EXISTS") || !strings.Contains(response, "READ-ONLY") {
		t.Fatalf("EXAMINE response:\n%s", response)
	}
	response = imapCommand(t, conn, reader, "d", "UID FETCH 1:* (UID FLAGS ENVELOPE RFC822.SIZE BODY.PEEK[])")
	if !strings.Contains(response, "Initial commit") || !strings.Contains(response, "diff --git") {
		t.Fatalf("FETCH response:\n%s", response)
	}
	response = imapCommand(t, conn, reader, "e", `STORE 1 +FLAGS (\Seen)`)
	if !strings.Contains(response, "e NO") {
		t.Fatalf("STORE response:\n%s", response)
	}
	_ = imapCommand(t, conn, reader, "f", "LOGOUT")
}

func imapCommand(t *testing.T, conn net.Conn, reader *bufio.Reader, tag, command string) string {
	t.Helper()
	if _, err := fmt.Fprintf(conn, "%s %s\r\n", tag, command); err != nil {
		t.Fatal(err)
	}
	var response strings.Builder
	for {
		line, err := reader.ReadString('\n')
		if err != nil {
			t.Fatalf("read %s response: %v\n%s", command, err, response.String())
		}
		response.WriteString(line)
		if strings.HasPrefix(line, tag+" ") {
			return response.String()
		}
	}
}

func protocolFixture(t *testing.T) (*service.RepositoryService, string, string, func()) {
	t.Helper()
	root := t.TempDir()
	cache := filepath.Join(root, "cache")
	data := filepath.Join(root, "data")
	if err := os.MkdirAll(cache, 0o700); err != nil {
		t.Fatal(err)
	}
	work := filepath.Join(root, "work")
	runGit(t, "", "init", "-b", "main", work)
	runGit(t, work, "config", "user.name", "Example Author")
	runGit(t, work, "config", "user.email", "author@example.com")
	if err := os.WriteFile(filepath.Join(work, "README.md"), []byte("hello\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	runGit(t, work, "add", "README.md")
	runGit(t, work, "commit", "-m", "Initial commit")
	oid := strings.TrimSpace(runGit(t, work, "rev-parse", "HEAD"))
	repoID := "repo-id"
	runGit(t, "", "clone", "--mirror", work, filepath.Join(cache, repoID+".git"))

	st, err := store.Open(filepath.Join(data, "test.db"))
	if err != nil {
		t.Fatal(err)
	}
	box, err := secure.NewBox(bytes.Repeat([]byte{4}, 32))
	if err != nil {
		t.Fatal(err)
	}
	authCipher, _ := box.Encrypt([]byte(`{}`))
	password := "mail-password"
	passwordHash, _ := secure.HashPassword(password)
	passwordCipher, _ := box.Encrypt([]byte(password))
	now := time.Now().UTC()
	repo := store.Repository{
		ID: repoID, Name: "project", RemoteURL: "https://invalid.example/project.git",
		AuthType: "none", AuthSecret: authCipher, Status: "ready", DefaultBranch: "main",
		MailUsername: "git2imap+project@mail.example", MailPasswordHash: passwordHash, MailPasswordCipher: passwordCipher,
		CreatedAt: now, UpdatedAt: now,
	}
	if err := st.CreateRepository(context.Background(), repo); err != nil {
		t.Fatal(err)
	}
	if err := st.ReplaceMailboxes(context.Background(), repoID, "main", []store.BranchSnapshot{{
		Name: "main", HeadOID: oid, NewCommits: []store.CommitSnapshot{{
			OID: oid, Subject: "Initial commit", AuthorName: "Example Author",
			AuthorEmail: "author@example.com", AuthoredAt: now,
		}},
	}}); err != nil {
		t.Fatal(err)
	}
	git := &gitbackend.Backend{
		GitCommand: "git", SSHCommand: "ssh", KnownHosts: filepath.Join(data, "known_hosts"),
		Timeout: 5 * time.Second,
	}
	repositories := service.NewRepositoryService(st, box, git, cache, "mail.example", slog.New(slog.NewTextHandler(io.Discard, nil)))
	return repositories, repo.MailUsername, password, func() { _ = st.Close() }
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

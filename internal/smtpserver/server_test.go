package smtpserver

import (
	"bufio"
	"bytes"
	"context"
	"encoding/base64"
	"fmt"
	"io"
	"log/slog"
	"net"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/emersion/go-smtp"

	"git2imap/internal/gitbackend"
	"git2imap/internal/secure"
	"git2imap/internal/service"
	"git2imap/internal/store"
)

func TestAuthenticatedMessageIsAcceptedAndDiscarded(t *testing.T) {
	root := t.TempDir()
	st, err := store.Open(filepath.Join(root, "test.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	box, _ := secure.NewBox(bytes.Repeat([]byte{9}, 32))
	authCipher, _ := box.Encrypt([]byte(`{}`))
	password := "mail-password"
	passwordHash, _ := secure.HashPassword(password)
	passwordCipher, _ := box.Encrypt([]byte(password))
	now := time.Now().UTC()
	repo := store.Repository{
		ID: "repo", Name: "project", RemoteURL: "https://example.test/project.git",
		AuthType: "none", AuthSecret: authCipher, Status: "ready",
		MailUsername: "git2imap+project@mail.example", MailPasswordHash: passwordHash,
		MailPasswordCipher: passwordCipher, CreatedAt: now, UpdatedAt: now,
	}
	if err := st.CreateRepository(context.Background(), repo); err != nil {
		t.Fatal(err)
	}
	repositories := service.NewRepositoryService(st, box, &gitbackend.Backend{}, root, "mail.example",
		slog.New(slog.NewTextHandler(io.Discard, nil)))
	server := smtp.NewServer(&backend{repositories: repositories})
	server.Domain = "mail.example"
	server.AllowInsecureAuth = true
	server.MaxMessageBytes = 1024
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
	expectSMTP(t, reader, "220")
	sendSMTP(t, conn, "EHLO client.example")
	readSMTPMultiline(t, reader, "250")
	token := base64.StdEncoding.EncodeToString([]byte("\x00" + repo.MailUsername + "\x00" + password))
	sendSMTP(t, conn, "AUTH PLAIN "+token)
	expectSMTP(t, reader, "235")
	sendSMTP(t, conn, "MAIL FROM:<sender@example.com>")
	expectSMTP(t, reader, "250")
	sendSMTP(t, conn, "RCPT TO:<git2imap+project@mail.example>")
	expectSMTP(t, reader, "250")
	sendSMTP(t, conn, "DATA")
	expectSMTP(t, reader, "354")
	sendSMTP(t, conn, "Subject: discarded\r\n\r\nThis is discarded.\r\n.")
	expectSMTP(t, reader, "250")
	sendSMTP(t, conn, "QUIT")
	expectSMTP(t, reader, "221")
}

func sendSMTP(t *testing.T, conn net.Conn, command string) {
	t.Helper()
	if _, err := fmt.Fprintf(conn, "%s\r\n", command); err != nil {
		t.Fatal(err)
	}
}

func expectSMTP(t *testing.T, reader *bufio.Reader, code string) {
	t.Helper()
	line, err := reader.ReadString('\n')
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(line, code) {
		t.Fatalf("SMTP response = %q, want %s", line, code)
	}
}

func readSMTPMultiline(t *testing.T, reader *bufio.Reader, code string) {
	t.Helper()
	for {
		line, err := reader.ReadString('\n')
		if err != nil {
			t.Fatal(err)
		}
		if !strings.HasPrefix(line, code) {
			t.Fatalf("SMTP response = %q, want %s", line, code)
		}
		if len(line) >= 4 && line[3] == ' ' {
			return
		}
	}
}

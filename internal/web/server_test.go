package web

import (
	"bytes"
	"context"
	"encoding/base64"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"git2imap/internal/config"
	"git2imap/internal/gitbackend"
	"git2imap/internal/secure"
	"git2imap/internal/service"
	"git2imap/internal/store"
)

func TestAdminLoginAndDashboard(t *testing.T) {
	root := t.TempDir()
	cfg := config.Default()
	cfg.DataDir = filepath.Join(root, "data")
	cfg.CacheDir = filepath.Join(root, "cache")
	cfg.MasterKey = base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{5}, 32))
	cfg.Admin.Username = "admin"
	cfg.Admin.Password = "admin-password"
	st, err := store.Open(cfg.DatabasePath())
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	box, _ := secure.NewBox(cfg.MasterKeyBytes())
	repositories := service.NewRepositoryService(st, box, &gitbackend.Backend{}, cfg.CacheDir, cfg.PublicHost,
		slog.New(slog.NewTextHandler(io.Discard, nil)))
	server, err := New(cfg, repositories, st, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatal(err)
	}

	loginPage := httptest.NewRecorder()
	server.httpServer.Handler.ServeHTTP(loginPage, httptest.NewRequest(http.MethodGet, "/login", nil))
	if loginPage.Code != http.StatusOK || !strings.Contains(loginPage.Body.String(), "Administrator sign in") {
		t.Fatalf("login page status=%d body=%s", loginPage.Code, loginPage.Body.String())
	}

	form := url.Values{"username": {"admin"}, "password": {"admin-password"}}
	login := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodPost, "/login", strings.NewReader(form.Encode()))
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	server.httpServer.Handler.ServeHTTP(login, request)
	if login.Code != http.StatusSeeOther {
		t.Fatalf("login status=%d body=%s", login.Code, login.Body.String())
	}
	cookies := login.Result().Cookies()
	if len(cookies) != 1 || cookies[0].Value == "" {
		t.Fatal("login did not return a session cookie")
	}

	dashboard := httptest.NewRecorder()
	request = httptest.NewRequest(http.MethodGet, "/", nil)
	request.AddCookie(cookies[0])
	server.httpServer.Handler.ServeHTTP(dashboard, request)
	if dashboard.Code != http.StatusOK || !strings.Contains(dashboard.Body.String(), "No repositories yet") {
		t.Fatalf("dashboard status=%d body=%s", dashboard.Code, dashboard.Body.String())
	}

	static := httptest.NewRecorder()
	server.httpServer.Handler.ServeHTTP(static, httptest.NewRequest(http.MethodGet, "/static/app.css", nil))
	if static.Code != http.StatusOK || !strings.Contains(static.Body.String(), ".topbar") {
		t.Fatalf("static asset status=%d", static.Code)
	}

	newPage := httptest.NewRecorder()
	request = httptest.NewRequest(http.MethodGet, "/repos/new", nil)
	request.AddCookie(cookies[0])
	server.httpServer.Handler.ServeHTTP(newPage, request)
	if newPage.Code != http.StatusOK ||
		!strings.Contains(newPage.Body.String(), `data-auth-fields="http" disabled`) ||
		!strings.Contains(newPage.Body.String(), `data-auth-fields="ssh" disabled`) {
		t.Fatalf("new repository form does not disable inactive credentials: %s", newPage.Body.String())
	}

	appJS := httptest.NewRecorder()
	server.httpServer.Handler.ServeHTTP(appJS, httptest.NewRequest(http.MethodGet, "/static/app.js", nil))
	if appJS.Code != http.StatusOK || !strings.Contains(appJS.Body.String(), "syncAuthFields") {
		t.Fatalf("app script status=%d", appJS.Code)
	}

	session, err := st.Session(context.Background(), tokenHash(cookies[0].Value))
	if err != nil {
		t.Fatal(err)
	}
	authCipher, _ := box.Encrypt([]byte(`{}`))
	mailPassword := "imap-secret"
	mailHash, _ := secure.HashPassword(mailPassword)
	mailCipher, _ := box.Encrypt([]byte(mailPassword))
	now := time.Now().UTC()
	repo := store.Repository{
		ID: "repo-id", Name: "project", RemoteURL: "https://example.test/project.git",
		AuthType: "none", AuthSecret: authCipher, Status: "ready", DefaultBranch: "main",
		MailUsername: "git2imap+project@localhost", MailPasswordHash: mailHash,
		MailPasswordCipher: mailCipher, CreatedAt: now, UpdatedAt: now,
	}
	if err := st.CreateRepository(context.Background(), repo); err != nil {
		t.Fatal(err)
	}

	actionGET := httptest.NewRecorder()
	request = httptest.NewRequest(http.MethodGet, "/repos/"+repo.ID+"/reveal", nil)
	request.SetPathValue("id", repo.ID)
	request.AddCookie(cookies[0])
	server.httpServer.Handler.ServeHTTP(actionGET, request)
	if actionGET.Code != http.StatusSeeOther || actionGET.Header().Get("Location") != "/repos/"+repo.ID {
		t.Fatalf("action GET status=%d location=%q", actionGET.Code, actionGET.Header().Get("Location"))
	}

	revealForm := url.Values{
		"csrf":           {session.CSRFToken},
		"admin_password": {"admin-password"},
	}
	reveal := httptest.NewRecorder()
	request = httptest.NewRequest(http.MethodPost, "/repos/"+repo.ID+"/reveal", strings.NewReader(revealForm.Encode()))
	request.SetPathValue("id", repo.ID)
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	request.AddCookie(cookies[0])
	server.httpServer.Handler.ServeHTTP(reveal, request)
	if reveal.Code != http.StatusSeeOther || reveal.Header().Get("Location") != "/repos/"+repo.ID {
		t.Fatalf("reveal status=%d location=%q", reveal.Code, reveal.Header().Get("Location"))
	}

	detail := httptest.NewRecorder()
	request = httptest.NewRequest(http.MethodGet, "/repos/"+repo.ID, nil)
	request.SetPathValue("id", repo.ID)
	request.AddCookie(cookies[0])
	server.httpServer.Handler.ServeHTTP(detail, request)
	if detail.Code != http.StatusOK || !strings.Contains(detail.Body.String(), mailPassword) {
		t.Fatalf("detail did not consume password flash: status=%d", detail.Code)
	}

	refreshed := httptest.NewRecorder()
	request = httptest.NewRequest(http.MethodGet, "/repos/"+repo.ID, nil)
	request.SetPathValue("id", repo.ID)
	request.AddCookie(cookies[0])
	server.httpServer.Handler.ServeHTTP(refreshed, request)
	if refreshed.Code != http.StatusOK || strings.Contains(refreshed.Body.String(), mailPassword) {
		t.Fatal("password flash was not one-time")
	}

	if err := st.PurgeExpiredSessions(context.Background()); err != nil {
		t.Fatal(err)
	}
}

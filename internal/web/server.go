package web

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"embed"
	"encoding/hex"
	"fmt"
	"html/template"
	"log/slog"
	"net"
	"net/http"
	"strconv"
	"sync"
	"time"

	"git2imap/internal/config"
	"git2imap/internal/secure"
	"git2imap/internal/service"
	"git2imap/internal/store"
)

//go:embed templates/*.html static/*
var assets embed.FS

type Server struct {
	cfg          config.Config
	repositories *service.RepositoryService
	store        *store.Store
	adminHash    string
	logger       *slog.Logger
	templates    map[string]*template.Template
	httpServer   *http.Server
	httpsServer  *http.Server
	attemptsMu   sync.Mutex
	attempts     map[string][]time.Time
	flashesMu    sync.Mutex
	flashes      map[string]flashData
}

type flashData struct {
	Message      string
	MailPassword string
	ExpiresAt    time.Time
}

type pageData struct {
	Title        string
	CSRF         string
	Repos        []store.Repository
	Repo         store.Repository
	MailPassword string
	Error        string
	Message      string
	PublicHost   string
	IMAPAddr     string
	IMAPTLSAddr  string
	SMTPAddr     string
	SMTPTLSAddr  string
}

func New(cfg config.Config, repositories *service.RepositoryService, st *store.Store, logger *slog.Logger) (*Server, error) {
	adminHash, err := secure.HashPassword(cfg.Admin.Password)
	if err != nil {
		return nil, err
	}
	templates := make(map[string]*template.Template)
	for _, page := range []string{"login", "dashboard", "new", "detail"} {
		t, err := template.New("layout.html").Funcs(template.FuncMap{
			"timefmt": func(value *time.Time) string {
				if value == nil {
					return "Never"
				}
				return value.Local().Format("2006-01-02 15:04:05 MST")
			},
			"statusClass": func(status string) string {
				switch status {
				case "ready":
					return "ok"
				case "error":
					return "error"
				default:
					return "working"
				}
			},
		}).ParseFS(assets, "templates/layout.html", "templates/"+page+".html")
		if err != nil {
			return nil, fmt.Errorf("parse %s template: %w", page, err)
		}
		templates[page] = t
	}
	s := &Server{
		cfg: cfg, repositories: repositories, store: st, adminHash: adminHash,
		logger: logger, templates: templates, attempts: make(map[string][]time.Time),
		flashes: make(map[string]flashData),
	}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusNoContent) })
	mux.HandleFunc("GET /readyz", func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusNoContent) })
	mux.Handle("GET /static/", http.FileServerFS(assets))
	mux.HandleFunc("GET /login", s.loginPage)
	mux.HandleFunc("POST /login", s.login)
	mux.Handle("POST /logout", s.auth(http.HandlerFunc(s.logout)))
	mux.Handle("GET /", s.auth(http.HandlerFunc(s.dashboard)))
	mux.Handle("GET /repos", s.auth(http.HandlerFunc(s.redirectDashboard)))
	mux.Handle("GET /repos/new", s.auth(http.HandlerFunc(s.newRepositoryPage)))
	mux.Handle("POST /repos", s.auth(http.HandlerFunc(s.addRepository)))
	mux.Handle("GET /repos/{id}", s.auth(http.HandlerFunc(s.repositoryDetail)))
	mux.Handle("GET /repos/{id}/refresh", s.auth(http.HandlerFunc(s.redirectRepositoryAction)))
	mux.Handle("GET /repos/{id}/reveal", s.auth(http.HandlerFunc(s.redirectRepositoryAction)))
	mux.Handle("GET /repos/{id}/rotate", s.auth(http.HandlerFunc(s.redirectRepositoryAction)))
	mux.Handle("GET /repos/{id}/delete", s.auth(http.HandlerFunc(s.redirectRepositoryAction)))
	mux.Handle("POST /repos/{id}/refresh", s.auth(http.HandlerFunc(s.refreshRepository)))
	mux.Handle("POST /repos/{id}/reveal", s.auth(http.HandlerFunc(s.revealCredential)))
	mux.Handle("POST /repos/{id}/rotate", s.auth(http.HandlerFunc(s.rotateCredential)))
	mux.Handle("POST /repos/{id}/delete", s.auth(http.HandlerFunc(s.deleteRepository)))

	handler := securityHeaders(mux)
	s.httpServer = &http.Server{Addr: cfg.Web.Addr, Handler: handler, ReadHeaderTimeout: 10 * time.Second}
	s.httpsServer = &http.Server{Addr: cfg.Web.TLSAddr, Handler: handler, ReadHeaderTimeout: 10 * time.Second}
	return s, nil
}

func (s *Server) Serve(ctx context.Context, report func(string, error)) {
	if s.cfg.Web.Addr != "" {
		go func() {
			err := s.httpServer.ListenAndServe()
			if err == http.ErrServerClosed {
				err = nil
			}
			report("web", err)
		}()
	}
	if s.cfg.Web.TLSAddr != "" && s.cfg.Web.TLSCert != "" {
		go func() {
			err := s.httpsServer.ListenAndServeTLS(s.cfg.Web.TLSCert, s.cfg.Web.TLSKey)
			if err == http.ErrServerClosed {
				err = nil
			}
			report("web-tls", err)
		}()
	}
	go func() {
		<-ctx.Done()
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		_ = s.httpServer.Shutdown(shutdownCtx)
		_ = s.httpsServer.Shutdown(shutdownCtx)
	}()
}

func (s *Server) loginPage(w http.ResponseWriter, r *http.Request) {
	if _, ok := s.session(r); ok {
		http.Redirect(w, r, "/", http.StatusSeeOther)
		return
	}
	s.render(w, "login", pageData{Title: "Sign in"})
}

func (s *Server) login(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, 64<<10)
	ip, _, _ := net.SplitHostPort(r.RemoteAddr)
	if s.rateLimited(ip) {
		http.Error(w, "Too many login attempts. Try again later.", http.StatusTooManyRequests)
		return
	}
	if err := r.ParseForm(); err != nil {
		http.Error(w, "Invalid form", http.StatusBadRequest)
		return
	}
	usernameOK := subtle.ConstantTimeCompare([]byte(r.FormValue("username")), []byte(s.cfg.Admin.Username)) == 1
	if !usernameOK || !secure.VerifyPassword(s.adminHash, r.FormValue("password")) {
		s.recordAttempt(ip)
		s.renderStatus(w, "login", pageData{Title: "Sign in", Error: "Invalid username or password."}, http.StatusUnauthorized)
		return
	}
	token, err := secure.RandomToken(32)
	if err != nil {
		http.Error(w, "Unable to create session", http.StatusInternalServerError)
		return
	}
	csrf, err := secure.RandomToken(24)
	if err != nil {
		http.Error(w, "Unable to create session", http.StatusInternalServerError)
		return
	}
	expires := time.Now().UTC().Add(12 * time.Hour)
	if err := s.store.CreateSession(r.Context(), tokenHash(token), csrf, expires); err != nil {
		http.Error(w, "Unable to create session", http.StatusInternalServerError)
		return
	}
	http.SetCookie(w, &http.Cookie{
		Name: s.cfg.Web.CookieName, Value: token, Path: "/", HttpOnly: true,
		Secure: s.cfg.Web.CookieSecure || r.TLS != nil, SameSite: http.SameSiteStrictMode, Expires: expires,
	})
	http.Redirect(w, r, "/", http.StatusSeeOther)
}

func (s *Server) logout(w http.ResponseWriter, r *http.Request) {
	if !s.checkCSRF(r) {
		http.Error(w, "Invalid CSRF token", http.StatusForbidden)
		return
	}
	if cookie, err := r.Cookie(s.cfg.Web.CookieName); err == nil {
		_ = s.store.DeleteSession(r.Context(), tokenHash(cookie.Value))
	}
	http.SetCookie(w, &http.Cookie{Name: s.cfg.Web.CookieName, Path: "/", MaxAge: -1, HttpOnly: true})
	http.Redirect(w, r, "/login", http.StatusSeeOther)
}

func (s *Server) dashboard(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}
	repos, err := s.repositories.ListRepositories(r.Context())
	if err != nil {
		http.Error(w, "Unable to list repositories", http.StatusInternalServerError)
		return
	}
	s.render(w, "dashboard", s.data(r, pageData{
		Title: "Repositories", Repos: repos, Message: r.URL.Query().Get("message"),
	}))
}

func (s *Server) newRepositoryPage(w http.ResponseWriter, r *http.Request) {
	s.render(w, "new", s.data(r, pageData{Title: "Add repository"}))
}

func (s *Server) redirectDashboard(w http.ResponseWriter, r *http.Request) {
	http.Redirect(w, r, "/", http.StatusSeeOther)
}

func (s *Server) redirectRepositoryAction(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if _, err := s.repositories.Repository(r.Context(), id); err != nil {
		http.Redirect(w, r, "/", http.StatusSeeOther)
		return
	}
	http.Redirect(w, r, "/repos/"+id, http.StatusSeeOther)
}

func (s *Server) addRepository(w http.ResponseWriter, r *http.Request) {
	if !s.checkCSRF(r) {
		http.Error(w, "Invalid CSRF token", http.StatusForbidden)
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, 2<<20)
	if err := r.ParseForm(); err != nil {
		http.Error(w, "Invalid form", http.StatusBadRequest)
		return
	}
	repo, password, err := s.repositories.AddRepository(r.Context(), service.AddRepositoryInput{
		Name: r.FormValue("name"), RemoteURL: r.FormValue("remote_url"),
		AuthType: r.FormValue("auth_type"), Username: r.FormValue("git_username"),
		Password: r.FormValue("git_password"), PrivateKey: r.FormValue("private_key"),
		Passphrase: r.FormValue("passphrase"),
	})
	if err != nil {
		s.renderStatus(w, "new", s.data(r, pageData{Title: "Add repository", Error: err.Error()}), http.StatusBadRequest)
		return
	}
	s.setFlash(r, flashData{
		Message:      "Repository registered. Cloning has started.",
		MailPassword: password,
	})
	http.Redirect(w, r, "/repos/"+repo.ID, http.StatusSeeOther)
}

func (s *Server) repositoryDetail(w http.ResponseWriter, r *http.Request) {
	repo, err := s.repositories.Repository(r.Context(), r.PathValue("id"))
	if err != nil {
		http.NotFound(w, r)
		return
	}
	data := pageData{
		Title: "Repository", Repo: repo, Message: r.URL.Query().Get("message"),
	}
	if flash, ok := s.popFlash(r); ok {
		data.Message = flash.Message
		data.MailPassword = flash.MailPassword
	}
	s.render(w, "detail", s.data(r, data))
}

func (s *Server) refreshRepository(w http.ResponseWriter, r *http.Request) {
	if !s.checkCSRF(r) {
		http.Error(w, "Invalid CSRF token", http.StatusForbidden)
		return
	}
	id := r.PathValue("id")
	go func() {
		if err := s.repositories.RefreshRepository(context.Background(), id); err != nil {
			s.logger.Error("manual refresh failed", "repository_id", id, "error", err)
		}
	}()
	http.Redirect(w, r, "/repos/"+id+"?message=Refresh+started", http.StatusSeeOther)
}

func (s *Server) revealCredential(w http.ResponseWriter, r *http.Request) {
	s.credentialAction(w, r, false)
}

func (s *Server) rotateCredential(w http.ResponseWriter, r *http.Request) {
	s.credentialAction(w, r, true)
}

func (s *Server) credentialAction(w http.ResponseWriter, r *http.Request, rotate bool) {
	if !s.checkCSRF(r) {
		http.Error(w, "Invalid CSRF token", http.StatusForbidden)
		return
	}
	if err := r.ParseForm(); err != nil || !secure.VerifyPassword(s.adminHash, r.FormValue("admin_password")) {
		http.Error(w, "Administrator password is required", http.StatusUnauthorized)
		return
	}
	id := r.PathValue("id")
	if _, err := s.repositories.Repository(r.Context(), id); err != nil {
		http.NotFound(w, r)
		return
	}
	var password string
	var err error
	if rotate {
		password, err = s.repositories.RotateMailCredential(r.Context(), id)
	} else {
		password, err = s.repositories.RevealMailCredential(r.Context(), id)
	}
	if err != nil {
		http.Error(w, "Unable to access credential", http.StatusInternalServerError)
		return
	}
	message := "Credential revealed."
	if rotate {
		message = "Credential rotated. Existing clients must be updated."
	}
	s.setFlash(r, flashData{Message: message, MailPassword: password})
	http.Redirect(w, r, "/repos/"+id, http.StatusSeeOther)
}

func (s *Server) deleteRepository(w http.ResponseWriter, r *http.Request) {
	if !s.checkCSRF(r) {
		http.Error(w, "Invalid CSRF token", http.StatusForbidden)
		return
	}
	if err := s.repositories.DeleteRepository(r.Context(), r.PathValue("id")); err != nil {
		http.Error(w, "Unable to delete repository", http.StatusInternalServerError)
		return
	}
	http.Redirect(w, r, "/?message=Repository+deleted", http.StatusSeeOther)
}

func (s *Server) auth(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if _, ok := s.session(r); !ok {
			http.Redirect(w, r, "/login", http.StatusSeeOther)
			return
		}
		next.ServeHTTP(w, r)
	})
}

func (s *Server) session(r *http.Request) (store.Session, bool) {
	cookie, err := r.Cookie(s.cfg.Web.CookieName)
	if err != nil {
		return store.Session{}, false
	}
	session, err := s.store.Session(r.Context(), tokenHash(cookie.Value))
	return session, err == nil
}

func (s *Server) setFlash(r *http.Request, flash flashData) {
	session, ok := s.session(r)
	if !ok {
		return
	}
	now := time.Now()
	flash.ExpiresAt = now.Add(5 * time.Minute)
	s.flashesMu.Lock()
	for key, existing := range s.flashes {
		if existing.ExpiresAt.Before(now) {
			delete(s.flashes, key)
		}
	}
	s.flashes[session.ID] = flash
	s.flashesMu.Unlock()
}

func (s *Server) popFlash(r *http.Request) (flashData, bool) {
	session, ok := s.session(r)
	if !ok {
		return flashData{}, false
	}
	s.flashesMu.Lock()
	defer s.flashesMu.Unlock()
	flash, ok := s.flashes[session.ID]
	delete(s.flashes, session.ID)
	if !ok || flash.ExpiresAt.Before(time.Now()) {
		return flashData{}, false
	}
	return flash, true
}

func (s *Server) checkCSRF(r *http.Request) bool {
	session, ok := s.session(r)
	if !ok {
		return false
	}
	if err := r.ParseForm(); err != nil {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(session.CSRFToken), []byte(r.FormValue("csrf"))) == 1
}

func (s *Server) data(r *http.Request, data pageData) pageData {
	if session, ok := s.session(r); ok {
		data.CSRF = session.CSRFToken
	}
	data.PublicHost = s.cfg.PublicHost
	data.IMAPAddr = s.cfg.IMAP.Addr
	data.IMAPTLSAddr = s.cfg.IMAP.TLSAddr
	data.SMTPAddr = s.cfg.SMTP.Addr
	data.SMTPTLSAddr = s.cfg.SMTP.TLSAddr
	return data
}

func (s *Server) render(w http.ResponseWriter, name string, data pageData) {
	s.renderStatus(w, name, data, http.StatusOK)
}

func (s *Server) renderStatus(w http.ResponseWriter, name string, data pageData, status int) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(status)
	if err := s.templates[name].ExecuteTemplate(w, "layout", data); err != nil {
		s.logger.Error("render template", "name", name, "error", err)
	}
}

func (s *Server) rateLimited(ip string) bool {
	s.attemptsMu.Lock()
	defer s.attemptsMu.Unlock()
	cutoff := time.Now().Add(-10 * time.Minute)
	var recent []time.Time
	for _, attempt := range s.attempts[ip] {
		if attempt.After(cutoff) {
			recent = append(recent, attempt)
		}
	}
	s.attempts[ip] = recent
	return len(recent) >= 5
}

func (s *Server) recordAttempt(ip string) {
	s.attemptsMu.Lock()
	s.attempts[ip] = append(s.attempts[ip], time.Now())
	s.attemptsMu.Unlock()
}

func tokenHash(token string) string {
	sum := sha256.Sum256([]byte(token))
	return hex.EncodeToString(sum[:])
}

func securityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("Referrer-Policy", "no-referrer")
		w.Header().Set("Content-Security-Policy", "default-src 'self'; style-src 'self'; script-src 'self'")
		next.ServeHTTP(w, r)
	})
}

func displayPort(addr string) string {
	_, port, err := net.SplitHostPort(addr)
	if err == nil {
		return port
	}
	return strconv.Itoa(0)
}

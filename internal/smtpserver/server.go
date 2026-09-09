package smtpserver

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"log/slog"
	"net"

	"github.com/emersion/go-sasl"
	"github.com/emersion/go-smtp"

	"git2imap/internal/config"
	"git2imap/internal/service"
)

type Server struct {
	plain *smtp.Server
	tls   *smtp.Server
	cfg   config.SMTPConfig
}

func New(cfg config.SMTPConfig, publicHost string, repositories *service.RepositoryService, logger *slog.Logger) (*Server, error) {
	tlsConfig, err := loadTLSConfig(cfg.TLSCert, cfg.TLSKey)
	if err != nil {
		return nil, err
	}
	backend := &backend{repositories: repositories}
	makeServer := func(addr string, implicit bool) *smtp.Server {
		s := smtp.NewServer(backend)
		s.Addr = addr
		s.Domain = publicHost
		s.TLSConfig = tlsConfig
		s.MaxMessageBytes = cfg.MaxMessage
		s.MaxRecipients = 100
		s.AllowInsecureAuth = cfg.AllowInsecureAuth || (tlsConfig == nil && isLoopbackAddress(addr))
		s.ErrorLog = smtpLogger{logger.With("server", map[bool]string{true: "smtps", false: "smtp"}[implicit])}
		return s
	}
	return &Server{
		plain: makeServer(cfg.Addr, false),
		tls:   makeServer(cfg.TLSAddr, true),
		cfg:   cfg,
	}, nil
}

func (s *Server) Serve(ctx context.Context, report func(string, error)) {
	if s.cfg.Addr != "" {
		go func() { report("smtp", s.plain.ListenAndServe()) }()
	}
	if s.cfg.TLSAddr != "" && s.cfg.TLSCert != "" {
		go func() { report("smtps", s.tls.ListenAndServeTLS()) }()
	}
	go func() {
		<-ctx.Done()
		_ = s.plain.Close()
		_ = s.tls.Close()
	}()
}

type backend struct {
	repositories *service.RepositoryService
}

func (b *backend) NewSession(*smtp.Conn) (smtp.Session, error) {
	return &session{repositories: b.repositories}, nil
}

type session struct {
	repositories  *service.RepositoryService
	authenticated bool
}

func (s *session) AuthMechanisms() []string { return []string{sasl.Plain} }

func (s *session) Auth(mech string) (sasl.Server, error) {
	if mech != sasl.Plain {
		return nil, smtp.ErrAuthUnknownMechanism
	}
	return sasl.NewPlainServer(func(identity, username, password string) error {
		if _, ok := s.repositories.Authenticate(context.Background(), username, password); !ok {
			return smtp.ErrAuthFailed
		}
		s.authenticated = true
		return nil
	}), nil
}

func (s *session) Mail(string, *smtp.MailOptions) error {
	if !s.authenticated {
		return smtp.ErrAuthRequired
	}
	return nil
}

func (s *session) Rcpt(string, *smtp.RcptOptions) error {
	if !s.authenticated {
		return smtp.ErrAuthRequired
	}
	return nil
}

func (s *session) Data(r io.Reader) error {
	if !s.authenticated {
		return smtp.ErrAuthRequired
	}
	_, err := io.Copy(io.Discard, r)
	return err
}

func (s *session) Reset()        {}
func (s *session) Logout() error { return nil }

type smtpLogger struct{ log *slog.Logger }

func (l smtpLogger) Printf(format string, args ...interface{}) {
	l.log.Error("protocol error", "detail", fmt.Sprintf(format, args...))
}
func (l smtpLogger) Println(args ...interface{}) {
	l.log.Error("protocol error", "detail", fmt.Sprint(args...))
}

func loadTLSConfig(certPath, keyPath string) (*tls.Config, error) {
	if certPath == "" && keyPath == "" {
		return nil, nil
	}
	cert, err := tls.LoadX509KeyPair(certPath, keyPath)
	if err != nil {
		return nil, fmt.Errorf("load TLS certificate: %w", err)
	}
	return &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS12}, nil
}

func isLoopbackAddress(addr string) bool {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return false
	}
	ip := net.ParseIP(host)
	return host == "localhost" || (ip != nil && ip.IsLoopback())
}

var _ smtp.AuthSession = (*session)(nil)

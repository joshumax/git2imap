package config

import (
	"encoding/base64"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

type Config struct {
	PublicHost string      `yaml:"public_host"`
	DataDir    string      `yaml:"data_dir"`
	CacheDir   string      `yaml:"cache_dir"`
	MasterKey  string      `yaml:"master_key"`
	Admin      AdminConfig `yaml:"admin"`
	Web        WebConfig   `yaml:"web"`
	IMAP       IMAPConfig  `yaml:"imap"`
	SMTP       SMTPConfig  `yaml:"smtp"`
	Git        GitConfig   `yaml:"git"`
	Log        LogConfig   `yaml:"log"`
}

type AdminConfig struct {
	Username string `yaml:"username"`
	Password string `yaml:"password"`
}

type WebConfig struct {
	Addr         string `yaml:"addr"`
	TLSAddr      string `yaml:"tls_addr"`
	TLSCert      string `yaml:"tls_cert"`
	TLSKey       string `yaml:"tls_key"`
	CookieName   string `yaml:"cookie_name"`
	CookieSecure bool   `yaml:"cookie_secure"`
}

type IMAPConfig struct {
	Addr              string        `yaml:"addr"`
	TLSAddr           string        `yaml:"tls_addr"`
	TLSCert           string        `yaml:"tls_cert"`
	TLSKey            string        `yaml:"tls_key"`
	AllowInsecureAuth bool          `yaml:"allow_insecure_auth"`
	IdleFetchInterval time.Duration `yaml:"idle_fetch_interval"`
}

type SMTPConfig struct {
	Addr              string `yaml:"addr"`
	TLSAddr           string `yaml:"tls_addr"`
	TLSCert           string `yaml:"tls_cert"`
	TLSKey            string `yaml:"tls_key"`
	MaxMessage        int64  `yaml:"max_message_bytes"`
	AllowInsecureAuth bool   `yaml:"allow_insecure_auth"`
}

type GitConfig struct {
	Command      string        `yaml:"command"`
	SSHCommand   string        `yaml:"ssh_command"`
	CloneTimeout time.Duration `yaml:"clone_timeout"`
	FetchTimeout time.Duration `yaml:"fetch_timeout"`
}

type LogConfig struct {
	Format string `yaml:"format"`
	Level  string `yaml:"level"`
}

func Default() Config {
	cache, _ := os.UserCacheDir()
	data, _ := os.UserConfigDir()
	return Config{
		PublicHost: "localhost",
		DataDir:    filepath.Join(data, "git2imap"),
		CacheDir:   filepath.Join(cache, "git2imap", "repos"),
		Admin: AdminConfig{
			Username: "admin",
		},
		Web: WebConfig{
			Addr:       "127.0.0.1:8080",
			CookieName: "git2imap_session",
		},
		IMAP: IMAPConfig{
			Addr:              "127.0.0.1:1143",
			IdleFetchInterval: time.Minute,
		},
		SMTP: SMTPConfig{
			Addr:       "127.0.0.1:1025",
			MaxMessage: 10 << 20,
		},
		Git: GitConfig{
			Command:      "git",
			SSHCommand:   "ssh",
			CloneTimeout: 30 * time.Minute,
			FetchTimeout: time.Minute,
		},
		Log: LogConfig{Format: "text", Level: "info"},
	}
}

func Load(path string) (Config, error) {
	cfg := Default()
	if path != "" {
		data, err := os.ReadFile(path)
		if err != nil {
			return cfg, fmt.Errorf("read config: %w", err)
		}
		if err := yaml.Unmarshal(data, &cfg); err != nil {
			return cfg, fmt.Errorf("parse config: %w", err)
		}
	}
	applyEnv(&cfg)
	if err := cfg.Validate(); err != nil {
		return cfg, err
	}
	return cfg, nil
}

func (c Config) Validate() error {
	var problems []string
	if c.PublicHost == "" {
		problems = append(problems, "public_host is required")
	} else if strings.ContainsAny(c.PublicHost, "\r\n\t @") {
		problems = append(problems, "public_host must be a hostname without whitespace")
	}
	if c.DataDir == "" || c.CacheDir == "" {
		problems = append(problems, "data_dir and cache_dir are required")
	}
	key, err := base64.StdEncoding.DecodeString(c.MasterKey)
	if err != nil || len(key) != 32 {
		problems = append(problems, "master_key must be base64 for exactly 32 bytes")
	}
	if c.Admin.Username == "" || c.Admin.Password == "" {
		problems = append(problems, "admin username and password are required")
	}
	if c.Git.CloneTimeout <= 0 || c.Git.FetchTimeout <= 0 {
		problems = append(problems, "git.clone_timeout and git.fetch_timeout must be positive")
	}
	if c.SMTP.MaxMessage <= 0 {
		problems = append(problems, "smtp.max_message_bytes must be positive")
	}
	for name, pair := range map[string][2]string{
		"web":  {c.Web.TLSCert, c.Web.TLSKey},
		"imap": {c.IMAP.TLSCert, c.IMAP.TLSKey},
		"smtp": {c.SMTP.TLSCert, c.SMTP.TLSKey},
	} {
		if (pair[0] == "") != (pair[1] == "") {
			problems = append(problems, name+" TLS certificate and key must be configured together")
		}
	}
	for name, listener := range map[string][3]string{
		"web":  {c.Web.TLSAddr, c.Web.TLSCert, c.Web.TLSKey},
		"imap": {c.IMAP.TLSAddr, c.IMAP.TLSCert, c.IMAP.TLSKey},
		"smtp": {c.SMTP.TLSAddr, c.SMTP.TLSCert, c.SMTP.TLSKey},
	} {
		if listener[0] != "" && (listener[1] == "" || listener[2] == "") {
			problems = append(problems, name+" tls_addr requires a TLS certificate and key")
		}
	}
	if len(problems) > 0 {
		return errors.New(strings.Join(problems, "; "))
	}
	return nil
}

func (c Config) MasterKeyBytes() []byte {
	key, _ := base64.StdEncoding.DecodeString(c.MasterKey)
	return key
}

func (c Config) DatabasePath() string {
	return filepath.Join(c.DataDir, "git2imap.db")
}

func applyEnv(c *Config) {
	setString(&c.PublicHost, "GIT2IMAP_PUBLIC_HOST")
	setString(&c.DataDir, "GIT2IMAP_DATA_DIR")
	setString(&c.CacheDir, "GIT2IMAP_CACHE_DIR")
	setString(&c.MasterKey, "GIT2IMAP_MASTER_KEY")
	setString(&c.Admin.Username, "GIT2IMAP_ADMIN_USERNAME")
	setString(&c.Admin.Password, "GIT2IMAP_ADMIN_PASSWORD")
	setString(&c.Web.Addr, "GIT2IMAP_WEB_ADDR")
	setString(&c.Web.TLSAddr, "GIT2IMAP_WEB_TLS_ADDR")
	setString(&c.Web.TLSCert, "GIT2IMAP_WEB_TLS_CERT")
	setString(&c.Web.TLSKey, "GIT2IMAP_WEB_TLS_KEY")
	setBool(&c.Web.CookieSecure, "GIT2IMAP_WEB_COOKIE_SECURE")
	setString(&c.IMAP.Addr, "GIT2IMAP_IMAP_ADDR")
	setString(&c.IMAP.TLSAddr, "GIT2IMAP_IMAP_TLS_ADDR")
	setString(&c.IMAP.TLSCert, "GIT2IMAP_IMAP_TLS_CERT")
	setString(&c.IMAP.TLSKey, "GIT2IMAP_IMAP_TLS_KEY")
	setString(&c.SMTP.Addr, "GIT2IMAP_SMTP_ADDR")
	setString(&c.SMTP.TLSAddr, "GIT2IMAP_SMTP_TLS_ADDR")
	setString(&c.SMTP.TLSCert, "GIT2IMAP_SMTP_TLS_CERT")
	setString(&c.SMTP.TLSKey, "GIT2IMAP_SMTP_TLS_KEY")
	setString(&c.Git.Command, "GIT2IMAP_GIT_COMMAND")
	setString(&c.Git.SSHCommand, "GIT2IMAP_SSH_COMMAND")
	setString(&c.Log.Format, "GIT2IMAP_LOG_FORMAT")
	setString(&c.Log.Level, "GIT2IMAP_LOG_LEVEL")
	setDuration(&c.IMAP.IdleFetchInterval, "GIT2IMAP_IMAP_IDLE_FETCH_INTERVAL")
	setDuration(&c.Git.CloneTimeout, "GIT2IMAP_GIT_CLONE_TIMEOUT")
	setDuration(&c.Git.FetchTimeout, "GIT2IMAP_GIT_FETCH_TIMEOUT")
	setBool(&c.IMAP.AllowInsecureAuth, "GIT2IMAP_IMAP_ALLOW_INSECURE_AUTH")
	setBool(&c.SMTP.AllowInsecureAuth, "GIT2IMAP_SMTP_ALLOW_INSECURE_AUTH")
	if value := os.Getenv("GIT2IMAP_SMTP_MAX_MESSAGE_BYTES"); value != "" {
		if n, err := strconv.ParseInt(value, 10, 64); err == nil {
			c.SMTP.MaxMessage = n
		}
	}
}

func setBool(dst *bool, key string) {
	if value := os.Getenv(key); value != "" {
		if parsed, err := strconv.ParseBool(value); err == nil {
			*dst = parsed
		}
	}
}

func setString(dst *string, key string) {
	if value := os.Getenv(key); value != "" {
		*dst = value
	}
}

func setDuration(dst *time.Duration, key string) {
	if value := os.Getenv(key); value != "" {
		if parsed, err := time.ParseDuration(value); err == nil {
			*dst = parsed
		}
	}
}

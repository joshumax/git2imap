package config

import (
	"encoding/base64"
	"path/filepath"
	"testing"
	"time"
)

func TestLoadEnvironmentOverrides(t *testing.T) {
	key := make([]byte, 32)
	t.Setenv("GIT2IMAP_MASTER_KEY", base64.StdEncoding.EncodeToString(key))
	t.Setenv("GIT2IMAP_ADMIN_PASSWORD", "secret")
	t.Setenv("GIT2IMAP_PUBLIC_HOST", "mail.example")
	t.Setenv("GIT2IMAP_DATA_DIR", filepath.Join(t.TempDir(), "data"))
	t.Setenv("GIT2IMAP_CACHE_DIR", filepath.Join(t.TempDir(), "cache"))
	t.Setenv("GIT2IMAP_IMAP_ALLOW_INSECURE_AUTH", "true")
	t.Setenv("GIT2IMAP_GIT_CLONE_TIMEOUT", "45m")
	cfg, err := Load("")
	if err != nil {
		t.Fatal(err)
	}
	if cfg.PublicHost != "mail.example" || !cfg.IMAP.AllowInsecureAuth || cfg.Git.CloneTimeout != 45*time.Minute {
		t.Fatalf("environment overrides were not applied: %#v", cfg)
	}
}

func TestTLSListenerRequiresCertificate(t *testing.T) {
	cfg := Default()
	cfg.MasterKey = base64.StdEncoding.EncodeToString(make([]byte, 32))
	cfg.Admin.Password = "secret"
	cfg.IMAP.TLSAddr = "127.0.0.1:1993"
	if err := cfg.Validate(); err == nil {
		t.Fatal("TLS listener without certificate was accepted")
	}
}

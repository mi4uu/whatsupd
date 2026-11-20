package main

import (
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

func clearOIDCEnv(t *testing.T) {
	for _, k := range []string{"ISSUER", "CLIENT_ID", "CLIENT_SECRET", "NAME", "SCOPES", "ALLOWED_EMAILS"} {
		t.Setenv("WHATSUPD_OIDC_"+k, "")
		t.Setenv("WAMCP_OIDC_"+k, "")
	}
}

func TestLoadOIDCOffWithoutConfig(t *testing.T) {
	clearOIDCEnv(t)
	cfg, err := loadOIDC(t.TempDir())
	if err != nil || cfg != nil {
		t.Fatalf("got %+v, %v", cfg, err)
	}
}

func TestLoadOIDCFromFile(t *testing.T) {
	clearOIDCEnv(t)
	dir := t.TempDir()
	body := `# Google
WHATSUPD_OIDC_ISSUER=https://accounts.google.com
WHATSUPD_OIDC_CLIENT_ID=cid.apps.googleusercontent.com
export WHATSUPD_OIDC_CLIENT_SECRET="s3cret"
WHATSUPD_OIDC_NAME=Google
WHATSUPD_OIDC_ALLOWED_EMAILS=me@gmail.com, wife@gmail.com
`
	if err := os.WriteFile(filepath.Join(dir, oidcFile), []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("WHATSUPD_OIDC_NAME", "Work SSO")
	cfg, err := loadOIDC(dir)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.ClientSecret != "s3cret" || cfg.Name != "Work SSO" || cfg.Issuer != "https://accounts.google.com" ||
		!slices.Equal(cfg.AllowedEmails, []string{"me@gmail.com", "wife@gmail.com"}) ||
		!slices.Equal(cfg.Scopes, []string{"openid", "email", "profile"}) {
		t.Fatalf("config: %+v", cfg)
	}
}

func TestLoadOIDCRequiresAllowlist(t *testing.T) {
	clearOIDCEnv(t)
	t.Setenv("WHATSUPD_OIDC_ISSUER", "https://accounts.google.com")
	t.Setenv("WHATSUPD_OIDC_CLIENT_ID", "cid")
	if _, err := loadOIDC(t.TempDir()); err == nil || !strings.Contains(err.Error(), "ALLOWED_EMAILS") {
		t.Fatalf("no allowlist: %v", err)
	}
	t.Setenv("WHATSUPD_OIDC_ALLOWED_EMAILS", " , ")
	if _, err := loadOIDC(t.TempDir()); err == nil {
		t.Fatal("blank allowlist accepted")
	}
}

func TestLoadOIDCRefusesReadableFile(t *testing.T) {
	clearOIDCEnv(t)
	dir := t.TempDir()
	path := filepath.Join(dir, oidcFile)
	if err := os.WriteFile(path, []byte("WHATSUPD_OIDC_ISSUER=https://x\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := loadOIDC(dir); err == nil || !strings.Contains(err.Error(), "chmod 600") {
		t.Fatalf("group-readable file: %v", err)
	}
}

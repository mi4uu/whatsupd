package main

import (
	"bufio"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"

	"github.com/mi4uu/whatsupd/internal/config"
	"github.com/mi4uu/whatsupd/internal/web"
)

const oidcFile = "oidc.env"

// loadOIDC reads the OIDC settings from WHATSUPD_OIDC_* variables and from
// oidc.env in the data directory; a variable wins over the file. The file
// lets the background service get the client secret without putting it in
// the unit file or on the command line. Returns nil when OIDC is not set up.
func loadOIDC(dataDir string) (*web.OIDC, error) {
	file, err := readEnvFile(filepath.Join(dataDir, oidcFile))
	if err != nil {
		return nil, err
	}
	get := func(name string) string {
		if v := config.Env("OIDC_" + name); v != "" {
			return strings.TrimSpace(v)
		}
		return file["WHATSUPD_OIDC_"+name]
	}
	cfg := &web.OIDC{
		Issuer: get("ISSUER"), ClientID: get("CLIENT_ID"), ClientSecret: get("CLIENT_SECRET"), Name: get("NAME"),
		Scopes: strings.Fields(strings.ReplaceAll(get("SCOPES"), ",", " ")),
	}
	for _, e := range strings.Split(get("ALLOWED_EMAILS"), ",") {
		if e = strings.TrimSpace(e); e != "" {
			cfg.AllowedEmails = append(cfg.AllowedEmails, e)
		}
	}
	if cfg.Issuer == "" && cfg.ClientID == "" {
		return nil, nil
	}
	if len(cfg.Scopes) == 0 {
		cfg.Scopes = []string{"openid", "email", "profile"}
	}
	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	return cfg, nil
}

// readEnvFile parses KEY=VALUE lines. It refuses a file other users can read,
// since it holds the client secret.
func readEnvFile(path string) (map[string]string, error) {
	f, err := os.Open(path)
	if errors.Is(err, fs.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	defer f.Close()
	st, err := f.Stat()
	if err != nil {
		return nil, err
	}
	if st.Mode().Perm()&0o077 != 0 {
		return nil, fmt.Errorf("%s is readable by other users; run chmod 600 %s", path, path)
	}
	out := map[string]string{}
	sc := bufio.NewScanner(f)
	for n := 1; sc.Scan(); n++ {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		k, v, ok := strings.Cut(strings.TrimPrefix(line, "export "), "=")
		if !ok {
			return nil, fmt.Errorf("%s:%d: expected KEY=VALUE", path, n)
		}
		v = strings.TrimSpace(v)
		if len(v) >= 2 && (v[0] == '"' || v[0] == '\'') && v[len(v)-1] == v[0] {
			v = v[1 : len(v)-1]
		}
		out[strings.TrimSpace(k)] = v
	}
	return out, sc.Err()
}

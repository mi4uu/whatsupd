package web

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"net/http"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"golang.org/x/oauth2"
)

// OIDC configures "Sign in with …" for the web client through an OpenID
// Connect provider (Google, Keycloak, Authentik and others).
type OIDC struct {
	Issuer       string
	ClientID     string
	ClientSecret string
	Name         string   // button label, e.g. Google
	Scopes       []string // openid is always added
	// AllowedEmails are the only accounts let in. Required: without it any
	// account at the provider could read the archive.
	AllowedEmails []string
}

// Validate reports configuration errors that must stop the daemon.
func (o *OIDC) Validate() error {
	switch {
	case o.Issuer == "":
		return errors.New("OIDC issuer is not set")
	case o.ClientID == "":
		return errors.New("OIDC client ID is not set")
	case len(o.AllowedEmails) == 0:
		return errors.New("OIDC needs an allowlist of e-mail addresses (WHATSUPD_OIDC_ALLOWED_EMAILS); without it any account at the provider could read your WhatsApp")
	}
	return nil
}

const (
	oidcCookie     = "whatsupd_oidc_session"
	oidcFlowCookie = "whatsupd_oidc_flow"
	oidcFlowPath   = "/auth/oidc"
	oidcCallback   = oidcFlowPath + "/callback"
	oidcSessionTTL = 30 * 24 * time.Hour
	oidcFlowTTL    = 10 * time.Minute
	oidcMaxFlows   = 100
)

type oidcFlow struct {
	nonce    string
	verifier string
	redirect string
	expires  time.Time
}

type oidcLogin struct {
	cfg     OIDC
	key     []byte // signs session cookies
	allowed map[string]bool
	client  *http.Client

	mu       sync.Mutex
	provider *oidc.Provider // discovered on first use, so a slow network does not stop the daemon
	flows    map[string]oidcFlow
}

func newOIDCLogin(cfg OIDC, token string) *oidcLogin {
	mac := hmac.New(sha256.New, []byte(token))
	mac.Write([]byte("whatsupd-oidc-session"))
	allowed := map[string]bool{}
	for _, e := range cfg.AllowedEmails {
		if e = strings.ToLower(strings.TrimSpace(e)); e != "" {
			allowed[e] = true
		}
	}
	if cfg.Name == "" {
		cfg.Name = "SSO"
	}
	if !slices.Contains(cfg.Scopes, oidc.ScopeOpenID) {
		cfg.Scopes = append([]string{oidc.ScopeOpenID}, cfg.Scopes...)
	}
	return &oidcLogin{cfg: cfg, key: mac.Sum(nil), allowed: allowed,
		client: &http.Client{Timeout: 15 * time.Second}, flows: map[string]oidcFlow{}}
}

func (o *oidcLogin) discover(ctx context.Context) (*oidc.Provider, error) {
	o.mu.Lock()
	defer o.mu.Unlock()
	if o.provider != nil {
		return o.provider, nil
	}
	p, err := oidc.NewProvider(oidc.ClientContext(ctx, o.client), o.cfg.Issuer)
	if err != nil {
		return nil, err
	}
	o.provider = p
	return p, nil
}

func (o *oidcLogin) oauth2(p *oidc.Provider, redirect string) *oauth2.Config {
	return &oauth2.Config{ClientID: o.cfg.ClientID, ClientSecret: o.cfg.ClientSecret, Endpoint: p.Endpoint(),
		RedirectURL: redirect, Scopes: o.cfg.Scopes}
}

func randomString() string {
	b := make([]byte, 32)
	_, _ = rand.Read(b)
	return base64.RawURLEncoding.EncodeToString(b)
}

func (o *oidcLogin) addFlow(state string, f oidcFlow) {
	o.mu.Lock()
	defer o.mu.Unlock()
	now := time.Now()
	for k, v := range o.flows {
		if now.After(v.expires) {
			delete(o.flows, k)
		}
	}
	for len(o.flows) >= oidcMaxFlows {
		oldest := ""
		for k, v := range o.flows {
			if oldest == "" || v.expires.Before(o.flows[oldest].expires) {
				oldest = k
			}
		}
		delete(o.flows, oldest)
	}
	o.flows[state] = f
}

// takeFlow returns the pending login for state and forgets it, so each
// state works once.
func (o *oidcLogin) takeFlow(state string) (oidcFlow, bool) {
	o.mu.Lock()
	defer o.mu.Unlock()
	f, ok := o.flows[state]
	delete(o.flows, state)
	return f, ok && time.Now().Before(f.expires)
}

type oidcClaims struct {
	Email         string `json:"email"`
	EmailVerified any    `json:"email_verified"` // some providers send "true" as a string
	Nonce         string `json:"nonce"`
}

func (c oidcClaims) verified() bool {
	switch v := c.EmailVerified.(type) {
	case bool:
		return v
	case string:
		return strings.EqualFold(v, "true")
	}
	return false
}

var errOIDCDenied = errors.New("account not allowed")

// finish exchanges the code and checks the ID token: signature, issuer,
// audience and expiry (go-oidc), then nonce, a verified e-mail and the allowlist.
func (o *oidcLogin) finish(ctx context.Context, code string, f oidcFlow) (string, error) {
	p, err := o.discover(ctx)
	if err != nil {
		return "", err
	}
	ctx = oidc.ClientContext(ctx, o.client)
	tok, err := o.oauth2(p, f.redirect).Exchange(ctx, code, oauth2.VerifierOption(f.verifier))
	if err != nil {
		return "", fmt.Errorf("code exchange: %w", err)
	}
	raw, ok := tok.Extra("id_token").(string)
	if !ok || raw == "" {
		return "", errors.New("no ID token in the token response")
	}
	idt, err := p.Verifier(&oidc.Config{ClientID: o.cfg.ClientID}).Verify(ctx, raw)
	if err != nil {
		return "", fmt.Errorf("ID token: %w", err)
	}
	var c oidcClaims
	if err := idt.Claims(&c); err != nil {
		return "", fmt.Errorf("ID token claims: %w", err)
	}
	if !hmac.Equal([]byte(c.Nonce), []byte(f.nonce)) {
		return "", errors.New("ID token nonce does not match the login")
	}
	email := strings.ToLower(strings.TrimSpace(c.Email))
	if email == "" || !c.verified() || !o.allowed[email] {
		return email, errOIDCDenied
	}
	return email, nil
}

// sessionValue is base64(email|unix expiry) "." hex(HMAC).
func (o *oidcLogin) sessionValue(email string, expires time.Time) string {
	payload := base64.RawURLEncoding.EncodeToString([]byte(email + "|" + fmt.Sprint(expires.Unix())))
	return payload + "." + o.sign(payload)
}

func (o *oidcLogin) sign(payload string) string {
	mac := hmac.New(sha256.New, o.key)
	mac.Write([]byte(payload))
	return hex.EncodeToString(mac.Sum(nil))
}

// sessionEmail checks a session cookie value. The allowlist is checked on
// every request, so removing an address signs that account out.
func (o *oidcLogin) sessionEmail(value string) (string, bool) {
	payload, sig, ok := strings.Cut(value, ".")
	if !ok || !hmac.Equal([]byte(sig), []byte(o.sign(payload))) {
		return "", false
	}
	raw, err := base64.RawURLEncoding.DecodeString(payload)
	if err != nil {
		return "", false
	}
	email, exp, ok := strings.Cut(string(raw), "|")
	var unix int64
	if _, err := fmt.Sscan(exp, &unix); !ok || err != nil || time.Now().Unix() >= unix {
		return "", false
	}
	return email, o.allowed[email]
}

// oidcRedirect is the callback URL for this request, or "" when the Host is
// not one whatsupd answers to by name: on a listener that accepts any Host
// the provider would otherwise be sent a redirect chosen by the client.
func (s *server) oidcRedirect(r *http.Request) string {
	host := strings.ToLower(r.Host)
	if h, _, err := net.SplitHostPort(host); err == nil {
		host = h
	}
	host = strings.Trim(host, "[]")
	if host != "localhost" && host != "127.0.0.1" && host != "::1" && !slices.Contains(s.opt.PublicHosts, host) {
		return ""
	}
	return s.baseURL(r) + oidcCallback
}

func (s *server) oidcStart(w http.ResponseWriter, r *http.Request) {
	o := s.oidc
	redirect := s.oidcRedirect(r)
	if redirect == "" {
		http.Redirect(w, r, "/?login=oidc-host", http.StatusSeeOther)
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 15*time.Second)
	defer cancel()
	p, err := o.discover(ctx)
	if err != nil {
		s.log().Warn("OIDC discovery failed", "issuer", o.cfg.Issuer, "err", err)
		http.Redirect(w, r, "/?login=oidc-failed", http.StatusSeeOther)
		return
	}
	state, nonce, verifier := randomString(), randomString(), oauth2.GenerateVerifier()
	o.addFlow(state, oidcFlow{nonce: nonce, verifier: verifier, redirect: redirect, expires: time.Now().Add(oidcFlowTTL)})
	// Lax, not Strict: the browser must send it on the redirect back from the provider.
	http.SetCookie(w, &http.Cookie{Name: oidcFlowCookie, Value: state, Path: oidcFlowPath, HttpOnly: true,
		Secure: strings.HasPrefix(redirect, "https://"), SameSite: http.SameSiteLaxMode, MaxAge: int(oidcFlowTTL.Seconds())})
	w.Header().Set("Cache-Control", "no-store")
	http.Redirect(w, r, o.oauth2(p, redirect).AuthCodeURL(state, oidc.Nonce(nonce), oauth2.S256ChallengeOption(verifier)),
		http.StatusFound)
}

func (s *server) oidcCallback(w http.ResponseWriter, r *http.Request) {
	o := s.oidc
	w.Header().Set("Cache-Control", "no-store")
	http.SetCookie(w, &http.Cookie{Name: oidcFlowCookie, Value: "", Path: oidcFlowPath, MaxAge: -1})
	q := r.URL.Query()
	c, err := r.Cookie(oidcFlowCookie)
	state := q.Get("state")
	if err != nil || state == "" || !hmac.Equal([]byte(c.Value), []byte(state)) {
		s.log().Warn("OIDC sign-in rejected: state does not match this browser")
		http.Redirect(w, r, "/?login=oidc-failed", http.StatusSeeOther)
		return
	}
	f, ok := o.takeFlow(state)
	if !ok || f.redirect != s.oidcRedirect(r) {
		s.log().Warn("OIDC sign-in rejected: unknown or expired state")
		http.Redirect(w, r, "/?login=oidc-failed", http.StatusSeeOther)
		return
	}
	if e := q.Get("error"); e != "" {
		s.log().Warn("OIDC provider returned an error", "error", e)
		http.Redirect(w, r, "/?login=oidc-failed", http.StatusSeeOther)
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 20*time.Second)
	defer cancel()
	email, err := o.finish(ctx, q.Get("code"), f)
	if errors.Is(err, errOIDCDenied) {
		s.log().Warn("OIDC sign-in denied: account not on the allowlist or e-mail not verified", "email", email)
		http.Redirect(w, r, "/?login=denied", http.StatusSeeOther)
		return
	}
	if err != nil {
		s.log().Warn("OIDC sign-in failed", "err", err)
		http.Redirect(w, r, "/?login=oidc-failed", http.StatusSeeOther)
		return
	}
	s.log().Info("OIDC sign-in", "email", email)
	http.SetCookie(w, &http.Cookie{Name: oidcCookie, Value: o.sessionValue(email, time.Now().Add(oidcSessionTTL)), Path: "/",
		HttpOnly: true, Secure: strings.HasPrefix(f.redirect, "https://"), SameSite: http.SameSiteStrictMode,
		MaxAge: int(oidcSessionTTL.Seconds())})
	http.Redirect(w, r, "/", http.StatusSeeOther)
}

func (s *server) oidcSignedIn(r *http.Request) bool {
	if s.oidc == nil {
		return false
	}
	c, err := r.Cookie(oidcCookie)
	if err != nil {
		return false
	}
	_, ok := s.oidc.sessionEmail(c.Value)
	return ok
}

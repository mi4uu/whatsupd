package web

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/mi4uu/whatsupd/internal/oauth"
)

// fakeIssuer is a minimal OpenID provider: discovery, JWKS and a token
// endpoint that checks PKCE and returns an RS256 ID token.
type fakeIssuer struct {
	*httptest.Server
	key *rsa.PrivateKey

	mu        sync.Mutex
	challenge string          // from the last authorize URL
	claims    map[string]any  // ID token claims for the next exchange
	email     string          // signed in by /authorize, for the demo server
	used      map[string]bool // codes already exchanged: each works once, as at a real provider
}

func newFakeIssuer(t *testing.T) *fakeIssuer {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	f := &fakeIssuer{key: key, used: map[string]bool{}}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /.well-known/openid-configuration", func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, map[string]any{
			"issuer": f.URL, "authorization_endpoint": f.URL + "/authorize", "token_endpoint": f.URL + "/token",
			"jwks_uri": f.URL + "/jwks", "id_token_signing_alg_values_supported": []string{"RS256"},
		})
	})
	mux.HandleFunc("GET /jwks", func(w http.ResponseWriter, _ *http.Request) {
		b64 := base64.RawURLEncoding.EncodeToString
		writeJSON(w, map[string]any{"keys": []map[string]string{{
			"kty": "RSA", "alg": "RS256", "use": "sig", "kid": "k1",
			"n": b64(key.N.Bytes()), "e": b64(big.NewInt(int64(key.E)).Bytes()),
		}}})
	})
	// /authorize signs in f.email straight away, so the demo server can run
	// the whole flow in a browser.
	mux.HandleFunc("GET /authorize", func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query()
		f.mu.Lock()
		f.challenge = q.Get("code_challenge")
		f.claims = f.claimsFor(q.Get("nonce"), f.email, true)
		f.mu.Unlock()
		http.Redirect(w, r, q.Get("redirect_uri")+"?code=good-"+randomString()+"&state="+url.QueryEscape(q.Get("state")), http.StatusFound)
	})
	mux.HandleFunc("POST /token", func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		id, secret, _ := r.BasicAuth()
		if id == "" {
			id, secret = r.PostForm.Get("client_id"), r.PostForm.Get("client_secret")
		}
		sum := sha256.Sum256([]byte(r.PostForm.Get("code_verifier")))
		code := r.PostForm.Get("code")
		f.mu.Lock()
		claims, challenge, reused := f.claims, f.challenge, f.used[code]
		f.used[code] = true
		f.mu.Unlock()
		if id != "cid" || secret != "csecret" || !strings.HasPrefix(code, "good-") || reused ||
			base64.RawURLEncoding.EncodeToString(sum[:]) != challenge {
			w.WriteHeader(http.StatusBadRequest)
			writeJSON(w, map[string]string{"error": "invalid_grant"})
			return
		}
		writeJSON(w, map[string]any{"access_token": "at", "token_type": "Bearer", "id_token": f.sign(t, claims)})
	})
	f.Server = httptest.NewServer(mux)
	t.Cleanup(f.Close)
	return f
}

func freshCode() string { return "good-" + randomString() }

func (f *fakeIssuer) sign(t *testing.T, claims map[string]any) string {
	t.Helper()
	enc := func(v any) string {
		b, _ := json.Marshal(v)
		return base64.RawURLEncoding.EncodeToString(b)
	}
	input := enc(map[string]string{"alg": "RS256", "typ": "JWT", "kid": "k1"}) + "." + enc(claims)
	sum := sha256.Sum256([]byte(input))
	sig, err := rsa.SignPKCS1v15(rand.Reader, f.key, crypto.SHA256, sum[:])
	if err != nil {
		t.Fatal(err)
	}
	return input + "." + base64.RawURLEncoding.EncodeToString(sig)
}

func (f *fakeIssuer) claimsFor(nonce, email string, verified any) map[string]any {
	now := time.Now()
	return map[string]any{"iss": f.URL, "sub": "123", "aud": "cid", "iat": now.Unix(), "exp": now.Add(time.Hour).Unix(),
		"nonce": nonce, "email": email, "email_verified": verified}
}

func oidcServer(t *testing.T, f *fakeIssuer, allowed ...string) *Server {
	t.Helper()
	base, d := setup(t)
	return Handler(Options{Token: testToken, MCP: base.s.opt.MCP, Archive: base.s.opt.Archive, Daemon: d,
		OIDC: &OIDC{Issuer: f.URL, ClientID: "cid", ClientSecret: "csecret", Name: "Google", AllowedEmails: allowed}})
}

type oidcStarted struct {
	state, nonce string
	flow         *http.Cookie
}

func startOIDC(t *testing.T, srv http.Handler, f *fakeIssuer) oidcStarted {
	t.Helper()
	rec := do(srv, "GET", "/auth/oidc/login", "", nil)
	if rec.Code != http.StatusFound {
		t.Fatalf("start: got %d %s", rec.Code, rec.Body.String())
	}
	loc, err := url.Parse(rec.Header().Get("Location"))
	if err != nil || !strings.HasPrefix(loc.String(), f.URL+"/authorize") {
		t.Fatalf("start redirects to %q", rec.Header().Get("Location"))
	}
	q := loc.Query()
	if q.Get("code_challenge_method") != "S256" || q.Get("redirect_uri") != "http://127.0.0.1:8765/auth/oidc/callback" ||
		!strings.Contains(q.Get("scope"), "openid") {
		t.Fatalf("authorize URL: %s", loc)
	}
	f.mu.Lock()
	f.challenge = q.Get("code_challenge")
	f.mu.Unlock()
	var flow *http.Cookie
	for _, c := range rec.Result().Cookies() {
		if c.Name == oidcFlowCookie {
			flow = c
		}
	}
	if flow == nil || flow.SameSite != http.SameSiteLaxMode || !flow.HttpOnly {
		t.Fatalf("flow cookie: %+v", flow)
	}
	return oidcStarted{state: q.Get("state"), nonce: q.Get("nonce"), flow: flow}
}

// callback finishes the login and returns where it redirected and the
// session cookie, if one was set.
func callback(t *testing.T, srv http.Handler, query string, flow *http.Cookie) (string, *http.Cookie) {
	t.Helper()
	req := httptest.NewRequest("GET", "http://127.0.0.1:8765/auth/oidc/callback?"+query, nil)
	if flow != nil {
		req.AddCookie(flow)
	}
	rec := httptest.NewRecorder()
	srv.ServeHTTP(rec, req)
	if rec.Code != http.StatusSeeOther {
		t.Fatalf("callback: got %d", rec.Code)
	}
	for _, c := range rec.Result().Cookies() {
		if c.Name == oidcCookie && c.Value != "" {
			return rec.Header().Get("Location"), c
		}
	}
	return rec.Header().Get("Location"), nil
}

func withCookie(h http.Handler, method, path string, c *http.Cookie, hdr map[string]string) int {
	req := httptest.NewRequest(method, "http://127.0.0.1:8765"+path, strings.NewReader("{}"))
	req.AddCookie(c)
	for k, v := range hdr {
		req.Header.Set(k, v)
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec.Code
}

func login(t *testing.T, srv http.Handler, f *fakeIssuer, email string, verified any) (string, *http.Cookie) {
	t.Helper()
	st := startOIDC(t, srv, f)
	f.mu.Lock()
	f.claims = f.claimsFor(st.nonce, email, verified)
	f.mu.Unlock()
	return callback(t, srv, "code="+freshCode()+"&state="+url.QueryEscape(st.state), st.flow)
}

func TestOIDCAllowedAccountSignsIn(t *testing.T) {
	f := newFakeIssuer(t)
	srv := oidcServer(t, f, "Owner@Example.com")
	var sess map[string]any
	_ = json.Unmarshal(do(srv, "GET", "/api/session", "", nil).Body.Bytes(), &sess)
	if sess["oidc"] != "Google" || sess["authenticated"] != false {
		t.Fatalf("session before sign-in: %v", sess)
	}
	loc, c := login(t, srv, f, "owner@example.COM", true)
	if loc != "/" || c == nil || !c.HttpOnly || c.SameSite != http.SameSiteStrictMode {
		t.Fatalf("allowed account: redirect %q, cookie %+v", loc, c)
	}
	if code := withCookie(srv, "GET", "/api/chats", c, nil); code != http.StatusOK {
		t.Fatalf("web API with OIDC session: got %d", code)
	}
	req := httptest.NewRequest("GET", "http://127.0.0.1:8765/api/session", nil)
	req.AddCookie(c)
	rec := httptest.NewRecorder()
	srv.ServeHTTP(rec, req)
	if !strings.Contains(rec.Body.String(), `"authenticated":true`) {
		t.Fatalf("session after sign-in: %s", rec.Body.String())
	}
}

func TestOIDCDeniesUnlistedOrUnverified(t *testing.T) {
	f := newFakeIssuer(t)
	srv := oidcServer(t, f, "owner@example.com", "kim@example.com", "info@example.com")
	for name, tc := range map[string]struct {
		email    string
		verified any
	}{
		"unlisted":          {"someone@gmail.com", true},
		"unverified":        {"owner@example.com", false},
		"verified missing":  {"owner@example.com", nil},
		"verified as text":  {"owner@example.com", "false"},
		"no e-mail":         {"", true},
		"lookalike address": {"owner@example.com.evil", true},
		"Unicode case fold": {"\u212Aim@example.com", true}, // Kelvin sign lowercases to k
		"dotted capital I":  {"\u0130nfo@example.com", true},
	} {
		loc, c := login(t, srv, f, tc.email, tc.verified)
		if loc != "/?login=denied" || c != nil {
			t.Errorf("%s: redirect %q, cookie %v", name, loc, c)
		}
	}
}

func TestOIDCRejectsBadFlow(t *testing.T) {
	f := newFakeIssuer(t)
	srv := oidcServer(t, f, "owner@example.com")

	st := startOIDC(t, srv, f)
	f.claims = f.claimsFor(st.nonce, "owner@example.com", true)
	if loc, c := callback(t, srv, "code=good-code&state=other", st.flow); loc != "/?login=oidc-failed" || c != nil {
		t.Errorf("state mismatch: %q %v", loc, c)
	}

	st = startOIDC(t, srv, f)
	f.claims = f.claimsFor(st.nonce, "owner@example.com", true)
	if loc, c := callback(t, srv, "code="+freshCode()+"&state="+url.QueryEscape(st.state), nil); loc != "/?login=oidc-failed" || c != nil {
		t.Errorf("no flow cookie (login started in another browser): %q %v", loc, c)
	}

	st = startOIDC(t, srv, f)
	f.claims = f.claimsFor("not-the-nonce", "owner@example.com", true)
	if loc, c := callback(t, srv, "code="+freshCode()+"&state="+url.QueryEscape(st.state), st.flow); loc != "/?login=oidc-failed" || c != nil {
		t.Errorf("nonce mismatch: %q %v", loc, c)
	}

	st = startOIDC(t, srv, f)
	claims := f.claimsFor(st.nonce, "owner@example.com", true)
	claims["aud"] = "another-client"
	f.claims = claims
	if loc, c := callback(t, srv, "code="+freshCode()+"&state="+url.QueryEscape(st.state), st.flow); loc != "/?login=oidc-failed" || c != nil {
		t.Errorf("token for another client: %q %v", loc, c)
	}

	st = startOIDC(t, srv, f)
	claims = f.claimsFor(st.nonce, "owner@example.com", true)
	claims["exp"] = time.Now().Add(-time.Minute).Unix()
	f.claims = claims
	if loc, c := callback(t, srv, "code="+freshCode()+"&state="+url.QueryEscape(st.state), st.flow); loc != "/?login=oidc-failed" || c != nil {
		t.Errorf("expired ID token: %q %v", loc, c)
	}

	st = startOIDC(t, srv, f)
	f.claims = f.claimsFor(st.nonce, "owner@example.com", true)
	q := "code=" + freshCode() + "&state=" + url.QueryEscape(st.state)
	if loc, c := callback(t, srv, q, st.flow); loc != "/" || c == nil {
		t.Fatalf("valid login: %q %v", loc, c)
	}
	if loc, c := callback(t, srv, q, st.flow); loc != "/?login=oidc-failed" || c != nil {
		t.Errorf("replayed state: %q %v", loc, c)
	}

	st = startOIDC(t, srv, f)
	f.claims = f.claimsFor(st.nonce, "owner@example.com", true)
	if loc, c := callback(t, srv, "error=access_denied&state="+url.QueryEscape(st.state), st.flow); loc != "/?login=oidc-failed" || c != nil {
		t.Errorf("provider error: %q %v", loc, c)
	}
}

func TestOIDCSessionCannotReachAgentEndpoints(t *testing.T) {
	f := newFakeIssuer(t)
	base, d := setup(t)
	store, err := oauth.Open(filepath.Join(t.TempDir(), "oauth.json"))
	if err != nil {
		t.Fatal(err)
	}
	srv := Handler(Options{Token: testToken, MCP: base.s.opt.MCP, Archive: base.s.opt.Archive, Daemon: d,
		OAuth: &oauth.Handler{S: store, OwnerToken: testToken, Access: "read"},
		OIDC:  &OIDC{Issuer: f.URL, ClientID: "cid", ClientSecret: "csecret", AllowedEmails: []string{"owner@example.com"}}})
	_, c := login(t, srv, f, "owner@example.com", true)
	if c == nil {
		t.Fatal("no session")
	}
	for _, ep := range []struct{ method, path string }{
		{"POST", "/mcp"}, {"GET", "/api/live/status"}, {"POST", "/api/live/send"}, {"POST", "/api/login-code"},
		{"GET", "/api/oauth/clients"}, {"POST", "/api/oauth/revoke"},
	} {
		if code := withCookie(srv, ep.method, ep.path, c, map[string]string{"Sec-Fetch-Site": "same-origin"}); code != http.StatusUnauthorized {
			t.Errorf("%s %s with an OIDC session: got %d, want 401", ep.method, ep.path, code)
		}
	}
	// The session cookie is not a bearer token either.
	if code := withCookie(srv, "POST", "/mcp", c, map[string]string{"Authorization": "Bearer " + c.Value}); code != http.StatusUnauthorized {
		t.Errorf("OIDC cookie value as bearer: got %d", code)
	}
}

func TestOIDCSessionRevokedWithAllowlist(t *testing.T) {
	f := newFakeIssuer(t)
	srv := oidcServer(t, f, "owner@example.com", "wife@example.com")
	_, c := login(t, srv, f, "wife@example.com", true)
	if c == nil {
		t.Fatal("no session")
	}
	// Restart with the address removed: the old cookie stops working.
	later := oidcServer(t, f, "owner@example.com")
	if code := withCookie(later, "GET", "/api/chats", c, nil); code != http.StatusUnauthorized {
		t.Errorf("removed address: got %d", code)
	}
	tampered := *c
	tampered.Value = strings.Replace(c.Value, c.Value[:4], "AAAA", 1)
	if code := withCookie(srv, "GET", "/api/chats", &tampered, nil); code != http.StatusUnauthorized {
		t.Errorf("tampered cookie: got %d", code)
	}
	forged := &http.Cookie{Name: oidcCookie, Value: srv.s.oidc.sessionValue("wife@example.com", time.Now().Add(-time.Second))}
	if code := withCookie(srv, "GET", "/api/chats", forged, nil); code != http.StatusUnauthorized {
		t.Errorf("expired session: got %d", code)
	}
	if code := withCookie(srv, "GET", "/api/chats", &http.Cookie{Name: oidcCookie, Value: startOIDC(t, srv, f).flow.Value}, nil); code != http.StatusUnauthorized {
		t.Errorf("flow cookie used as a session: got %d", code)
	}
	otherKey := Handler(Options{Token: "another-token", Archive: srv.s.opt.Archive, Daemon: srv.s.opt.Daemon,
		OIDC: &OIDC{Issuer: f.URL, ClientID: "cid", AllowedEmails: []string{"wife@example.com"}}})
	if code := withCookie(otherKey, "GET", "/api/chats", c, nil); code != http.StatusUnauthorized {
		t.Errorf("session signed for another token: got %d", code)
	}
}

func TestOIDCTokenLoginUnchanged(t *testing.T) {
	f := newFakeIssuer(t)
	srv := oidcServer(t, f, "owner@example.com")
	rec := do(srv, "POST", "/api/login", `{"token":"`+testToken+`"}`, nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("token login: got %d", rec.Code)
	}
	var sess *http.Cookie
	for _, c := range rec.Result().Cookies() {
		if c.Name == cookieName {
			sess = c
		}
	}
	if sess == nil || withCookie(srv, "GET", "/api/chats", sess, nil) != http.StatusOK {
		t.Fatalf("token session cookie: %+v", sess)
	}
	if rec := do(srv, "POST", "/api/login", `{"token":"wrong"}`, nil); rec.Code != http.StatusUnauthorized {
		t.Fatalf("wrong token: got %d", rec.Code)
	}
	code := srv.NewLoginCode()
	if rec := do(srv, "GET", "/login?code="+code, "", nil); rec.Code != http.StatusSeeOther || rec.Header().Get("Location") != "/" {
		t.Fatalf("login code: got %d %s", rec.Code, rec.Header().Get("Location"))
	}
}

func TestOIDCRefusesForeignHost(t *testing.T) {
	f := newFakeIssuer(t)
	srv := oidcServer(t, f, "owner@example.com")
	srv.s.opt.AllowAnyHost = true
	req := httptest.NewRequest("GET", "http://10.0.0.5:8765/auth/oidc/login", nil)
	rec := httptest.NewRecorder()
	srv.ServeHTTP(rec, req)
	if rec.Code != http.StatusSeeOther || rec.Header().Get("Location") != "/?login=oidc-host" {
		t.Fatalf("Host that is not localhost or a public host: got %d %s", rec.Code, rec.Header().Get("Location"))
	}
	srv.s.opt.PublicHosts = []string{"wa.example.com"}
	req = httptest.NewRequest("GET", "http://wa.example.com/auth/oidc/login", nil)
	rec = httptest.NewRecorder()
	srv.ServeHTTP(rec, req)
	loc, _ := url.Parse(rec.Header().Get("Location"))
	if got := loc.Query().Get("redirect_uri"); got != "https://wa.example.com/auth/oidc/callback" {
		t.Fatalf("public host redirect_uri: %q", got)
	}
	for _, c := range rec.Result().Cookies() {
		if c.Name == oidcFlowCookie && !c.Secure {
			t.Error("flow cookie over https must be Secure")
		}
	}
}

func TestOIDCValidate(t *testing.T) {
	for name, cfg := range map[string]OIDC{
		"no allowlist": {Issuer: "https://accounts.google.com", ClientID: "cid"},
		"no client":    {Issuer: "https://accounts.google.com", AllowedEmails: []string{"a@b.c"}},
		"no issuer":    {ClientID: "cid", AllowedEmails: []string{"a@b.c"}},
		"non-ASCII":    {Issuer: "https://accounts.google.com", ClientID: "cid", AllowedEmails: []string{"ząb@example.com"}},
	} {
		if cfg.Validate() == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

func TestOIDCOffByDefault(t *testing.T) {
	srv, _ := setup(t)
	if rec := do(srv, "GET", "/auth/oidc/login", "", nil); rec.Code == http.StatusFound {
		t.Fatal("OIDC route served without OIDC configured")
	}
	if strings.Contains(do(srv, "GET", "/api/session", "", nil).Body.String(), `"oidc"`) {
		t.Fatal("session advertises OIDC without OIDC configured")
	}
}

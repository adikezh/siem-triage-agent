package web

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/hex"
	"net/http"
	"net/url"
	"sync"
	"time"
)

const cookieName = "triage_session"
const sessionTTL = 8 * time.Hour

type session struct {
	ID, KeyHash, CSRF string
	Expires           time.Time
}
type sessions struct {
	mu     sync.Mutex
	values map[string]session
}

func randomToken() (string, error) {
	var b [32]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", err
	}
	return hex.EncodeToString(b[:]), nil
}
func (s *sessions) get(r *http.Request) (session, bool) {
	cookie, err := r.Cookie(cookieName)
	if err != nil {
		return session{}, false
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	v, ok := s.values[cookie.Value]
	if ok && !time.Now().Before(v.Expires) {
		delete(s.values, cookie.Value)
		ok = false
	}
	return v, ok
}
func (s *sessions) remove(id string) { s.mu.Lock(); defer s.mu.Unlock(); delete(s.values, id) }
func (s *sessions) create(w http.ResponseWriter, r *http.Request, hash string, secure bool) (session, error) {
	id, err := randomToken()
	if err != nil {
		return session{}, err
	}
	csrf, err := randomToken()
	if err != nil {
		return session{}, err
	}
	v := session{ID: id, KeyHash: hash, CSRF: csrf, Expires: time.Now().Add(sessionTTL)}
	s.mu.Lock()
	for key, old := range s.values {
		if !time.Now().Before(old.Expires) {
			delete(s.values, key)
		}
	}
	// Bound unauthenticated login sessions; fail closed instead of evicting users.
	if len(s.values) >= 4096 {
		s.mu.Unlock()
		return session{}, http.ErrServerClosed
	}
	s.values[id] = v
	s.mu.Unlock()
	http.SetCookie(w, &http.Cookie{Name: cookieName, Value: id, Path: "/", HttpOnly: true, SameSite: http.SameSiteLaxMode, Secure: secure || r.TLS != nil, MaxAge: int(sessionTTL.Seconds())})
	return v, nil
}
func checkCSRF(r *http.Request, v session, publicOrigin string) bool {
	if r.Header.Get("Sec-Fetch-Site") == "cross-site" {
		return false
	}
	if origin := r.Header.Get("Origin"); origin != "" {
		u, err := url.Parse(origin)
		if publicOrigin != "" {
			if err != nil || origin != publicOrigin {
				return false
			}
			return v.CSRF != "" && subtle.ConstantTimeCompare([]byte(r.PostForm.Get("_csrf")), []byte(v.CSRF)) == 1
		}
		scheme := "http"
		if r.TLS != nil {
			scheme = "https"
		}
		if err != nil || u.Scheme != scheme || u.Host != r.Host || u.Path != "" || u.RawQuery != "" || u.Fragment != "" || u.User != nil {
			return false
		}
	}
	return v.CSRF != "" && subtle.ConstantTimeCompare([]byte(r.PostForm.Get("_csrf")), []byte(v.CSRF)) == 1
}

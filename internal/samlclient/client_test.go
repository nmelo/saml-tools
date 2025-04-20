package samlclient

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/crewjam/saml/samlsp"
	"github.com/gorilla/sessions"
)

// Mock certificate and key for testing
const (
	testCert = `-----BEGIN CERTIFICATE-----
MIICvDCCAaQCCQD6E8ZGsQ2usjANBgkqhkiG9w0BAQsFADAgMR4wHAYDVQQDDBVt
eXNlcnZpY2UuZXhhbXBsZS5jb20wHhcNMjIwMjE3MTQwNjM5WhcNMjMwMjE3MTQw
NjM5WjAgMR4wHAYDVQQDDBVteXNlcnZpY2UuZXhhbXBsZS5jb20wggEiMA0GCSqG
SIb3DQEBAQUAA4IBDwAwggEKAoIBAQC7XKdCRxUZXjdqVqwwwOJqc1Ch0nOSmk+U
erkUqlviWHdeLR+FolHKjqLzCBloAz4xVc0DFfR76gWcWAHJloqZ7GBS7NpDhzV8
G+cXQ+bTU0Lu2e73zCQb30XUdKhWiGfDKaU+1xg9CD/2gIfsYPs3TTq1sq7oCs5q
LdUHaVL5kcRaHKdnTi7cs5i9xzs3TsUnXcrJPwydjp+aEkyRh07oMpXBEobGisfF
2p1MA6pVW2gjmywdVLC3hNSiSPi/+K6rkxL+f/L2Ej+FOV95URV/kScjobIa5Q7M
I+f+3yOlqR5L4S6ZFZuCMYUvGSUXE8wqmQSE0EaPCgF0gOgxAgMBAAEwDQYJKoZI
hvcNAQELBQADggEBAF55SYXEHw3y8/lXSC08IUW+y90jGHaBYoQflWqZa2n5NKhQ
eo0gOrWn5QTY205ZvxSrD3Y1+1zxkD8H5w0XaLK+AZaJ7hEa82zz+nYJwRxYOZUo
qGSQCumTv1a4S1u4v4GoI+ORAYLTNhgGg7LpmNWbcFtpwKgqYGXMGJPrEkj/EwwS
Xfr2NhFRFE9GYGJVg3LT9/R9DQzJJbU21xXAsY0Q/liNPiSQdK9zIlbOXGztAXj+
7ASTZK7DMnXUCEL6+Nfz9nZMmvGeeJ3qHWjSPkXXdYDB0ZGrHjIJ6oJQJi3WQK64
FNOqGC7J7UVIITK33H5d/lKAP7dDrObdtek=
-----END CERTIFICATE-----`

	testKey = `-----BEGIN PRIVATE KEY-----
MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQC7XKdCRxUZXjdq
VqwwwOJqc1Ch0nOSmk+UerkUqlviWHdeLR+FolHKjqLzCBloAz4xVc0DFfR76gWc
WAHJloqZ7GBS7NpDhzV8G+cXQ+bTU0Lu2e73zCQb30XUdKhWiGfDKaU+1xg9CD/2
gIfsYPs3TTq1sq7oCs5qLdUHaVL5kcRaHKdnTi7cs5i9xzs3TsUnXcrJPwydjp+a
EkyRh07oMpXBEobGisfF2p1MA6pVW2gjmywdVLC3hNSiSPi/+K6rkxL+f/L2Ej+F
OV95URV/kScjobIa5Q7MI+f+3yOlqR5L4S6ZFZuCMYUvGSUXE8wqmQSE0EaPCgF0
gOgxAgMBAAECggEBAKBPXIFRnfWoBoFW2AxrXQx3zTbwHXP0YefzBTBs1uVCIMZo
wYLU96jfA52+qlyBt/Mx7ZbQswc/XzC2nAQxPXGYXhNKPbwkpI6c1FHuF94ATtPt
bv9E1i4z6i6HJ5CJxXkoFJP1IKgZiIZ3JmGAQjUKn5DEJrTCnUk1l8eODTYb+SMZ
QJCL4TLkB127TiO1CdXEPzS5Jf04U8vh77Ik6F7eG2B/M7DTHfkYJnHKPOJlPLvl
eQJVYzlMnkOLwXn5DDKG4kP3zqx/s5QiOcXCBsGvZW5tjFyQ5onhEzOvLjH/hEY6
BrTvy6wsictLWOoJzn+fNSau+aS3wMWfmIYQTfj4P4ECgYEA7VkPJC0If5Kpxbeu
lQxzlcQRvYXKUVHvWoRrYjHpKe3zrqLmPYRIFtRSzYFtYTQH7JbKFd1XZ8V+LmQE
Uhx07iDN2hNFVxY/NcXPMtP23ndyK2j4qQMOXmrZYgXdQQYGx+nigCCu2Qey3HEM
slUKJ/ppXNy9XGN+XQBThEPQOhkCgYEAyj+hVmhXDRRUo+GaOdil/UFu/j2me7BX
Mvuu+uscFt1O/S5HCjpLqLQf4YuJwMbTG/8xGsNUdVJ/wwJVhEPLfpVZtCjWcRfx
pnDarfZlnzU/wYH5hfXFWND3DnVv3hgIw7fRlOVr637x9XoGx1PM7K2oSqkZXn5K
YG40IPkIYwkCgYBOD6KWGnLBeDLaJJtj3mE0eJzyk+MtfV5qjLBmwjcwYzGgkFkE
E5r6llQnJvQnxxa51PvXIkH1BY7jK+AkgKKCMNQvqJEEzai1KKkIQq/4o5HBmMP4
LKJSh3UIxJl9YpqubnPbAQ4FRqidpII2tMY2JUsj7iQYUBH/7X6lEUBYOQKBgD8B
ChcQHXRVwK35oJdtYF55adkijIKTVUK9cPLQPHyM7XpbNw7UO9Z4JJ+EJgXGjQDt
8RuAOoNsiLXD22pr1XJ8zwYxP7orV8rd7EXXw170BzYyhC+wLJ5RvvfBULQXML7q
XvUSj0jXlpN0rTVnKiYvq5QJeN59MkapB4UEn7MJAoGAcMdYGVY5TnxT0YTl0mIt
CGU05ME2VIjBYR2BNN1IDJTRqKNqlFRr2lZ5iwXTpgXZn0badFKV66qygJqrOQHK
glYNLLnGwKrlL9p1C3lkfB0SJYtDCc6UOn+FyPafh+5YQZZYkebf0cELJ7pb9MaO
6tylKrK/W9BBBqAIrYBOeVU=
-----END PRIVATE KEY-----`
)

// Helper function to create a test SAMLClient for testing
func createTestSAMLClient(t *testing.T) *SAMLClient {
	// Create cert and key from test strings
	certBlock, _ := pem.Decode([]byte(testCert))
	if certBlock == nil {
		t.Fatal("Failed to parse certificate PEM")
	}
	keyBlock, _ := pem.Decode([]byte(testKey))
	if keyBlock == nil {
		t.Fatal("Failed to parse key PEM")
	}

	certificate, err := x509.ParseCertificate(certBlock.Bytes)
	if err != nil {
		t.Fatalf("Failed to parse certificate: %v", err)
	}

	privateKey, err := x509.ParsePKCS1PrivateKey(keyBlock.Bytes)
	if err != nil {
		t.Fatalf("Failed to parse private key: %v", err)
	}

	// Create test config
	config := Config{
		ListenAddr:                  ":8080",
		BaseURL:                     "http://localhost:8080",
		EntityID:                    "urn:samlclient:sp",
		AssertionConsumerServiceURL: "http://localhost:8080/saml/acs",
		MetadataPath:                "/saml/metadata",
		IdpMetadataURL:              "http://localhost:8082/metadata",
		SessionSecret:               "test-session-secret",
	}

	// Create session store
	sessionStore := sessions.NewCookieStore([]byte(config.SessionSecret))
	sessionStore.Options.HttpOnly = true

	// Create client
	client := &SAMLClient{
		Config:       config,
		Certificate:  certificate,
		PrivateKey:   privateKey,
		SessionStore: sessionStore,
	}

	// We can't fully initialize the middleware without a real IdP, so we'll set up a minimal test middleware
	client.Middleware = &samlsp.Middleware{
		ServiceProvider: samlsp.ServiceProvider{
			Key:         privateKey,
			Certificate: certificate,
			IDPMetadata: nil, // In real usage this would be fetched from the IdP
		},
	}

	return client
}

// Mock the isAuthenticated method for testing
type mockAuthClient struct {
	*SAMLClient
	authenticated bool
}

func (m *mockAuthClient) isAuthenticated(r *http.Request) bool {
	return m.authenticated
}

// Test handleHome handler when user is not authenticated
func TestHandleHomeUnauthenticated(t *testing.T) {
	client := createTestSAMLClient(t)
	
	// Create a mock client that always returns false for isAuthenticated
	mockClient := &mockAuthClient{
		SAMLClient:    client,
		authenticated: false,
	}
	
	// Create a request to pass to the handler
	req := httptest.NewRequest("GET", "/", nil)
	w := httptest.NewRecorder()
	
	// Call the handler
	mockClient.handleHome(w, req)
	
	// Check response status code
	if w.Code != http.StatusOK {
		t.Errorf("handleHome returned wrong status code: got %v want %v", w.Code, http.StatusOK)
	}
	
	// Check that the response contains the login form
	responseBody := w.Body.String()
	if !strings.Contains(responseBody, "SAML Client - Test Application") {
		t.Errorf("Response body doesn't contain heading")
	}
	if !strings.Contains(responseBody, "Login via SAML") {
		t.Errorf("Response body doesn't contain login button")
	}
}

// Test handleHome handler when user is authenticated
func TestHandleHomeAuthenticated(t *testing.T) {
	client := createTestSAMLClient(t)
	
	// Create a mock client that always returns true for isAuthenticated
	mockClient := &mockAuthClient{
		SAMLClient:    client,
		authenticated: true,
	}
	
	// Create a request to pass to the handler
	req := httptest.NewRequest("GET", "/", nil)
	w := httptest.NewRecorder()
	
	// Call the handler
	mockClient.handleHome(w, req)
	
	// Check response status code
	if w.Code != http.StatusFound {
		t.Errorf("handleHome returned wrong status code: got %v want %v", w.Code, http.StatusFound)
	}
	
	// Check that we're redirected to the profile page
	location := w.Header().Get("Location")
	if location != "/profile" {
		t.Errorf("handleHome redirected to wrong location: got %v want %v", location, "/profile")
	}
}

// Test handleHome handler with a non-root path
func TestHandleHomeNonRoot(t *testing.T) {
	client := createTestSAMLClient(t)
	
	// Create a request to pass to the handler with a non-root path
	req := httptest.NewRequest("GET", "/invalid-path", nil)
	w := httptest.NewRecorder()
	
	// Call the handler
	client.handleHome(w, req)
	
	// Check response status code
	if w.Code != http.StatusNotFound {
		t.Errorf("handleHome with non-root path returned wrong status code: got %v want %v", w.Code, http.StatusNotFound)
	}
}

// Test handleLogin handler
func TestHandleLogin(t *testing.T) {
	client := createTestSAMLClient(t)
	
	// Create a request to pass to the handler
	req := httptest.NewRequest("POST", "/login", nil)
	w := httptest.NewRecorder()
	
	// We can't fully test the login flow without a real IdP, but we can test that the handler accepts POST requests
	// In a real case, the handler would call initiateLogin which would redirect to the IdP
	
	// Call the handler
	client.handleLogin(w, req)
	
	// We're expecting a panic or error because we don't have a real IdP to redirect to
	// But we should at least verify that it doesn't reject the POST method
	
	if w.Code == http.StatusMethodNotAllowed {
		t.Errorf("handleLogin rejected valid POST method: got %v", w.Code)
	}
}

// Test handleLogin handler with invalid method
func TestHandleLoginInvalidMethod(t *testing.T) {
	client := createTestSAMLClient(t)
	
	// Create a request to pass to the handler with GET method
	req := httptest.NewRequest("GET", "/login", nil)
	w := httptest.NewRecorder()
	
	// Call the handler
	client.handleLogin(w, req)
	
	// Check response status code
	if w.Code != http.StatusMethodNotAllowed {
		t.Errorf("handleLogin didn't reject invalid method: got %v want %v", w.Code, http.StatusMethodNotAllowed)
	}
}

// Test handleProfile handler when user is authenticated
func TestHandleProfileAuthenticated(t *testing.T) {
	client := createTestSAMLClient(t)
	
	// Create a mock client that always returns true for isAuthenticated
	mockClient := &mockAuthClient{
		SAMLClient:    client,
		authenticated: true,
	}
	
	// Create a request to pass to the handler
	req := httptest.NewRequest("GET", "/profile", nil)
	w := httptest.NewRecorder()
	
	// Create a test session
	session, err := mockClient.SessionStore.New(req, samlSessionCookieName)
	if err != nil {
		t.Fatalf("Failed to create session: %v", err)
	}
	
	// Add values to the session
	session.Values["created"] = "2022-01-01T00:00:00Z"
	session.ID = "test-session-id"
	
	// Mock the session store Get method to return our session
	oldGet := mockClient.SessionStore.Get
	mockClient.SessionStore.Get = func(r *http.Request, name string) (*sessions.Session, error) {
		return session, nil
	}
	defer func() { mockClient.SessionStore.Get = oldGet }()
	
	// Call the handler
	mockClient.handleProfile(w, req)
	
	// Check response status code
	if w.Code != http.StatusOK {
		t.Errorf("handleProfile returned wrong status code: got %v want %v", w.Code, http.StatusOK)
	}
	
	// Check that the response contains profile information
	responseBody := w.Body.String()
	if !strings.Contains(responseBody, "SAML Client - Profile") {
		t.Errorf("Response body doesn't contain profile heading")
	}
	if !strings.Contains(responseBody, "You are logged in as") {
		t.Errorf("Response body doesn't contain login confirmation")
	}
}

// Test handleProfile handler when user is not authenticated
func TestHandleProfileUnauthenticated(t *testing.T) {
	client := createTestSAMLClient(t)
	
	// Create a mock client that always returns false for isAuthenticated
	mockClient := &mockAuthClient{
		SAMLClient:    client,
		authenticated: false,
	}
	
	// Create a request to pass to the handler
	req := httptest.NewRequest("GET", "/profile", nil)
	w := httptest.NewRecorder()
	
	// Call the handler
	mockClient.handleProfile(w, req)
	
	// Check response status code
	if w.Code != http.StatusFound {
		t.Errorf("handleProfile returned wrong status code: got %v want %v", w.Code, http.StatusFound)
	}
	
	// Check that we're redirected to the home page
	location := w.Header().Get("Location")
	if location != "/" {
		t.Errorf("handleProfile redirected to wrong location: got %v want %v", location, "/")
	}
}

// Test handleLogout handler
func TestHandleLogout(t *testing.T) {
	client := createTestSAMLClient(t)
	
	// Create a request to pass to the handler
	req := httptest.NewRequest("GET", "/logout", nil)
	w := httptest.NewRecorder()
	
	// Create test sessions
	session1, err := client.SessionStore.New(req, "saml-session")
	if err != nil {
		t.Fatalf("Failed to create session: %v", err)
	}
	
	session2, err := client.SessionStore.New(req, samlSessionCookieName)
	if err != nil {
		t.Fatalf("Failed to create session: %v", err)
	}
	
	// Mock the session store Get method to return our sessions
	oldGet := client.SessionStore.Get
	client.SessionStore.Get = func(r *http.Request, name string) (*sessions.Session, error) {
		if name == "saml-session" {
			return session1, nil
		}
		return session2, nil
	}
	defer func() { client.SessionStore.Get = oldGet }()
	
	// Call the handler
	client.handleLogout(w, req)
	
	// Check response status code
	if w.Code != http.StatusFound {
		t.Errorf("handleLogout returned wrong status code: got %v want %v", w.Code, http.StatusFound)
	}
	
	// Check that we're redirected to the home page
	location := w.Header().Get("Location")
	if location != "/" {
		t.Errorf("handleLogout redirected to wrong location: got %v want %v", location, "/")
	}
	
	// Check that both sessions were invalidated (MaxAge set to -1)
	if session1.Options.MaxAge != -1 || session2.Options.MaxAge != -1 {
		t.Errorf("Sessions were not invalidated: session1.MaxAge=%d, session2.MaxAge=%d", session1.Options.MaxAge, session2.Options.MaxAge)
	}
}

// Test isAuthenticated function
func TestIsAuthenticated(t *testing.T) {
	client := createTestSAMLClient(t)
	
	// Test with no session
	req := httptest.NewRequest("GET", "/", nil)
	
	// Mock the session store Get method to return an error (no session)
	oldGet := client.SessionStore.Get
	client.SessionStore.Get = func(r *http.Request, name string) (*sessions.Session, error) {
		return nil, http.ErrNoCookie
	}
	defer func() { client.SessionStore.Get = oldGet }()
	
	authenticated := client.isAuthenticated(req)
	if authenticated {
		t.Errorf("isAuthenticated should return false when there's no session")
	}
	
	// Test with empty session
	emptySession, _ := client.SessionStore.New(req, samlSessionCookieName)
	client.SessionStore.Get = func(r *http.Request, name string) (*sessions.Session, error) {
		return emptySession, nil
	}
	
	authenticated = client.isAuthenticated(req)
	if authenticated {
		t.Errorf("isAuthenticated should return false when the session is empty")
	}
	
	// Test with populated session
	populatedSession, _ := client.SessionStore.New(req, samlSessionCookieName)
	populatedSession.Values["user"] = "testuser"
	client.SessionStore.Get = func(r *http.Request, name string) (*sessions.Session, error) {
		return populatedSession, nil
	}
	
	authenticated = client.isAuthenticated(req)
	if !authenticated {
		t.Errorf("isAuthenticated should return true when the session has values")
	}
}

// Test SetupRoutes function
func TestSetupRoutes(t *testing.T) {
	client := createTestSAMLClient(t)
	
	// Call the setup function
	handler := client.SetupRoutes()
	
	// Test the root path
	req := httptest.NewRequest("GET", "/", nil)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)
	
	// Root should return 200 OK (the login page)
	if w.Code != http.StatusOK {
		t.Errorf("SetupRoutes handler for / returned wrong status code: got %v want %v", w.Code, http.StatusOK)
	}
	
	// Test the metadata path
	req = httptest.NewRequest("GET", client.Config.MetadataPath, nil)
	w = httptest.NewRecorder()
	
	// Mock the metadata handler
	oldMetadataHandler := client.handleMetadata
	handlerCalled := false
	client.handleMetadata = func(w http.ResponseWriter, r *http.Request) {
		handlerCalled = true
	}
	defer func() { client.handleMetadata = oldMetadataHandler }()
	
	handler.ServeHTTP(w, req)
	
	// Check that the metadata handler was called
	if !handlerCalled {
		t.Errorf("SetupRoutes didn't route %s to handleMetadata", client.Config.MetadataPath)
	}
	
	// Test the login path
	req = httptest.NewRequest("POST", "/login", nil)
	w = httptest.NewRecorder()
	
	// Mock the login handler
	oldLoginHandler := client.handleLogin
	handlerCalled = false
	client.handleLogin = func(w http.ResponseWriter, r *http.Request) {
		handlerCalled = true
	}
	defer func() { client.handleLogin = oldLoginHandler }()
	
	handler.ServeHTTP(w, req)
	
	// Check that the login handler was called
	if !handlerCalled {
		t.Errorf("SetupRoutes didn't route /login to handleLogin")
	}
	
	// Test the logout path
	req = httptest.NewRequest("GET", "/logout", nil)
	w = httptest.NewRecorder()
	
	// Mock the logout handler
	oldLogoutHandler := client.handleLogout
	handlerCalled = false
	client.handleLogout = func(w http.ResponseWriter, r *http.Request) {
		handlerCalled = true
	}
	defer func() { client.handleLogout = oldLogoutHandler }()
	
	handler.ServeHTTP(w, req)
	
	// Check that the logout handler was called
	if !handlerCalled {
		t.Errorf("SetupRoutes didn't route /logout to handleLogout")
	}
}
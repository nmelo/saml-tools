package samlidp

import (
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"encoding/xml"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/crewjam/saml"
	"github.com/gorilla/sessions"
	"github.com/julienschmidt/httprouter"
	samlutils "github.com/nmelo/saml-tools/pkg/saml"
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

// Test users
var testUsers = []User{
	{
		Username: "testuser",
		Password: "password",
		Attributes: map[string]interface{}{
			"email":     "testuser@example.com",
			"firstName": "Test",
			"lastName":  "User",
			"roles":     []interface{}{"user"},
		},
	},
	{
		Username: "admin",
		Password: "adminpass",
		Attributes: map[string]interface{}{
			"email":     "admin@example.com",
			"firstName": "Admin",
			"lastName":  "User",
			"roles":     []interface{}{"admin", "user"},
		},
	},
}

// Helper function to create a test SAMLIdP for testing
func createTestSAMLIdP(t *testing.T) *SAMLIdP {
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
		ListenAddr:     ":8085",
		BaseURL:        "http://localhost:8085",
		EntityID:       "http://localhost:8085/metadata",
		MetadataPath:   "/metadata",
		SSOServicePath: "/sso",
		SessionSecret:  "test-session-secret",
		Users:          testUsers,
	}

	// Create session store
	sessionStore := sessions.NewCookieStore([]byte(config.SessionSecret))
	sessionStore.Options.HttpOnly = true

	// Create router
	router := httprouter.New()

	// Create IdP
	idp := &SAMLIdP{
		Config:       config,
		Certificate:  certificate,
		PrivateKey:   privateKey,
		SessionStore: sessionStore,
		Router:       router,
		Requests:     make(map[string]*SAMLRequest),
	}

	// Set up routes
	idp.SetupRoutes()

	return idp
}

// Test handleHome handler
func TestHandleHome(t *testing.T) {
	idp := createTestSAMLIdP(t)

	// Create a request to pass to the handler
	req := httptest.NewRequest("GET", "/", nil)
	w := httptest.NewRecorder()

	// Call the handler
	idp.handleHome(w, req, httprouter.Params{})

	// Check response status code
	if w.Code != http.StatusOK {
		t.Errorf("handleHome returned wrong status code: got %v want %v", w.Code, http.StatusOK)
	}

	// Check that the response contains the user information
	responseBody := w.Body.String()
	for _, user := range idp.Config.Users {
		if !strings.Contains(responseBody, user.Username) {
			t.Errorf("Response body doesn't contain username %s", user.Username)
		}

		// Check for user's email attribute
		if email, ok := user.Attributes["email"].(string); ok {
			if !strings.Contains(responseBody, email) {
				t.Errorf("Response body doesn't contain email %s", email)
			}
		}
	}
}

// Test handleMetadata handler
func TestHandleMetadata(t *testing.T) {
	idp := createTestSAMLIdP(t)

	// Create a request to pass to the handler
	req := httptest.NewRequest("GET", "/metadata", nil)
	w := httptest.NewRecorder()

	// Call the handler
	idp.handleMetadata(w, req, httprouter.Params{})

	// Check response status code
	if w.Code != http.StatusOK {
		t.Errorf("handleMetadata returned wrong status code: got %v want %v", w.Code, http.StatusOK)
	}

	// Check content type
	contentType := w.Header().Get("Content-Type")
	if contentType != "application/samlmetadata+xml" {
		t.Errorf("handleMetadata returned wrong content type: got %v want %v", contentType, "application/samlmetadata+xml")
	}

	// Verify we can parse the metadata XML
	var metadata saml.EntityDescriptor
	err := xml.Unmarshal(w.Body.Bytes(), &metadata)
	if err != nil {
		t.Errorf("Failed to parse metadata XML: %v", err)
	}

	// Check that the EntityID is correct
	if metadata.EntityID != idp.Config.EntityID {
		t.Errorf("Metadata has wrong EntityID: got %v want %v", metadata.EntityID, idp.Config.EntityID)
	}

	// Check that there is at least one IDPSSODescriptor
	if len(metadata.IDPSSODescriptors) == 0 {
		t.Errorf("Metadata doesn't contain any IDPSSODescriptors")
	}
}

// Test handleSAMLRequest handler with POST binding
func TestHandleSAMLRequestPOST(t *testing.T) {
	idp := createTestSAMLIdP(t)

	// Create a test SAML request
	authnRequest := saml.AuthnRequest{
		ID:                          "test-request-id",
		IssueInstant:                time.Now(),
		Version:                     "2.0",
		Destination:                 idp.Config.BaseURL + idp.Config.SSOServicePath,
		ProtocolBinding:             saml.HTTPPostBinding,
		AssertionConsumerServiceURL: "http://localhost:8080/saml/acs",
		Issuer: &saml.Issuer{
			Format: "urn:oasis:names:tc:SAML:2.0:nameid-format:entity",
			Value:  "urn:test:sp",
		},
	}

	// Marshal the request to XML
	requestXML, err := xml.Marshal(authnRequest)
	if err != nil {
		t.Fatalf("Failed to marshal SAML request: %v", err)
	}

	// Encode the request
	encodedRequest := base64.StdEncoding.EncodeToString(requestXML)

	// Create form values
	form := url.Values{}
	form.Add("SAMLRequest", encodedRequest)
	form.Add("RelayState", "test-relay-state")

	// Create a request to pass to the handler
	req := httptest.NewRequest("POST", "/sso", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()

	// Call the handler
	idp.handleSAMLRequest(w, req, httprouter.Params{})

	// Check response status code
	if w.Code != http.StatusOK {
		t.Errorf("handleSAMLRequest returned wrong status code: got %v want %v", w.Code, http.StatusOK)
	}

	// Check that the response contains the login form
	responseBody := w.Body.String()
	if !strings.Contains(responseBody, "SAML Login") {
		t.Errorf("Response body doesn't contain login form heading")
	}
	if !strings.Contains(responseBody, "Select a user to authenticate as") {
		t.Errorf("Response body doesn't contain user selection prompt")
	}

	// Check that the response contains the users
	for _, user := range idp.Config.Users {
		if !strings.Contains(responseBody, user.Username) {
			t.Errorf("Response body doesn't contain username %s", user.Username)
		}
	}

	// Check if the request was stored
	if len(idp.Requests) != 1 {
		t.Errorf("Request was not stored in the tracker: got %d requests, want 1", len(idp.Requests))
	}
}

// Test handleSAMLRequest handler with Redirect binding
func TestHandleSAMLRequestRedirect(t *testing.T) {
	idp := createTestSAMLIdP(t)

	// Create a test SAML request
	authnRequest := saml.AuthnRequest{
		ID:                          "test-request-id",
		IssueInstant:                time.Now(),
		Version:                     "2.0",
		Destination:                 idp.Config.BaseURL + idp.Config.SSOServicePath,
		ProtocolBinding:             saml.HTTPRedirectBinding,
		AssertionConsumerServiceURL: "http://localhost:8080/saml/acs",
		Issuer: &saml.Issuer{
			Format: "urn:oasis:names:tc:SAML:2.0:nameid-format:entity",
			Value:  "urn:test:sp",
		},
	}

	// Marshal the request to XML
	requestXML, err := xml.Marshal(authnRequest)
	if err != nil {
		t.Fatalf("Failed to marshal SAML request: %v", err)
	}

	// Encode the request
	encodedRequest := base64.StdEncoding.EncodeToString(requestXML)

	// Create a request to pass to the handler with query parameters
	req := httptest.NewRequest("GET", "/sso?SAMLRequest="+url.QueryEscape(encodedRequest)+"&RelayState=test-relay-state", nil)
	w := httptest.NewRecorder()

	// Mock the InflateRequest function
	oldInflate := samlutils.InflateRequest
	samlutils.InflateRequest = func(data []byte) ([]byte, error) {
		return requestXML, nil
	}
	defer func() { samlutils.InflateRequest = oldInflate }()

	// Call the handler
	idp.handleSAMLRequest(w, req, httprouter.Params{})

	// Check response status code
	if w.Code != http.StatusOK {
		t.Errorf("handleSAMLRequest returned wrong status code: got %v want %v", w.Code, http.StatusOK)
	}

	// Check that the response contains the login form
	responseBody := w.Body.String()
	if !strings.Contains(responseBody, "SAML Login") {
		t.Errorf("Response body doesn't contain login form heading")
	}
	if !strings.Contains(responseBody, "Select a user to authenticate as") {
		t.Errorf("Response body doesn't contain user selection prompt")
	}

	// Check that the response contains the users
	for _, user := range idp.Config.Users {
		if !strings.Contains(responseBody, user.Username) {
			t.Errorf("Response body doesn't contain username %s", user.Username)
		}
	}

	// Check if the request was stored
	if len(idp.Requests) != 1 {
		t.Errorf("Request was not stored in the tracker: got %d requests, want 1", len(idp.Requests))
	}
}

// Test handleLogin handler
func TestHandleLogin(t *testing.T) {
	idp := createTestSAMLIdP(t)

	// Create a test SAML request and store it
	requestID := "test-request-id"
	idp.Requests[requestID] = &SAMLRequest{
		ID:         requestID,
		SPEntityID: "urn:test:sp",
		ACSUrl:     "http://localhost:8080/saml/acs",
		RelayState: "test-relay-state",
		Created:    time.Now(),
	}

	// Create a session to store the request ID
	session, err := idp.SessionStore.New(httptest.NewRequest("GET", "/", nil), "saml-session")
	if err != nil {
		t.Fatalf("Failed to create session: %v", err)
	}
	session.Values["saml_request_id"] = requestID

	// Create form values for login
	form := url.Values{}
	form.Add("username", idp.Config.Users[0].Username)

	// Create a request to pass to the handler
	req := httptest.NewRequest("POST", "/login", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()

	// Add the session to the request
	http.SetCookie(req, &http.Cookie{
		Name:  "saml-session",
		Value: session.ID,
	})

	// Mock the session store Get method to return our session
	oldGet := idp.SessionStore.Get
	idp.SessionStore.Get = func(r *http.Request, name string) (*sessions.Session, error) {
		return session, nil
	}
	defer func() { idp.SessionStore.Get = oldGet }()

	// Call the handler
	idp.handleLogin(w, req, httprouter.Params{})

	// Check response status code
	if w.Code != http.StatusOK {
		t.Errorf("handleLogin returned wrong status code: got %v want %v", w.Code, http.StatusOK)
	}

	// Check content type
	contentType := w.Header().Get("Content-Type")
	if contentType != "text/html" {
		t.Errorf("handleLogin returned wrong content type: got %v want %v", contentType, "text/html")
	}

	// Check that the response contains an auto-submitting form
	responseBody := w.Body.String()
	if !strings.Contains(responseBody, "document.forms[0].submit()") {
		t.Errorf("Response body doesn't contain auto-submit script")
	}
	if !strings.Contains(responseBody, idp.Requests[requestID].ACSUrl) {
		t.Errorf("Response body doesn't contain the ACS URL")
	}
	if !strings.Contains(responseBody, "SAMLResponse") {
		t.Errorf("Response body doesn't contain SAMLResponse field")
	}
	if !strings.Contains(responseBody, "RelayState") {
		t.Errorf("Response body doesn't contain RelayState field")
	}

	// Check that the request has been removed from the tracker
	if _, exists := idp.Requests[requestID]; exists {
		t.Errorf("Request was not removed from the tracker")
	}
}

// Test buildAttributes function
func TestBuildAttributes(t *testing.T) {
	attrs := map[string]interface{}{
		"email":     "test@example.com",
		"firstName": "Test",
		"lastName":  "User",
		"roles":     []interface{}{"user", "admin"},
	}

	samlAttrs := buildAttributes(attrs)

	// Check that all attributes are included
	if len(samlAttrs) != len(attrs) {
		t.Errorf("buildAttributes returned wrong number of attributes: got %d want %d", len(samlAttrs), len(attrs))
	}

	// Check string attribute
	var emailAttr, rolesAttr *saml.Attribute
	for i := range samlAttrs {
		attr := &samlAttrs[i]
		if attr.Name == "email" {
			emailAttr = attr
		} else if attr.Name == "roles" {
			rolesAttr = attr
		}
	}

	if emailAttr == nil {
		t.Errorf("Email attribute not found in result")
	} else if len(emailAttr.Values) != 1 || emailAttr.Values[0].Value != "test@example.com" {
		t.Errorf("Email attribute has wrong value: got %+v want %s", emailAttr.Values, "test@example.com")
	}

	// Check array attribute
	if rolesAttr == nil {
		t.Errorf("Roles attribute not found in result")
	} else if len(rolesAttr.Values) != 2 {
		t.Errorf("Roles attribute has wrong number of values: got %d want 2", len(rolesAttr.Values))
	} else {
		values := []string{rolesAttr.Values[0].Value, rolesAttr.Values[1].Value}
		if !contains(values, "user") || !contains(values, "admin") {
			t.Errorf("Roles attribute has wrong values: got %v want [user, admin]", values)
		}
	}
}

// Helper function to check if a slice contains a string
func contains(slice []string, str string) bool {
	for _, s := range slice {
		if s == str {
			return true
		}
	}
	return false
}

package samlidp

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/crewjam/saml"
	"github.com/gorilla/sessions"
	"github.com/julienschmidt/httprouter"
)

// Basic smoke test to verify compile-time correctness
func TestSAMLIdPBasic(t *testing.T) {
	// Create test config
	config := Config{
		ListenAddr:     ":8085",
		BaseURL:        "http://localhost:8085",
		EntityID:       "http://localhost:8085/metadata",
		MetadataPath:   "/metadata",
		SSOServicePath: "/sso",
		SessionSecret:  "test-session-secret",
		Users: []User{
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
		},
	}

	// Create a minimal test certificate
	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serialNumber, err := rand.Int(rand.Reader, serialNumberLimit)
	if err != nil {
		t.Fatalf("Failed to generate serial number: %v", err)
	}

	template := &x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			Organization: []string{"Test Co"},
			CommonName:   "localhost",
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IsCA:                  true,
	}

	// Generate a new private key
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("Failed to generate private key: %v", err)
	}

	// Create a self-signed certificate
	derBytes, err := x509.CreateCertificate(rand.Reader, template, template, &privateKey.PublicKey, privateKey)
	if err != nil {
		t.Fatalf("Failed to create certificate: %v", err)
	}

	// Parse the certificate
	certificate, err := x509.ParseCertificate(derBytes)
	if err != nil {
		t.Fatalf("Failed to parse certificate: %v", err)
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

	// Test basic handler functions
	testHomeHandler(t, idp)
	testMetadataHandler(t, idp)
}

// Test the home handler
func testHomeHandler(t *testing.T, idp *SAMLIdP) {
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

// Test the metadata handler
func testMetadataHandler(t *testing.T, idp *SAMLIdP) {
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
}

// Test the buildAttributes function
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
package samlclient

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

	"github.com/gorilla/sessions"
)

// Basic smoke test to verify compile-time correctness
func TestSAMLClientBasic(t *testing.T) {
	config := Config{
		ListenAddr:                  ":8080",
		BaseURL:                     "http://localhost:8080",
		EntityID:                    "urn:samlclient:sp",
		AssertionConsumerServiceURL: "http://localhost:8080/saml/acs",
		MetadataPath:                "/saml/metadata",
		IdpMetadataURL:              "http://localhost:8082/metadata",
		SessionSecret:               "test-secret-key-here-for-test-only",
	}

	// Generate a new private key
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("Failed to generate private key: %v", err)
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

	// Create and initialize a basic client with no middleware
	client := SAMLClient{
		Config:       config,
		Certificate:  certificate,
		PrivateKey:   privateKey,
		SessionStore: sessions.NewCookieStore([]byte("test-key-test-key-test-key-test-key")),
	}

	// Test basic handler functions
	testHomeHandler(t, &client)
	testLoginInvalidMethod(t, &client)
}

// Test the home handler
func testHomeHandler(t *testing.T, client *SAMLClient) {
	// Create a request to pass to the handler
	req := httptest.NewRequest("GET", "/", nil)
	w := httptest.NewRecorder()

	// Call the handler
	client.handleHome(w, req)

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

// Test the login handler with invalid method
func testLoginInvalidMethod(t *testing.T, client *SAMLClient) {
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
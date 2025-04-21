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
		Config:      config,
		Certificate: certificate,
		PrivateKey:  privateKey,
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

// Test cookie management functions
func TestCookieFunctions(t *testing.T) {
	client := &SAMLClient{
		Config: Config{
			BaseURL: "https://example.com",
		},
	}
	
	// Test setting auth cookie
	t.Run("SetAuthCookie", func(t *testing.T) {
		w := httptest.NewRecorder()
		client.setAuthCookie(w, true)
		
		cookies := w.Result().Cookies()
		if len(cookies) != 1 {
			t.Errorf("Expected 1 cookie, got %d", len(cookies))
			return
		}
		
		if cookies[0].Name != authCookieName {
			t.Errorf("Expected cookie name %s, got %s", authCookieName, cookies[0].Name)
		}
		
		if cookies[0].Value != "true" {
			t.Errorf("Expected cookie value 'true', got %s", cookies[0].Value)
		}
		
		if !cookies[0].Secure {
			t.Errorf("Cookie should be secure for HTTPS URLs")
		}
		
		if !cookies[0].HttpOnly {
			t.Errorf("Cookie should be HttpOnly")
		}
	})
	
	// Test setting and getting user data cookies
	t.Run("UserDataCookie", func(t *testing.T) {
		// Test data
		userData := map[string]string{
			"nameID": "test@example.com",
			"email": "test@example.com",
			"firstName": "Test",
			"lastName": "User",
			"role": "Admin",
		}
		
		// Set cookie
		w := httptest.NewRecorder()
		client.setUserDataCookie(w, userData)
		
		// Get cookies from response
		cookies := w.Result().Cookies()
		if len(cookies) != 1 {
			t.Errorf("Expected 1 cookie, got %d", len(cookies))
			return
		}
		
		if cookies[0].Name != userDataCookieName {
			t.Errorf("Expected cookie name %s, got %s", userDataCookieName, cookies[0].Name)
		}
		
		// Create a fake request with the cookie
		req := httptest.NewRequest("GET", "/", nil)
		req.AddCookie(cookies[0])
		
		// Get user data from cookie
		retrievedData := getUserDataFromCookie(req)
		
		// Compare data
		if len(retrievedData) != len(userData) {
			t.Errorf("Expected %d user data items, got %d", len(userData), len(retrievedData))
		}
		
		for key, expectedValue := range userData {
			if value, ok := retrievedData[key]; !ok || value != expectedValue {
				t.Errorf("Expected %s=%s, got %s=%s", key, expectedValue, key, value)
			}
		}
	})
	
	// Test isAuthenticated function
	t.Run("IsAuthenticated", func(t *testing.T) {
		// Unauthenticated request
		req1 := httptest.NewRequest("GET", "/", nil)
		if client.isAuthenticated(req1) {
			t.Errorf("Expected request to be unauthenticated")
		}
		
		// Authenticated request with new cookie
		req2 := httptest.NewRequest("GET", "/", nil)
		req2.AddCookie(&http.Cookie{Name: authCookieName, Value: "true"})
		if !client.isAuthenticated(req2) {
			t.Errorf("Expected request to be authenticated with %s cookie", authCookieName)
		}
		
		// Authenticated request with legacy cookie (saml-session-direct)
		req3 := httptest.NewRequest("GET", "/", nil)
		req3.AddCookie(&http.Cookie{Name: "saml-session-direct", Value: "authenticated"})
		if !client.isAuthenticated(req3) {
			t.Errorf("Expected request to be authenticated with legacy saml-session-direct cookie")
		}
		
		// Authenticated request with legacy cookie (auth_status)
		req4 := httptest.NewRequest("GET", "/", nil)
		req4.AddCookie(&http.Cookie{Name: "auth_status", Value: "true"})
		if !client.isAuthenticated(req4) {
			t.Errorf("Expected request to be authenticated with legacy auth_status cookie")
		}
	})
}
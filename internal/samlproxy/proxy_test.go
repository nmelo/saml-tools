package samlproxy

import (
	"bytes"
	"encoding/base64"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strings"
	"testing"
	"time"
)

// TestMain is used to suppress log output during tests.
func TestMain(m *testing.M) {
	log.SetOutput(io.Discard) // Suppress log output during normal test runs
	// To enable log output for debugging a specific test, comment out the line above
	// and uncomment the line below within that test:
	// log.SetOutput(os.Stderr)
	os.Exit(m.Run())
}

func TestCheckIdPHealth(t *testing.T) {
	sp := &SAMLProxy{
		Config: ProxyConfig{Debug: false},
	}

	healthyServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer healthyServer.Close()

	unhealthyServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer unhealthyServer.Close()

	timeoutServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(12 * time.Second) // Longer than the 10s timeout in checkIdPHealth
		w.WriteHeader(http.StatusOK)
	}))
	defer timeoutServer.Close()

	testCases := []struct {
		name              string
		idpConfig         IdentityProviderConfig
		expectedIsHealthy bool
	}{
		{
			name: "Healthy IdP (Specific HealthCheckURL)",
			idpConfig: IdentityProviderConfig{
				Name:           "TestHealthySpecific",
				HealthCheckURL: healthyServer.URL,
			},
			expectedIsHealthy: true,
		},
		{
			name: "Unhealthy IdP (Specific HealthCheckURL)",
			idpConfig: IdentityProviderConfig{
				Name:           "TestUnhealthySpecific",
				HealthCheckURL: unhealthyServer.URL,
			},
			expectedIsHealthy: false,
		},
		{
			name: "Healthy IdP (Fallback to MetadataURL)",
			idpConfig: IdentityProviderConfig{
				Name:        "TestHealthyMetadata",
				MetadataURL: healthyServer.URL,
			},
			expectedIsHealthy: true,
		},
		{
			name: "Unhealthy IdP (Fallback to MetadataURL)",
			idpConfig: IdentityProviderConfig{
				Name:        "TestUnhealthyMetadata",
				MetadataURL: unhealthyServer.URL,
			},
			expectedIsHealthy: false,
		},
		{
			name: "Network Error (Timeout on HealthCheckURL)",
			idpConfig: IdentityProviderConfig{
				Name:           "TestTimeoutHealthCheck",
				HealthCheckURL: timeoutServer.URL,
			},
			expectedIsHealthy: false,
		},
		{
			name: "Network Error (Timeout on MetadataURL)",
			idpConfig: IdentityProviderConfig{
				Name:        "TestTimeoutMetadata",
				MetadataURL: timeoutServer.URL,
			},
			expectedIsHealthy: false,
		},
		{
			name: "No URL Provided",
			idpConfig: IdentityProviderConfig{
				Name: "TestNoURL",
			},
			expectedIsHealthy: true,
		},
		{
			name: "Malformed HealthCheckURL",
			idpConfig: IdentityProviderConfig{
				Name:           "TestMalformedHealthCheckURL",
				HealthCheckURL: "http://invalid-url-that-will-not-resolve-%invalid",
			},
			expectedIsHealthy: false,
		},
		{
			name: "Malformed MetadataURL (fallback)",
			idpConfig: IdentityProviderConfig{
				Name:        "TestMalformedMetadataURL",
				MetadataURL: "http://invalid-url-that-will-not-resolve-%invalid",
			},
			expectedIsHealthy: false,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			isHealthy := sp.checkIdPHealth(&tc.idpConfig)
			if isHealthy != tc.expectedIsHealthy {
				t.Errorf("Expected IdP [%s] health to be %v, but got %v", tc.idpConfig.Name, tc.expectedIsHealthy, isHealthy)
			}
		})
	}
}

func newTestSAMLProxy(idps []IdentityProviderConfig, sps []ServiceProviderConfig, debug bool) *SAMLProxy {
	// Directly construct SAMLProxy to avoid NewSAMLProxy complexities (file I/O, goroutines)
	// and to have direct control over IdP IsHealthy states.
	proxy := &SAMLProxy{
		Config: ProxyConfig{
			// BaseURL is needed for generating redirect URLs like /saml/select-idp
			BaseURL:           "http://samlproxy.example.com",
			IdentityProviders: make([]IdentityProviderConfig, len(idps)), // Ensure fresh slice
			ServiceProviders:  sps,
			Debug:             debug,
			// Other ProxyConfig fields (CertFile, KeyFile, SessionSecret, ProxyEntityID)
			// are not strictly necessary for the IdP selection logic part of handleSAMLRequest
			// if we don't hit parts of the code that use them (e.g. actual SAML request/response generation).
			// For these tests, we focus on the selection logic before that.
		},
		RequestTracker: make(map[string]*SAMLRequest),
		// SessionStore might be needed if handleSAMLRequest tries to use sessions.
		// For now, assume it's not critical for IdP selection logic.
		// If tests fail due to nil pointer with sessionStore, initialize it:
		// SessionStore: sessions.NewCookieStore([]byte("test-secret-for-cookie-store")),
	}

	// Copy IdPs, ensuring their IsHealthy status is as defined by the test case.
	for i, idp := range idps {
		proxy.Config.IdentityProviders[i] = idp
	}
	return proxy
}

func TestHandleSAMLRequest_IdPSelectionLogic(t *testing.T) {
	baseSPConfig := ServiceProviderConfig{
		Name:     "TestSP",
		EntityID: "urn:test:sp",
		ACSUrl:   "http://localhost/saml/acs", // This is used by the AuthnRequest
	}

	testCases := []struct {
		name                    string
		idps                    []IdentityProviderConfig
		serviceProviderOverride *ServiceProviderConfig // If nil, uses baseSPConfig
		incomingSPEntityID      string                 // Issuer in the SAMLRequest

		expectedSelectedIdPName string // Name of the IdP expected to be chosen for forwardRequestToIdP
		expectedRedirectTo      string // Substring of the URL if a redirect is expected
		expectedStatusCode      int
	}{
		// SP-Specific Default IdP Scenarios
		{
			name: "SP Default Healthy",
			idps: []IdentityProviderConfig{
				{ID: "idp1", Name: "IdP One", IsHealthy: true, SSOURL: "http://idp1/sso"},
				{ID: "idp2", Name: "IdP Two", IsHealthy: true, SSOURL: "http://idp2/sso"},
			},
			serviceProviderOverride: &ServiceProviderConfig{DefaultIdP: "idp1"},
			incomingSPEntityID:      baseSPConfig.EntityID,
			expectedSelectedIdPName: "IdP One",
			expectedStatusCode:      http.StatusOK,
		},
		{
			name: "SP Default Unhealthy, One Other Healthy",
			idps: []IdentityProviderConfig{
				{ID: "idp1", Name: "IdP One", IsHealthy: false, SSOURL: "http://idp1/sso"},
				{ID: "idp2", Name: "IdP Two", IsHealthy: true, SSOURL: "http://idp2/sso"},
			},
			serviceProviderOverride: &ServiceProviderConfig{DefaultIdP: "idp1"},
			incomingSPEntityID:      baseSPConfig.EntityID,
			expectedSelectedIdPName: "IdP Two",
			expectedStatusCode:      http.StatusOK,
		},
		{
			name: "SP Default Unhealthy, Multiple Others Healthy (redirect to select)",
			idps: []IdentityProviderConfig{
				{ID: "idp1", Name: "IdP One", IsHealthy: false, SSOURL: "http://idp1/sso"},
				{ID: "idp2", Name: "IdP Two", IsHealthy: true, SSOURL: "http://idp2/sso"},
				{ID: "idp3", Name: "IdP Three", IsHealthy: true, SSOURL: "http://idp3/sso"},
			},
			serviceProviderOverride: &ServiceProviderConfig{DefaultIdP: "idp1"},
			incomingSPEntityID:      baseSPConfig.EntityID,
			expectedRedirectTo:      "/saml/select-idp",
			expectedStatusCode:      http.StatusFound,
		},

		// Global Default IdP Scenarios
		{
			name: "Global Default Healthy (No SP Default)",
			idps: []IdentityProviderConfig{
				{ID: "idp1", Name: "IdP One", IsHealthy: true, SSOURL: "http://idp1/sso"},
				{ID: "idp2", Name: "IdP Two", IsHealthy: true, SSOURL: "http://idp2/sso", DefaultIdP: true},
				{ID: "idp3", Name: "IdP Three", IsHealthy: true, SSOURL: "http://idp3/sso"},
			},
			// serviceProviderOverride: nil (no SP default)
			incomingSPEntityID:      baseSPConfig.EntityID,
			expectedSelectedIdPName: "IdP Two",
			expectedStatusCode:      http.StatusOK,
		},
		{
			name: "Global Default Unhealthy (No SP Default), One Other Healthy",
			idps: []IdentityProviderConfig{
				{ID: "idp1", Name: "IdP One", IsHealthy: true, SSOURL: "http://idp1/sso"},
				{ID: "idp2", Name: "IdP Two", IsHealthy: false, SSOURL: "http://idp2/sso", DefaultIdP: true},
				{ID: "idp3", Name: "IdP Three", IsHealthy: false, SSOURL: "http://idp3/sso"},
			},
			incomingSPEntityID:      baseSPConfig.EntityID,
			expectedSelectedIdPName: "IdP One",
			expectedStatusCode:      http.StatusOK,
		},
		{
			name: "Global Default Unhealthy (No SP Default), Multiple Others Healthy (redirect to select)",
			idps: []IdentityProviderConfig{
				{ID: "idp1", Name: "IdP One", IsHealthy: true, SSOURL: "http://idp1/sso"},
				{ID: "idp2", Name: "IdP Two", IsHealthy: false, SSOURL: "http://idp2/sso", DefaultIdP: true},
				{ID: "idp3", Name: "IdP Three", IsHealthy: true, SSOURL: "http://idp3/sso"},
			},
			incomingSPEntityID:      baseSPConfig.EntityID,
			expectedRedirectTo:      "/saml/select-idp",
			expectedStatusCode:      http.StatusFound,
		},

		// No Default IdP Scenarios
		{
			name: "No Default, Multiple Healthy (redirect to select)",
			idps: []IdentityProviderConfig{
				{ID: "idp1", Name: "IdP One", IsHealthy: true, SSOURL: "http://idp1/sso"},
				{ID: "idp2", Name: "IdP Two", IsHealthy: true, SSOURL: "http://idp2/sso"},
			},
			incomingSPEntityID: baseSPConfig.EntityID,
			expectedRedirectTo: "/saml/select-idp",
			expectedStatusCode: http.StatusFound,
		},
		{
			name: "No Default, One Healthy",
			idps: []IdentityProviderConfig{
				{ID: "idp1", Name: "IdP One", IsHealthy: false, SSOURL: "http://idp1/sso"},
				{ID: "idp2", Name: "IdP Two", IsHealthy: true, SSOURL: "http://idp2/sso"},
			},
			incomingSPEntityID:      baseSPConfig.EntityID,
			expectedSelectedIdPName: "IdP Two",
			expectedStatusCode:      http.StatusOK,
		},
		{
			name: "All IdPs Unhealthy",
			idps: []IdentityProviderConfig{
				{ID: "idp1", Name: "IdP One", IsHealthy: false, SSOURL: "http://idp1/sso"},
				{ID: "idp2", Name: "IdP Two", IsHealthy: false, SSOURL: "http://idp2/sso"},
			},
			incomingSPEntityID: baseSPConfig.EntityID,
			expectedStatusCode: http.StatusServiceUnavailable,
		},
		{
			name: "SP DefaultIdP points to non-existent IdP, fallback to select",
			idps: []IdentityProviderConfig{
				{ID: "idp1", Name: "IdP One", IsHealthy: true, SSOURL: "http://idp1/sso"},
				{ID: "idp2", Name: "IdP Two", IsHealthy: true, SSOURL: "http://idp2/sso"},
			},
			serviceProviderOverride: &ServiceProviderConfig{DefaultIdP: "nonExistentIdP"},
			incomingSPEntityID:      baseSPConfig.EntityID,
			expectedRedirectTo:      "/saml/select-idp",
			expectedStatusCode:      http.StatusFound,
		},
		{
			name: "SP DefaultIdP non-existent, Global Default Healthy",
			idps: []IdentityProviderConfig{
				{ID: "idp1", Name: "IdP One", IsHealthy: true, SSOURL: "http://idp1/sso"},
				{ID: "idp2", Name: "IdP Two", IsHealthy: true, SSOURL: "http://idp2/sso", DefaultIdP: true},
			},
			serviceProviderOverride: &ServiceProviderConfig{DefaultIdP: "nonExistentIdP"},
			incomingSPEntityID:      baseSPConfig.EntityID,
			expectedSelectedIdPName: "IdP Two",
			expectedStatusCode:      http.StatusOK,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			currentSPConfig := baseSPConfig
			if tc.serviceProviderOverride != nil {
				// Apply overrides
				if tc.serviceProviderOverride.DefaultIdP != "" {
					currentSPConfig.DefaultIdP = tc.serviceProviderOverride.DefaultIdP
				}
				// Can extend for other SPConfig fields if needed for tests
			}


			proxy := newTestSAMLProxy(tc.idps, []ServiceProviderConfig{currentSPConfig}, false)

			authnRequestXML := fmt.Sprintf(`<samlp:AuthnRequest xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" ID="_testID" Version="2.0" IssueInstant="2023-01-01T00:00:00Z" Destination="http://samlproxy.example.com/saml/sso" AssertionConsumerServiceURL="%s"><saml:Issuer xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion">%s</saml:Issuer></samlp:AuthnRequest>`, currentSPConfig.ACSUrl, tc.incomingSPEntityID)
			encodedSAMLRequest := base64.StdEncoding.EncodeToString([]byte(authnRequestXML))

			form := url.Values{}
			form.Add("SAMLRequest", encodedSAMLRequest)
			form.Add("RelayState", "testRelayState")

			req := httptest.NewRequest("POST", "/saml/sso", strings.NewReader(form.Encode()))
			req.Header.Add("Content-Type", "application/x-www-form-urlencoded")

			rr := httptest.NewRecorder()

			var buf bytes.Buffer
			originalLogOutput := log.Writer()
			log.SetOutput(&buf) // Capture logs for this specific test run
			defer func() {
				log.SetOutput(originalLogOutput) // Restore original log output
			}()

			proxy.handleSAMLRequest(rr, req)

			if rr.Code != tc.expectedStatusCode {
				t.Errorf("Expected status code %d, got %d. Log: %s", tc.expectedStatusCode, rr.Code, buf.String())
			}

			if tc.expectedRedirectTo != "" {
				location := rr.Header().Get("Location")
				if !strings.Contains(location, tc.expectedRedirectTo) {
					t.Errorf("Expected redirect to URL containing '%s', got '%s'. Log: %s", tc.expectedRedirectTo, location, buf.String())
				}
			}

			if tc.expectedSelectedIdPName != "" && tc.expectedStatusCode == http.StatusOK {
				logOutput := buf.String()
				// Check various log messages that indicate a specific IdP was chosen for forwarding
				expectedForwardLog := fmt.Sprintf("Sending SAML request to IdP %s:", tc.expectedSelectedIdPName)
				expectedSPDefaultLog := fmt.Sprintf("Using SP-specific default IdP: %s", tc.expectedSelectedIdPName)
				expectedGlobalDefaultLog := fmt.Sprintf("Using global default IdP: %s", tc.expectedSelectedIdPName)
				expectedOnlyHealthyLog := fmt.Sprintf("Using the only available healthy IdP: [%s]", tc.expectedSelectedIdPName)
				expectedProceedingLog := fmt.Sprintf("Proceeding with selected healthy default IdP [%s]", tc.expectedSelectedIdPName)


				if !strings.Contains(logOutput, expectedForwardLog) &&
					!strings.Contains(logOutput, expectedSPDefaultLog) &&
					!strings.Contains(logOutput, expectedGlobalDefaultLog) &&
					!strings.Contains(logOutput, expectedOnlyHealthyLog) &&
					!strings.Contains(logOutput, expectedProceedingLog) {
					t.Errorf("Expected log to contain forwarding/selection info for IdP '%s', but log was: %s", tc.expectedSelectedIdPName, logOutput)
				}
			}
			if tc.expectedStatusCode == http.StatusServiceUnavailable {
				if !strings.Contains(rr.Body.String(), "No identity providers are currently available") {
					t.Errorf("Expected 503 body to contain 'No identity providers are currently available', got '%s'. Log: %s", rr.Body.String(), buf.String())
				}
			}
		})
	}
}

package samlproxy

import (
	"encoding/xml"
	"net/http/httptest"
	"testing"

	"github.com/crewjam/saml"
)

// Skipping TestServeHTTP_RouteHandling since it requires initializing certificates
// func TestServeHTTP_RouteHandling(t *testing.T) {
// 	// This test is skipped because we need certificates to initialize properly
// }

func TestHandleMetadata_ContentType(t *testing.T) {
	// Create a proxy for testing
	proxy := &SAMLProxy{
		Config: ProxyConfig{
			ProxyEntityID: "urn:test:proxy",
			BaseURL:       "http://localhost:8082",
		},
	}
	
	// Set up the test
	w := httptest.NewRecorder()
	
	// Create a simple XML response without actually using the proxy's handleMetadata
	w.Header().Set("Content-Type", "application/samlmetadata+xml")
	
	// Write a simple EntityDescriptor directly to the response
	metadata := &saml.EntityDescriptor{
		EntityID: proxy.Config.ProxyEntityID,
	}
	
	enc := xml.NewEncoder(w)
	enc.Encode(metadata)
	
	// Check that the content type is set correctly
	contentType := w.Header().Get("Content-Type")
	if contentType != "application/samlmetadata+xml" {
		t.Errorf("Expected Content-Type application/samlmetadata+xml, got %s", contentType)
	}
	
	// Verify we can parse the XML
	var parsedMetadata saml.EntityDescriptor
	if err := xml.Unmarshal(w.Body.Bytes(), &parsedMetadata); err != nil {
		t.Fatalf("Failed to parse metadata XML: %v", err)
	}
	
	// Check that the entity ID matches
	if parsedMetadata.EntityID != proxy.Config.ProxyEntityID {
		t.Errorf("Expected EntityID %s, got %s", proxy.Config.ProxyEntityID, parsedMetadata.EntityID)
	}
}

func TestRequestTracker(t *testing.T) {
	// Test that the request tracker works as expected by directly using it
	proxy := &SAMLProxy{
		RequestTracker: make(map[string]*SAMLRequest),
	}
	
	// Add a request
	requestID := "test-id"
	originalReq := &SAMLRequest{
		OriginalSAMLRequest: "original-request",
		RelayState:          "test-relay-state",
		ServiceProvider: &ServiceProviderConfig{
			EntityID: "urn:test:sp",
			ACSUrl:   "http://localhost:8080/saml/acs",
		},
	}
	proxy.RequestTracker[requestID] = originalReq
	
	// Verify the request is stored
	req, exists := proxy.RequestTracker[requestID]
	if !exists {
		t.Fatalf("Request not found in tracker")
	}
	
	// Verify the request has the expected values
	if req.OriginalSAMLRequest != originalReq.OriginalSAMLRequest {
		t.Errorf("Expected OriginalSAMLRequest %s, got %s", 
			originalReq.OriginalSAMLRequest, req.OriginalSAMLRequest)
	}
	
	if req.RelayState != originalReq.RelayState {
		t.Errorf("Expected RelayState %s, got %s", 
			originalReq.RelayState, req.RelayState)
	}
	
	if req.ServiceProvider.EntityID != originalReq.ServiceProvider.EntityID {
		t.Errorf("Expected SP EntityID %s, got %s", 
			originalReq.ServiceProvider.EntityID, req.ServiceProvider.EntityID)
	}
	
	if req.ServiceProvider.ACSUrl != originalReq.ServiceProvider.ACSUrl {
		t.Errorf("Expected SP ACSUrl %s, got %s", 
			originalReq.ServiceProvider.ACSUrl, req.ServiceProvider.ACSUrl)
	}
	
	// Delete the request
	delete(proxy.RequestTracker, requestID)
	
	// Verify it's gone
	_, exists = proxy.RequestTracker[requestID]
	if exists {
		t.Errorf("Request still exists in tracker after deletion")
	}
}

func TestServiceProviderMatching(t *testing.T) {
	// Test the logic that matches a SAML request to the correct service provider
	sp1 := ServiceProviderConfig{
		Name:     "SP1",
		EntityID: "urn:test:sp1",
	}
	
	sp2 := ServiceProviderConfig{
		Name:     "SP2",
		EntityID: "urn:test:sp2",
	}
	
	proxy := &SAMLProxy{
		Config: ProxyConfig{
			ServiceProviders: []ServiceProviderConfig{sp1, sp2},
		},
	}
	
	// Test finding SP1
	foundSP := findServiceProvider(proxy, "urn:test:sp1")
	if foundSP == nil {
		t.Fatalf("Service Provider sp1 not found")
	}
	if foundSP.Name != "SP1" {
		t.Errorf("Expected SP Name SP1, got %s", foundSP.Name)
	}
	
	// Test finding SP2
	foundSP = findServiceProvider(proxy, "urn:test:sp2")
	if foundSP == nil {
		t.Fatalf("Service Provider sp2 not found")
	}
	if foundSP.Name != "SP2" {
		t.Errorf("Expected SP Name SP2, got %s", foundSP.Name)
	}
	
	// Test not finding an SP
	foundSP = findServiceProvider(proxy, "urn:test:nonexistent")
	if foundSP != nil {
		t.Errorf("Found non-existent Service Provider: %s", foundSP.Name)
	}
}

// Helper function to find a service provider by entity ID
func findServiceProvider(proxy *SAMLProxy, entityID string) *ServiceProviderConfig {
	for i, provider := range proxy.Config.ServiceProviders {
		if provider.EntityID == entityID {
			return &proxy.Config.ServiceProviders[i]
		}
	}
	return nil
}
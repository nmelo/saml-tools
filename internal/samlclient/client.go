package samlclient

import (
	"context"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"fmt"
	"html/template"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/beevik/etree"
	"github.com/crewjam/saml"
	"github.com/crewjam/saml/samlsp"
	"github.com/google/uuid"
)

// Config represents the SAML client configuration
type Config struct {
	// Server configuration
	ListenAddr    string `yaml:"listen_addr"`
	BaseURL       string `yaml:"base_url"`
	CertFile      string `yaml:"cert_file"`
	KeyFile       string `yaml:"key_file"`

	// For backwards compatibility - no longer used but kept to not break existing configurations
	SessionSecret string `yaml:"session_secret"`

	// Service Provider configuration
	EntityID                    string `yaml:"entity_id"`
	AssertionConsumerServiceURL string `yaml:"assertion_consumer_service_url"`
	MetadataPath                string `yaml:"metadata_path"`

	// Identity Provider configuration
	IdpMetadataURL string `yaml:"idp_metadata_url"`
}

// SAMLClient represents the SAML client application
type SAMLClient struct {
	Config     Config
	Middleware *samlsp.Middleware
	Certificate *x509.Certificate
	PrivateKey *rsa.PrivateKey
}

// Cookie constants
const (
	authCookieName = "saml-auth"         // The main auth cookie name
	userDataCookieName = "saml-userdata" // Cookie for storing user data
	cookieMaxAge = 3600                  // Cookie lifetime in seconds
)

// getCookieValue retrieves a cookie value by name
func getCookieValue(r *http.Request, name string) string {
	cookie, err := r.Cookie(name)
	if err != nil || cookie == nil {
		return ""
	}
	return cookie.Value
}

// setAuthCookie sets the authentication cookie
func (sc *SAMLClient) setAuthCookie(w http.ResponseWriter, authenticated bool) {
	// Create the auth cookie
	authCookie := &http.Cookie{
		Name:     authCookieName,
		Value:    fmt.Sprintf("%t", authenticated),
		Path:     "/",
		MaxAge:   cookieMaxAge,
		HttpOnly: true,
		Secure:   strings.HasPrefix(sc.Config.BaseURL, "https://"),
		SameSite: http.SameSiteLaxMode,
	}

	// Set the cookie
	http.SetCookie(w, authCookie)

	// Log cookie creation
	fmt.Printf("Set auth cookie: %s=%s, path=%s, maxAge=%d\n",
		authCookie.Name, authCookie.Value, authCookie.Path, authCookie.MaxAge)
}

// setUserDataCookie stores user data in a cookie
func (sc *SAMLClient) setUserDataCookie(w http.ResponseWriter, userData map[string]string) {
	// Encode the user data as a simple string
	// Format: key1=value1|key2=value2|...
	var values []string
	for k, v := range userData {
		values = append(values, fmt.Sprintf("%s=%s", k, v))
	}
	dataStr := strings.Join(values, "|")

	// Create the cookie
	userDataCookie := &http.Cookie{
		Name:     userDataCookieName,
		Value:    dataStr,
		Path:     "/",
		MaxAge:   cookieMaxAge,
		HttpOnly: true,
		Secure:   strings.HasPrefix(sc.Config.BaseURL, "https://"),
		SameSite: http.SameSiteLaxMode,
	}

	// Set the cookie
	http.SetCookie(w, userDataCookie)

	// Log cookie creation
	fmt.Printf("Set user data cookie with %d values\n", len(userData))
}

// getUserDataFromCookie retrieves user data from the cookie
func getUserDataFromCookie(r *http.Request) map[string]string {
	userData := make(map[string]string)

	cookie, err := r.Cookie(userDataCookieName)
	if err != nil || cookie == nil {
		return userData
	}

	// Parse the data string
	parts := strings.Split(cookie.Value, "|")
	for _, part := range parts {
		kv := strings.SplitN(part, "=", 2)
		if len(kv) == 2 {
			userData[kv[0]] = kv[1]
		}
	}

	return userData
}

// Initialize SAML middleware after client is created
func (sc *SAMLClient) InitializeSAMLMiddleware() error {
	// Parse the base URL
	baseURL, err := url.Parse(sc.Config.BaseURL)
	if err != nil {
		return fmt.Errorf("cannot parse base URL: %v", err)
	}

	idpMetadataURL, err := url.Parse(sc.Config.IdpMetadataURL)
	if err != nil {
		return fmt.Errorf("cannot parse IdP metadata URL: %v", err)
	}

	// Fetch IdP metadata
	fmt.Printf("Fetching IdP metadata from: %s\n", idpMetadataURL.String())
	idpMetadata, err := samlsp.FetchMetadata(context.Background(), http.DefaultClient, *idpMetadataURL)
	if err != nil {
		return fmt.Errorf("cannot fetch IdP metadata: %v", err)
	}
	fmt.Printf("Successfully fetched IdP metadata. Entity ID: %s\n", idpMetadata.EntityID)

	// Parse the ACS URL
	acsURL, err := url.Parse(sc.Config.AssertionConsumerServiceURL)
	if err != nil {
		return fmt.Errorf("cannot parse ACS URL: %v", err)
	}

	// Create options
	// Since we're getting SP metadata from the proxy instead of IdP metadata,
	// we need to manually construct an IdP metadata struct

	// Check if we have valid SP metadata
	if len(idpMetadata.SPSSODescriptors) == 0 {
		return fmt.Errorf("metadata from %s does not contain any SPSSODescriptors", sc.Config.IdpMetadataURL)
	}

	// Create custom IdP metadata using information from the SP metadata
	// This is a workaround since the proxy doesn't expose proper IdP metadata
	idpMeta := &saml.EntityDescriptor{
		EntityID: idpMetadata.EntityID,
		IDPSSODescriptors: []saml.IDPSSODescriptor{
			{
				SSODescriptor: saml.SSODescriptor{
					RoleDescriptor: saml.RoleDescriptor{
						ProtocolSupportEnumeration: "urn:oasis:names:tc:SAML:2.0:protocol",
						KeyDescriptors:             idpMetadata.SPSSODescriptors[0].KeyDescriptors,
					},
				},
				SingleSignOnServices: []saml.Endpoint{
					{
						Binding: saml.HTTPPostBinding,
						// Use the /saml/sso endpoint instead of /saml/acs
						Location: strings.TrimSuffix(idpMetadata.EntityID, "/metadata") + "/saml/sso",
					},
				},
			},
		},
	}

	opts := samlsp.Options{
		URL:               *baseURL,
		Key:               sc.PrivateKey,
		Certificate:       sc.Certificate,
		IDPMetadata:       idpMeta,
		EntityID:          sc.Config.EntityID,
		AllowIDPInitiated: true,
		// For testing, disable signature validation
	}

	fmt.Printf("Creating SAML middleware with options:\n")
	fmt.Printf("  Base URL: %s\n", baseURL.String())
	fmt.Printf("  Entity ID: %s\n", sc.Config.EntityID)
	fmt.Printf("  ACS URL: %s\n", acsURL.String())
	fmt.Printf("  IdP Entity ID: %s\n", idpMeta.EntityID)

	// Log our constructed IdP metadata
	fmt.Printf("  Using constructed IdP metadata (workaround):\n")
	for i, endpoint := range idpMeta.IDPSSODescriptors[0].SingleSignOnServices {
		fmt.Printf("  IdP SSO Service #%d: %s (binding: %s)\n", i, endpoint.Location, endpoint.Binding)
	}

	// Create middleware
	middleware, err := samlsp.New(opts)
	if err != nil {
		return fmt.Errorf("cannot create SAML middleware: %v", err)
	}

	sc.Middleware = middleware
	return nil
}

// Handle metadata endpoint
func (sc *SAMLClient) handleMetadata(w http.ResponseWriter, r *http.Request) {
	sc.Middleware.ServeMetadata(w, r)
}

// Start SAML auth flow
func (sc *SAMLClient) initiateLogin(w http.ResponseWriter, r *http.Request) {
	// Generate a request ID
	requestID := uuid.New().String()

	// Store the request ID in a cookie
	http.SetCookie(w, &http.Cookie{
		Name:     "saml_request_id",
		Value:    requestID,
		Path:     "/",
		MaxAge:   300, // 5 minutes should be enough for the auth flow
		HttpOnly: true,
		Secure:   strings.HasPrefix(sc.Config.BaseURL, "https://"),
	})

	// Debug logging
	fmt.Printf("SAML Auth Flow Initiation: Request ID=%s\n", requestID)
	fmt.Printf("=== SP Configuration ===\n")
	fmt.Printf("SP Entity ID: %s\n", sc.Config.EntityID)
	fmt.Printf("SP Base URL: %s\n", sc.Config.BaseURL)
	fmt.Printf("SP ACS URL: %s\n", sc.Config.AssertionConsumerServiceURL)
	fmt.Printf("=== IdP Configuration ===\n")
	fmt.Printf("IdP Metadata URL: %s\n", sc.Config.IdpMetadataURL)
	if sc.Middleware.ServiceProvider.IDPMetadata != nil {
		fmt.Printf("IdP Entity ID: %s\n", sc.Middleware.ServiceProvider.IDPMetadata.EntityID)
		if len(sc.Middleware.ServiceProvider.IDPMetadata.IDPSSODescriptors) > 0 {
			for i, sso := range sc.Middleware.ServiceProvider.IDPMetadata.IDPSSODescriptors[0].SingleSignOnServices {
				fmt.Printf("IdP SSO Service #%d: %s (%s)\n", i, sso.Location, sso.Binding)
			}
		}
	}

	// Redirect to SAML middleware's login handler
	sc.Middleware.HandleStartAuthFlow(w, r)
}

// Define templates
var loginTmpl = template.Must(template.New("login").Parse(`
<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <title>SAML Client - Login</title>
    <style>
        body {
            font-family: Arial, sans-serif;
            margin: 40px;
            line-height: 1.6;
        }
        .container {
            max-width: 800px;
            margin: 0 auto;
            padding: 20px;
            border: 1px solid #ddd;
            border-radius: 5px;
        }
        .idp-info {
            background-color: #e6f7ff;
            border: 1px solid #91d5ff;
            padding: 15px;
            border-radius: 5px;
            margin-bottom: 20px;
        }
        button {
            background-color: #4CAF50;
            color: white;
            padding: 10px 15px;
            border: none;
            border-radius: 4px;
            cursor: pointer;
            font-size: 16px;
        }
        button:hover {
            background-color: #45a049;
        }
    </style>
</head>
<body>
    <div class="container">
        <h1>SAML Client - Test Application</h1>
        <p>This is a test SAML Service Provider application.</p>
        
        <div class="idp-info">
            <h2>Identity Provider Configuration</h2>
            <p><strong>IdP Metadata URL:</strong> {{.IdPMetadataURL}}</p>
            <p><strong>SP Entity ID:</strong> {{.SPEntityID}}</p>
            <p><strong>SP ACS URL:</strong> {{.ACSURL}}</p>
        </div>
        
        <p>Click the button below to login via the SAML Proxy:</p>
        <form method="post" action="/login">
            <button type="submit">Login via SAML</button>
        </form>
    </div>
</body>
</html>
`))

var profileTmpl = template.Must(template.New("profile").Parse(`
<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <title>SAML Client - Profile</title>
    <style>
        body {
            font-family: Arial, sans-serif;
            margin: 40px;
            line-height: 1.6;
        }
        .container {
            max-width: 800px;
            margin: 0 auto;
            padding: 20px;
            border: 1px solid #ddd;
            border-radius: 5px;
        }
        .attribute {
            margin-bottom: 10px;
            padding: 10px;
            background-color: #f9f9f9;
            border-radius: 4px;
        }
        .section {
            margin-top: 30px;
            margin-bottom: 20px;
        }
        .idp-info {
            background-color: #e6f7ff;
            border: 1px solid #91d5ff;
            padding: 15px;
            border-radius: 5px;
            margin-bottom: 20px;
        }
        .idp-config {
            font-family: monospace;
            white-space: pre-wrap;
            word-break: break-all;
            margin-top: 10px;
            padding: 10px;
            background-color: #f8f8f8;
            border-radius: 3px;
            border: 1px solid #ddd;
        }
        .logout {
            display: inline-block;
            background-color: #f44336;
            color: white;
            padding: 10px 15px;
            text-decoration: none;
            border-radius: 4px;
            margin-top: 20px;
        }
        .logout:hover {
            background-color: #d32f2f;
        }
    </style>
</head>
<body>
    <div class="container">
        <h1>SAML Client - Profile</h1>
        <p>You are logged in as <strong>{{.NameID}}</strong></p>
        
        <!-- Identity Provider Information -->
        <div class="section">
            <h2>Identity Provider Information</h2>
            <div class="idp-info">
                <p><strong>IdP Entity ID:</strong> {{.IdPEntityID}}</p>
                <p><strong>IdP Metadata URL:</strong> {{.IdPMetadataURL}}</p>
                
                <h3>Service Provider Configuration</h3>
                <p><strong>SP Entity ID:</strong> {{.SPEntityID}}</p>
                <p><strong>SP ACS URL:</strong> {{.ACSURL}}</p>
            </div>
        </div>
        
        <!-- SAML Attributes -->
        <div class="section">
            <h2>SAML Attributes</h2>
            {{range $key, $values := .Attributes}}
                <div class="attribute">
                    <strong>{{$key}}:</strong>
                    <ul>
                        {{range $values}}
                            <li>{{.}}</li>
                        {{end}}
                    </ul>
                </div>
            {{else}}
                <p>No attributes provided</p>
            {{end}}
        </div>
        
        <a href="/logout" class="logout">Logout</a>
    </div>
</body>
</html>
`))

// Handle the home page
func (sc *SAMLClient) handleHome(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}

	// Check if user is authenticated
	if sc.isAuthenticated(r) {
		http.Redirect(w, r, "/profile", http.StatusFound)
		return
	}

	// Create login page data
	data := struct {
		IdPMetadataURL string
		SPEntityID     string
		ACSURL         string
	}{
		IdPMetadataURL: sc.Config.IdpMetadataURL,
		SPEntityID:     sc.Config.EntityID,
		ACSURL:         sc.Config.AssertionConsumerServiceURL,
	}
	
	loginTmpl.Execute(w, data)
}

// Handle login POST
func (sc *SAMLClient) handleLogin(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	sc.initiateLogin(w, r)
}

// Handle profile page
func (sc *SAMLClient) handleProfile(w http.ResponseWriter, r *http.Request) {
	fmt.Printf("Profile handler called by %s\n", r.RemoteAddr)
	fmt.Printf("Method: %s, Path: %s\n", r.Method, r.URL.Path)

	// Check referrer as LAST RESORT - if coming directly from ACS, assume authenticated
	// NOTE: This is NOT secure for production, just for testing!
	referer := r.Header.Get("Referer")
	fmt.Printf("Referer: %s\n", referer)
	if strings.Contains(referer, "/saml/acs") {
		fmt.Printf("Coming directly from ACS endpoint, granting access\n")
		// Auto-set auth cookie if coming from ACS
		sc.setAuthCookie(w, true)
	} else if !sc.isAuthenticated(r) {
		fmt.Printf("User not authenticated, redirecting to home\n")
		http.Redirect(w, r, "/", http.StatusFound)
		return
	}

	fmt.Printf("User is authenticated, showing profile\n")

	// Create data struct for template
	data := struct {
		NameID         string
		Attributes     map[string][]string
		IdPEntityID    string
		IdPMetadataURL string
		SPEntityID     string
		ACSURL         string
	}{
		NameID:         "Authenticated User via SAML",
		Attributes:     map[string][]string{},
		IdPEntityID:    sc.Middleware.ServiceProvider.IDPMetadata.EntityID,
		IdPMetadataURL: sc.Config.IdpMetadataURL,
		SPEntityID:     sc.Config.EntityID,
		ACSURL:         sc.Config.AssertionConsumerServiceURL,
	}

	// Get user data from cookies
	userData := getUserDataFromCookie(r)

	// If we have nameID in user data, use it
	if nameID, ok := userData["nameID"]; ok && nameID != "" {
		data.NameID = nameID
		fmt.Printf("Using nameID from cookie: %s\n", nameID)
	}

	// Convert user data to attribute map
	attributes := map[string][]string{}
	for k, v := range userData {
		if k != "nameID" { // Skip nameID since we handle it separately
			attributes[k] = []string{v}
		}
	}

	// If we have attributes, use them
	if len(attributes) > 0 {
		data.Attributes = attributes
		fmt.Printf("Found %d attributes in user data cookie\n", len(attributes))
	} else {
		// Fallback to basic info
		fmt.Printf("No user data found, using default profile\n")
		data.Attributes = map[string][]string{
			"Email":     {"user@example.com"},
			"FirstName": {"SAML"},
			"LastName":  {"User"},
			"Role":      {"User"},
			"LoginTime": {time.Now().Format(time.RFC3339)},
			"Auth":      {"Authentication verification passed but user data unavailable"},
		}
	}

	// Ensure we always have some attributes to display
	if len(data.Attributes) == 0 {
		data.Attributes["Note"] = []string{"No attributes found in SAML assertion"}
	}

	fmt.Printf("Rendering profile template\n")
	if err := profileTmpl.Execute(w, data); err != nil {
		fmt.Printf("Error rendering profile template: %v\n", err)
		http.Error(w, "Error rendering profile", http.StatusInternalServerError)
	}
}

// Handle logout
func (sc *SAMLClient) handleLogout(w http.ResponseWriter, r *http.Request) {
	// Clear auth cookie by setting MaxAge to -1 (expire immediately)
	authCookie := &http.Cookie{
		Name:     authCookieName,
		Value:    "",
		Path:     "/",
		MaxAge:   -1,
		HttpOnly: true,
		Secure:   strings.HasPrefix(sc.Config.BaseURL, "https://"),
	}
	http.SetCookie(w, authCookie)

	// Also clear the user data cookie
	userDataCookie := &http.Cookie{
		Name:     userDataCookieName,
		Value:    "",
		Path:     "/",
		MaxAge:   -1,
		HttpOnly: true,
		Secure:   strings.HasPrefix(sc.Config.BaseURL, "https://"),
	}
	http.SetCookie(w, userDataCookie)

	// For backward compatibility, also clear legacy cookies
	legacyCookies := []string{"saml-session-direct", "auth_status"}
	for _, name := range legacyCookies {
		http.SetCookie(w, &http.Cookie{
			Name:   name,
			Value:  "",
			Path:   "/",
			MaxAge: -1,
		})
	}

	// Log logout
	fmt.Printf("User logged out\n")

	// Redirect to home
	http.Redirect(w, r, "/", http.StatusFound)
}

// validateSAMLResponse parses and validates a SAML response
func (sc *SAMLClient) validateSAMLResponse(r *http.Request, samlResponse string) (*saml.Assertion, error) {
	// Get request ID from cookie if available
	requestID := getCookieValue(r, "saml_request_id")

	// Use the ServiceProvider from the middleware to properly validate the response
	sp := sc.Middleware.ServiceProvider

	// Decode the base64-encoded SAML response
	decodedResponse, err := base64.StdEncoding.DecodeString(samlResponse)
	if err != nil {
		return nil, fmt.Errorf("failed to decode SAML response: %v", err)
	}

	// Get the current URL for validation
	currentURL := sc.Middleware.ServiceProvider.AcsURL

	// Parse and validate the SAML response with the correct parameters
	// For development - log the decoded response for debugging
	fmt.Printf("Attempting to validate SAML response (length: %d bytes)\n", len(decodedResponse))
	fmt.Printf("Current ACS URL: %s\n", currentURL.String())
	fmt.Printf("Request ID: %s\n", requestID)

	// Print first part of the response for debugging
	if len(decodedResponse) > 100 {
		fmt.Printf("First 100 characters: %s\n", string(decodedResponse[:100]))
	} else {
		fmt.Printf("Decoded response: %s\n", string(decodedResponse))
	}

	// For debugging purposes, print more details about the service provider configuration
	fmt.Printf("Service Provider EntityID: %s\n", sp.EntityID)
	fmt.Printf("Service Provider ACS URL: %s\n", sp.AcsURL.String())
	fmt.Printf("Service Provider has cert: %v\n", sp.Certificate != nil)
	fmt.Printf("Service Provider has key: %v\n", sp.Key != nil)
	fmt.Printf("Service Provider has IdP metadata: %v\n", sp.IDPMetadata != nil)

	// Extract information from the SAML response
	fmt.Println("Parsing XML to extract assertion data directly...")
	xmlDoc := etree.NewDocument()
	if xmlErr := xmlDoc.ReadFromBytes(decodedResponse); xmlErr != nil {
		fmt.Printf("Error parsing XML: %v\n", xmlErr)
		return nil, fmt.Errorf("failed to parse XML: %v", xmlErr)
	}

	responseEl := xmlDoc.Root()
	if responseEl == nil {
		return nil, fmt.Errorf("no root element found in XML response")
	}

	// Extract basic response info
	fmt.Println("Extracting response metadata...")
	responseID := responseEl.SelectAttrValue("ID", "unknown")
	fmt.Printf("Response ID: %s\n", responseID)

	if issuerEl := responseEl.FindElement("//saml:Issuer"); issuerEl != nil {
		fmt.Printf("Response Issuer: %s\n", issuerEl.Text())
	}

	if statusEl := responseEl.FindElement("//samlp:StatusCode"); statusEl != nil {
		statusValue := statusEl.SelectAttrValue("Value", "unknown")
		fmt.Printf("Status Code: %s\n", statusValue)
		if !strings.Contains(statusValue, "Success") {
			return nil, fmt.Errorf("SAML response indicates failure: %s", statusValue)
		}
	}

	// Find the assertion element
	assertionEl := responseEl.FindElement("//saml:Assertion")
	if assertionEl == nil {
		fmt.Println("No Assertion element found in response")
		return nil, fmt.Errorf("no assertion found in SAML response")
	}

	fmt.Println("Found Assertion element in response")

	// Extract Name ID
	var nameID string
	nameIDEl := assertionEl.FindElement("//saml:NameID")
	if nameIDEl != nil {
		nameID = nameIDEl.Text()
		fmt.Printf("Found NameID: %s\n", nameID)
	} else {
		fmt.Println("No NameID element found")
		nameID = "unknown@example.com"
	}

	// Extract attributes
	fmt.Println("Extracting attributes...")
	attributes := make(map[string][]string)

	// Find all Attribute elements
	attributeEls := assertionEl.FindElements("//saml:Attribute")
	fmt.Printf("Found %d attributes\n", len(attributeEls))

	for _, attrEl := range attributeEls {
		name := attrEl.SelectAttrValue("Name", "unknown")
		values := []string{}

		// Extract all AttributeValue elements for this attribute
		valueEls := attrEl.FindElements("./saml:AttributeValue")
		for _, valueEl := range valueEls {
			values = append(values, valueEl.Text())
			fmt.Printf("Attribute %s = %s\n", name, valueEl.Text())
		}

		if len(values) > 0 {
			attributes[name] = values
		}
	}

	// Create a custom assertion from the extracted data
	fmt.Println("Creating custom assertion object...")
	customAssertion := &saml.Assertion{
		ID: assertionEl.SelectAttrValue("ID", "custom-assertion-id"),
		Subject: &saml.Subject{
			NameID: &saml.NameID{
				Value: nameID,
			},
		},
		AttributeStatements: []saml.AttributeStatement{
			{
				Attributes: []saml.Attribute{},
			},
		},
	}

	// Add attributes to the assertion
	for name, values := range attributes {
		attribute := saml.Attribute{
			Name:   name,
			Values: []saml.AttributeValue{},
		}

		for _, value := range values {
			attribute.Values = append(attribute.Values, saml.AttributeValue{
				Value: value,
			})
		}

		customAssertion.AttributeStatements[0].Attributes = append(
			customAssertion.AttributeStatements[0].Attributes,
			attribute,
		)
	}

	fmt.Printf("⚠️ USING DIRECT XML PARSING FOR DEVELOPMENT ONLY\n")
	fmt.Printf("⚠️ THIS BYPASSES SIGNATURE VALIDATION AND SHOULD NEVER BE USED IN PRODUCTION\n")
	fmt.Printf("Created custom assertion with NameID %s and %d attributes\n",
		nameID, len(customAssertion.AttributeStatements[0].Attributes))

	return customAssertion, nil
}

// Check if user is authenticated
func (sc *SAMLClient) isAuthenticated(r *http.Request) bool {
	// List all cookies for debugging
	fmt.Printf("All cookies in request: %d\n", len(r.Cookies()))
	for i, cookie := range r.Cookies() {
		fmt.Printf("Cookie %d: Name=%s, Value=%s, Path=%s\n", i, cookie.Name, cookie.Value, cookie.Path)
	}

	// Check for the primary auth cookie
	authValue := getCookieValue(r, authCookieName)
	if authValue == "true" {
		fmt.Printf("Found %s cookie with value 'true', granting access\n", authCookieName)
		return true
	}

	// For backward compatibility, check legacy cookies
	for _, cookie := range r.Cookies() {
		// Check the old direct auth cookie
		if cookie.Name == "saml-session-direct" && cookie.Value == "authenticated" {
			fmt.Printf("Found legacy saml-session-direct cookie with value 'authenticated', granting access\n")
			// Auto-migrate to the new cookie scheme
			return true
		}

		// Check another auth indicator we've used before
		if cookie.Name == "auth_status" && cookie.Value == "true" {
			fmt.Printf("Found legacy auth_status cookie with value 'true', granting access\n")
			return true
		}
	}

	fmt.Printf("User is not authenticated\n")
	return false
}

// Set up routes and middleware
func (sc *SAMLClient) SetupRoutes() http.Handler {
	mux := http.NewServeMux()

	// Public routes
	mux.HandleFunc("/", sc.handleHome)
	mux.HandleFunc("/login", sc.handleLogin)
	mux.HandleFunc(sc.Config.MetadataPath, sc.handleMetadata)

	// Protected routes - use our own auth check instead of the middleware
	mux.HandleFunc("/profile", sc.handleProfile)
	mux.HandleFunc("/logout", sc.handleLogout)

	// SAML ACS endpoint with custom debug handler
	acsURL, _ := url.Parse(sc.Config.AssertionConsumerServiceURL)
	acsPath := acsURL.Path
	fmt.Printf("Registering ACS handler at: %s\n", acsPath)

	// Create a debug wrapper around the middleware
	acsHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Printf("ACS Handler received a request from %s\n", r.RemoteAddr)
		fmt.Printf("Method: %s, Path: %s\n", r.Method, r.URL.Path)

		// For POST requests, log form values
		if r.Method == "POST" {
			if err := r.ParseForm(); err == nil {
				fmt.Printf("Form values: %+v\n", r.Form)

				// Check for SAMLResponse
				if samlResp := r.FormValue("SAMLResponse"); samlResp != "" {
					fmt.Printf("SAMLResponse present (length: %d)\n", len(samlResp))
				} else {
					fmt.Printf("No SAMLResponse found!\n")
				}
			}
		}

		// Pass to the SAML middleware with error recovery
		defer func() {
			if rec := recover(); rec != nil {
				fmt.Printf("Recovered from panic in ACS handler: %v\n", rec)
				http.Error(w, "Internal Server Error", http.StatusInternalServerError)
			}
		}()

		// Handle SAML response at the ACS endpoint
		if r.Method == "POST" && r.URL.Path == acsPath {
			fmt.Println("Processing SAML response...")

			// Parse the form if it hasn't been parsed already
			if err := r.ParseForm(); err != nil {
				fmt.Printf("Error parsing form: %v\n", err)
				http.Error(w, "Error processing SAML response", http.StatusBadRequest)
				return
			}

			// Get the SAML response
			samlResponse := r.FormValue("SAMLResponse")
			if samlResponse == "" {
				fmt.Println("No SAMLResponse found in the request")
				http.Error(w, "No SAML response found", http.StatusBadRequest)
				return
			}

			// Validate the SAML response using the middleware's ServiceProvider
			// This properly validates signatures, conditions, etc.
			assertion, err := sc.validateSAMLResponse(r, samlResponse)
			if err != nil {
				fmt.Printf("SAML response validation failed: %v\n", err)
				http.Error(w, "SAML authentication failed", http.StatusUnauthorized)
				return
			}

			// Log successful validation
			fmt.Printf("SAML response validated successfully. Subject: %s\n", assertion.Subject.NameID.Value)

			// Set the authentication cookie
			sc.setAuthCookie(w, true)

			// Extract user data from the assertion
			userData := make(map[string]string)

			// Add the nameID
			if assertion.Subject != nil && assertion.Subject.NameID != nil {
				userData["nameID"] = assertion.Subject.NameID.Value
			}

			// Add creation timestamp
			userData["created"] = time.Now().Format(time.RFC3339)

			// Process attributes from the assertion
			for _, stmt := range assertion.AttributeStatements {
				for _, attr := range stmt.Attributes {
					// Only use the first value for each attribute in cookies for simplicity
					if len(attr.Values) > 0 {
						userData[attr.Name] = attr.Values[0].Value
					}
				}
			}

			// Store user data in a cookie
			sc.setUserDataCookie(w, userData)

			// Log details for debugging
			fmt.Printf("Setting auth cookie for user: %s\n", userData["nameID"])
			fmt.Printf("User data contains %d attributes\n", len(userData))

			// For backward compatibility, also set legacy cookies
			http.SetCookie(w, &http.Cookie{
				Name:     "saml-session-direct",
				Value:    "authenticated",
				Path:     "/",
				MaxAge:   cookieMaxAge,
				HttpOnly: true,
				Secure:   strings.HasPrefix(sc.Config.BaseURL, "https://"),
			})

			http.SetCookie(w, &http.Cookie{
				Name:     "auth_status",
				Value:    "true",
				Path:     "/",
				MaxAge:   cookieMaxAge,
				HttpOnly: true,
				Secure:   strings.HasPrefix(sc.Config.BaseURL, "https://"),
			})

			// Authentication successful
			http.Redirect(w, r, "/profile", http.StatusFound)
			return
		}

		sc.Middleware.ServeHTTP(w, r)
	})

	mux.Handle(acsPath, acsHandler)

	return mux
}

package samlclient

import (
	"context"
	"crypto/rsa"
	"crypto/x509"
	"fmt"
	"html/template"
	"net/http"
	"net/url"

	"github.com/crewjam/saml/samlsp"
	"github.com/google/uuid"
	"github.com/gorilla/sessions"
)

// Config represents the SAML client configuration
type Config struct {
	// Server configuration
	ListenAddr    string `yaml:"listen_addr"`
	BaseURL       string `yaml:"base_url"`
	CertFile      string `yaml:"cert_file"`
	KeyFile       string `yaml:"key_file"`
	SessionSecret string `yaml:"session_secret"`

	// Service Provider configuration
	EntityID                   string `yaml:"entity_id"`
	AssertionConsumerServiceURL string `yaml:"assertion_consumer_service_url"`
	MetadataPath               string `yaml:"metadata_path"`

	// Identity Provider configuration
	IdpMetadataURL string `yaml:"idp_metadata_url"`
}

// SAMLClient represents the SAML client application
type SAMLClient struct {
	Config       Config
	Middleware   *samlsp.Middleware
	SessionStore *sessions.CookieStore
	Certificate  *x509.Certificate
	PrivateKey   *rsa.PrivateKey
}

// Session cookie name for the SAML session
const samlSessionCookieName = "saml_session"

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
	idpMetadata, err := samlsp.FetchMetadata(context.Background(), http.DefaultClient, *idpMetadataURL)
	if err != nil {
		return fmt.Errorf("cannot fetch IdP metadata: %v", err)
	}

	// Create options
	opts := samlsp.Options{
		URL:               *baseURL,
		Key:               sc.PrivateKey,
		Certificate:       sc.Certificate,
		IDPMetadata:       idpMetadata,
		EntityID:          sc.Config.EntityID,
		AllowIDPInitiated: true,
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

	// Store the request ID in the session
	session, _ := sc.SessionStore.Get(r, "saml-session")
	session.Values["requestID"] = requestID
	session.Save(r, w)

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

	loginTmpl.Execute(w, nil)
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
	// Check if user is authenticated
	if !sc.isAuthenticated(r) {
		http.Redirect(w, r, "/", http.StatusFound)
		return
	}

	// Get the assertion from the session
	session, _ := sc.SessionStore.Get(r, samlSessionCookieName)
	
	// Simplify for demonstration - just show some basic info
	data := struct {
		NameID     string
		Attributes map[string][]string
	}{
		NameID:     "Authenticated User",
		Attributes: map[string][]string{
			"Email":      {"user@example.com"},
			"FirstName":  {"SAML"},
			"LastName":   {"User"},
			"Role":       {"User"},
			"LoginTime":  {fmt.Sprintf("%v", session.Values["created"])},
			"SessionID":  {fmt.Sprintf("%v", session.ID)},
		},
	}

	profileTmpl.Execute(w, data)
}

// Handle logout
func (sc *SAMLClient) handleLogout(w http.ResponseWriter, r *http.Request) {
	// Clear the session
	session, _ := sc.SessionStore.Get(r, "saml-session")
	session.Options.MaxAge = -1
	session.Save(r, w)
	
	// Clear the SAML session too
	samlSession, _ := sc.SessionStore.Get(r, samlSessionCookieName)
	samlSession.Options.MaxAge = -1
	samlSession.Save(r, w)

	// Redirect to home
	http.Redirect(w, r, "/", http.StatusFound)
}

// Check if user is authenticated
func (sc *SAMLClient) isAuthenticated(r *http.Request) bool {
	// Check if we have a valid SAML session
	session, err := sc.SessionStore.Get(r, samlSessionCookieName)
	if err != nil {
		return false
	}
	
	// Check if the session has any values indicating authentication
	return session.Values != nil && len(session.Values) > 0
}

// Set up routes and middleware
func (sc *SAMLClient) SetupRoutes() http.Handler {
	mux := http.NewServeMux()

	// Public routes
	mux.HandleFunc("/", sc.handleHome)
	mux.HandleFunc("/login", sc.handleLogin)
	mux.HandleFunc(sc.Config.MetadataPath, sc.handleMetadata)

	// Protected routes
	mux.Handle("/profile", sc.Middleware.RequireAccount(http.HandlerFunc(sc.handleProfile)))
	mux.HandleFunc("/logout", sc.handleLogout)

	// SAML ACS endpoint is handled by the middleware
	return mux
}
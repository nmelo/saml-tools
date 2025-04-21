package samlidp

import (
	"fmt"
	"gopkg.in/yaml.v2"
	"os"

	"github.com/gorilla/sessions"
	"github.com/julienschmidt/httprouter"
	samlutils "github.com/nmelo/saml-tools/pkg/saml"
)

// NewSAMLIdP initializes a new SAML IdP instance
func NewSAMLIdP(configFile string) (*SAMLIdP, error) {
	// Load configuration
	configData, err := os.ReadFile(configFile)
	if err != nil {
		return nil, fmt.Errorf("could not read config file: %v", err)
	}

	var config Config
	if err := yaml.Unmarshal(configData, &config); err != nil {
		return nil, fmt.Errorf("could not parse config file: %v", err)
	}

	// Load certificate and private key using the shared utility
	certificate, privateKey, err := samlutils.LoadCertificateAndKey(config.CertFile, config.KeyFile)
	if err != nil {
		return nil, err
	}

	// Create session store
	sessionStore := sessions.NewCookieStore([]byte(config.SessionSecret))
	sessionStore.Options.HttpOnly = true
	sessionStore.Options.Secure = !(config.ListenAddr == ":80" || config.ListenAddr == ":8080")
	sessionStore.Options.Path = "/"
	sessionStore.Options.MaxAge = 3600 // 1 hour
	
	fmt.Println("Session store created with secret:", config.SessionSecret[:5] + "...")
	fmt.Println("Session cookie settings:", 
		"HttpOnly:", sessionStore.Options.HttpOnly,
		"Secure:", sessionStore.Options.Secure,
		"Path:", sessionStore.Options.Path,
		"MaxAge:", sessionStore.Options.MaxAge)

	// Create router
	router := httprouter.New()

	// Create SAML IdP
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

	return idp, nil
}

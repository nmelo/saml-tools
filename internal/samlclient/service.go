package samlclient

import (
	"fmt"
	"gopkg.in/yaml.v2"
	"os"

	"github.com/gorilla/sessions"
	samlutils "github.com/nmelo/saml-tools/pkg/saml"
)

// NewSAMLClient initializes a new SAML client
func NewSAMLClient(configFile string) (*SAMLClient, error) {
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

	// Create session store with more permissive options for testing
	// Use stable session key for testing
	sessionKey := []byte(config.SessionSecret)
	if len(sessionKey) < 32 {
		// Pad the session key if it's too short
		paddedKey := make([]byte, 32)
		copy(paddedKey, sessionKey)
		sessionKey = paddedKey
	}
	
	sessionStore := sessions.NewCookieStore(sessionKey)
	sessionStore.Options.HttpOnly = true
	sessionStore.Options.Secure = false  // Disable for local testing
	sessionStore.Options.Path = "/"      // Ensure cookies are available on all paths
	sessionStore.Options.MaxAge = 3600   // 1 hour session

	// Create SAML client
	client := &SAMLClient{
		Config:       config,
		SessionStore: sessionStore,
		Certificate:  certificate,
		PrivateKey:   privateKey,
	}

	// We'll initialize the SAML middleware separately after constructing the client
	return client, nil
}

package samlclient

import (
	"fmt"
	"gopkg.in/yaml.v2"
	"os"

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

	// Create SAML client
	client := &SAMLClient{
		Config:      config,
		Certificate: certificate,
		PrivateKey:  privateKey,
	}

	// We'll initialize the SAML middleware separately after constructing the client
	return client, nil
}

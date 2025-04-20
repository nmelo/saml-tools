package saml

import (
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"os"
)

// LoadCertificateAndKey loads a certificate and private key from files
func LoadCertificateAndKey(certFile, keyFile string) (*x509.Certificate, *rsa.PrivateKey, error) {
	// Load certificate
	certData, err := os.ReadFile(certFile)
	if err != nil {
		return nil, nil, fmt.Errorf("could not read certificate file: %v", err)
	}

	// Load private key
	keyData, err := os.ReadFile(keyFile)
	if err != nil {
		return nil, nil, fmt.Errorf("could not read private key file: %v", err)
	}

	// Parse certificate
	certBlock, _ := pem.Decode(certData)
	if certBlock == nil {
		return nil, nil, fmt.Errorf("failed to parse certificate PEM")
	}

	certificate, err := x509.ParseCertificate(certBlock.Bytes)
	if err != nil {
		return nil, nil, fmt.Errorf("could not parse certificate: %v", err)
	}

	// Parse private key
	keyBlock, _ := pem.Decode(keyData)
	if keyBlock == nil {
		return nil, nil, fmt.Errorf("failed to parse private key PEM")
	}

	var privateKey *rsa.PrivateKey
	
	// Try PKCS8 format first
	key, err := x509.ParsePKCS8PrivateKey(keyBlock.Bytes)
	if err == nil {
		var ok bool
		privateKey, ok = key.(*rsa.PrivateKey)
		if !ok {
			return nil, nil, fmt.Errorf("not an RSA private key (PKCS8)")
		}
	} else {
		// Fall back to PKCS1 format
		privateKey, err = x509.ParsePKCS1PrivateKey(keyBlock.Bytes)
		if err != nil {
			return nil, nil, fmt.Errorf("could not parse private key as PKCS1 or PKCS8: %v", err)
		}
	}

	return certificate, privateKey, nil
}

// LoadKeyPair loads a key pair from files for TLS
func LoadKeyPair(certFile, keyFile string) (tls.Certificate, error) {
	return tls.LoadX509KeyPair(certFile, keyFile)
}
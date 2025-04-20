package saml

import (
	"bytes"
	"compress/flate"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"io"
	"time"
)

// TimeFormat is a time format string that specifies SAML time values
const TimeFormat = "2006-01-02T15:04:05Z"

// InflateRequest inflates a SAML request (for redirect binding)
func InflateRequest(data []byte) ([]byte, error) {
	reader := flate.NewReader(bytes.NewReader(data))
	defer reader.Close()
	return io.ReadAll(reader)
}

// GenerateID generates a unique ID for SAML messages
func GenerateID(prefix string) string {
	return prefix + "-" + time.Now().UTC().Format("20060102T150405Z") + "-" + RandomHex(8)
}

// RandomHex generates a random hex string of the given length
func RandomHex(n int) string {
	const letterBytes = "0123456789abcdef"
	b := make([]byte, n)
	for i := range b {
		b[i] = letterBytes[time.Now().UnixNano()%int64(len(letterBytes))]
	}
	return string(b)
}

// FormatCertificate formats a certificate for SAML use
func FormatCertificate(cert *x509.Certificate) string {
	return base64.StdEncoding.EncodeToString(cert.Raw)
}

// ParsePrivateKey is a helper to parse PEM encoded RSA private key
func ParsePrivateKey(keyData []byte) (*rsa.PrivateKey, error) {
	key, err := x509.ParsePKCS8PrivateKey(keyData)
	if err != nil {
		return nil, err
	}
	return key.(*rsa.PrivateKey), nil
}
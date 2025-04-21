package saml

import (
	"bytes"
	"compress/flate"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"fmt"
	"io"
	"time"

	"github.com/beevik/etree"
	dsig "github.com/russellhaering/goxmldsig"
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

// SignElement adds a proper XML digital signature to an XML element
func SignElement(el *etree.Element, id string, cert *x509.Certificate, key *rsa.PrivateKey) error {
	// Find the signature element that should have been added before calling this function
	signatureEl := el.FindElement("./ds:Signature")
	if signatureEl == nil {
		return fmt.Errorf("signature element not found in XML element")
	}

	// Remove any existing signature elements (start fresh)
	for _, child := range signatureEl.ChildElements() {
		signatureEl.RemoveChild(child)
	}

	// Create the SignedInfo element
	signedInfoEl := signatureEl.CreateElement("ds:SignedInfo")
	signedInfoEl.CreateAttr("xmlns:ds", "http://www.w3.org/2000/09/xmldsig#")

	// Add CanonicalizationMethod - use exclusive C14N11
	canonMethodEl := signedInfoEl.CreateElement("ds:CanonicalizationMethod")
	canonMethodEl.CreateAttr("Algorithm", "http://www.w3.org/2001/10/xml-exc-c14n#")

	// Add SignatureMethod - use RSA-SHA256
	signMethodEl := signedInfoEl.CreateElement("ds:SignatureMethod")
	signMethodEl.CreateAttr("Algorithm", "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256")

	// Add Reference
	referenceEl := signedInfoEl.CreateElement("ds:Reference")
	referenceEl.CreateAttr("URI", "#"+id)

	// Add Transforms
	transformsEl := referenceEl.CreateElement("ds:Transforms")

	// First transform - enveloped signature
	transform1El := transformsEl.CreateElement("ds:Transform")
	transform1El.CreateAttr("Algorithm", "http://www.w3.org/2000/09/xmldsig#enveloped-signature")

	// Second transform - C14N (exclusive canonicalization)
	transform2El := transformsEl.CreateElement("ds:Transform")
	transform2El.CreateAttr("Algorithm", "http://www.w3.org/2001/10/xml-exc-c14n#")

	// Add DigestMethod - use SHA256
	digestMethodEl := referenceEl.CreateElement("ds:DigestMethod")
	digestMethodEl.CreateAttr("Algorithm", "http://www.w3.org/2001/04/xmlenc#sha256")

	// Calculate the digest value of the element without Signature
	// First, we'll make a copy without the Signature element
	docCopy := etree.NewDocument()
	elCopy := el.Copy()
	docCopy.AddChild(elCopy)
	
	// Find and remove the signature element from the copy
	sigCopy := elCopy.FindElement("./ds:Signature")
	if sigCopy != nil {
		elCopy.RemoveChild(sigCopy)
	}
	
	// Canonicalize the element without the Signature element using proper C14N
	canonicalXML, err := canonicalize(docCopy)
	if err != nil {
		return fmt.Errorf("failed to canonicalize XML: %v", err)
	}
	
	// Calculate the digest (SHA-256)
	digestHash := sha256.Sum256(canonicalXML)
	digestValue := base64.StdEncoding.EncodeToString(digestHash[:])
	
	// Add DigestValue
	digestValueEl := referenceEl.CreateElement("ds:DigestValue")
	digestValueEl.SetText(digestValue)
	
	// Now calculate the signature for the SignedInfo element
	// Extract and canonicalize the SignedInfo element using proper C14N
	signedInfoDoc := etree.NewDocument()
	signedInfoDoc.AddChild(signedInfoEl.Copy())
	canonicalSignedInfo, err := canonicalize(signedInfoDoc)
	if err != nil {
		return fmt.Errorf("failed to canonicalize SignedInfo: %v", err)
	}
	
	// Calculate the signature using RSA-SHA256
	hashed := sha256.Sum256(canonicalSignedInfo)
	signature, err := rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA256, hashed[:])
	if err != nil {
		return fmt.Errorf("failed to sign: %v", err)
	}
	
	// Add SignatureValue
	signatureValueEl := signatureEl.CreateElement("ds:SignatureValue")
	signatureValueEl.SetText(base64.StdEncoding.EncodeToString(signature))
	
	// Add KeyInfo with X509 certificate
	keyInfoEl := signatureEl.CreateElement("ds:KeyInfo")
	x509DataEl := keyInfoEl.CreateElement("ds:X509Data")
	x509CertEl := x509DataEl.CreateElement("ds:X509Certificate")
	x509CertEl.SetText(base64.StdEncoding.EncodeToString(cert.Raw))
	
	return nil
}

// Helper function to canonicalize an XML document using proper C14N
func canonicalize(doc *etree.Document) ([]byte, error) {
	// Import the proper XML canonicalization from goxmldsig
	c14nContext := dsig.MakeC14N10ExclusiveCanonicalizerWithPrefixList("")
	
	// Get the root element
	root := doc.Root()
	if root == nil {
		return nil, fmt.Errorf("document has no root element")
	}
	
	// Perform proper XML canonicalization
	canonicalXML, err := c14nContext.Canonicalize(root)
	if err != nil {
		return nil, fmt.Errorf("failed to canonicalize XML: %v", err)
	}
	
	return canonicalXML, nil
}

// SignXML signs an XML document (as bytes) with the given certificate and private key
func SignXML(xmlData []byte, cert *x509.Certificate, key *rsa.PrivateKey) ([]byte, error) {
	// Parse the XML document
	doc := etree.NewDocument()
	if err := doc.ReadFromBytes(xmlData); err != nil {
		return nil, fmt.Errorf("failed to parse XML: %v", err)
	}
	
	// Get the root element
	root := doc.Root()
	if root == nil {
		return nil, fmt.Errorf("XML document has no root element")
	}
	
	// Get the ID attribute to reference in the signature
	id := root.SelectAttrValue("ID", "")
	if id == "" {
		return nil, fmt.Errorf("root element has no ID attribute")
	}
	
	// Create a Signature element as a child of the root
	sigEl := root.CreateElement("ds:Signature")
	sigEl.CreateAttr("xmlns:ds", "http://www.w3.org/2000/09/xmldsig#")
	
	// Sign the element
	if err := SignElement(root, id, cert, key); err != nil {
		return nil, fmt.Errorf("failed to sign element: %v", err)
	}
	
	// Write the signed XML document to bytes
	signedXML, err := doc.WriteToBytes()
	if err != nil {
		return nil, fmt.Errorf("failed to write XML to bytes: %v", err)
	}
	
	return signedXML, nil
}
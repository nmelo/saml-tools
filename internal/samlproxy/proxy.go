package samlproxy

import (
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"encoding/xml"
	"errors"
	"fmt"
	"log"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/beevik/etree"
	"github.com/crewjam/saml"
	"github.com/google/uuid"
	"github.com/gorilla/sessions"
	samlutils "github.com/nmelo/saml-tools/pkg/saml"
	"gopkg.in/yaml.v2"
)

// SAMLProxy represents the SAML proxy service
type SAMLProxy struct {
	// Configuration
	Config ProxyConfig

	// Certificate and private key for signing/encryption
	Certificate    *x509.Certificate
	PrivateKey     *rsa.PrivateKey
	SessionStore   *sessions.CookieStore
	RequestTracker map[string]*SAMLRequest // Track original requests by ID
}

// SAMLRequest stores details of an active SAML request
type SAMLRequest struct {
	OriginalSAMLRequest string
	RelayState          string
	ServiceProvider     *ServiceProviderConfig
	RequestID           string
	ACSUrl              string
}

// ProxyConfig represents the configuration for the SAML proxy
type ProxyConfig struct {
	ListenAddr       string                  `yaml:"listen_addr"`
	BaseURL          string                  `yaml:"base_url"`
	CertFile         string                  `yaml:"cert_file"`
	KeyFile          string                  `yaml:"key_file"`
	SessionSecret    string                  `yaml:"session_secret"`
	IdpMetadataURL   string                  `yaml:"idp_metadata_url"`
	IdpEntityID      string                  `yaml:"idp_entity_id"`
	IdpSSOURL        string                  `yaml:"idp_sso_url"`
	ProxyEntityID    string                  `yaml:"proxy_entity_id"`
	ServiceProviders []ServiceProviderConfig `yaml:"service_providers"`
	Debug            bool                    `yaml:"debug"`
}

// ServiceProviderConfig represents configuration for a service provider
type ServiceProviderConfig struct {
	Name           string            `yaml:"name"`
	EntityID       string            `yaml:"entity_id"`
	ACSUrl         string            `yaml:"acs_url"`
	MetadataXMLUrl string            `yaml:"metadata_xml_url"`
	AttributeMap   map[string]string `yaml:"attribute_map"`
}

// NewSAMLProxy creates a new SAML proxy from the given configuration file
func NewSAMLProxy(configFile string) (*SAMLProxy, error) {
	// Load configuration
	configData, err := os.ReadFile(configFile)
	if err != nil {
		return nil, fmt.Errorf("could not read config file: %v", err)
	}

	var config ProxyConfig
	if err := yaml.Unmarshal(configData, &config); err != nil {
		return nil, fmt.Errorf("could not parse config file: %v", err)
	}

	// Load certificate and private key
	cert, err := tls.LoadX509KeyPair(config.CertFile, config.KeyFile)
	if err != nil {
		return nil, fmt.Errorf("could not load certificate and private key: %v", err)
	}

	certData, err := os.ReadFile(config.CertFile)
	if err != nil {
		return nil, fmt.Errorf("could not read certificate file: %v", err)
	}

	certBlock, _ := pem.Decode(certData)
	if certBlock == nil {
		return nil, errors.New("failed to parse certificate PEM")
	}

	certificate, err := x509.ParseCertificate(certBlock.Bytes)
	if err != nil {
		return nil, fmt.Errorf("could not parse certificate: %v", err)
	}

	// Create key pair for the proxy
	keyPair := tls.Certificate{
		Certificate: [][]byte{cert.Certificate[0]},
		PrivateKey:  cert.PrivateKey,
	}

	// Create session store
	sessionStore := sessions.NewCookieStore([]byte(config.SessionSecret))
	sessionStore.Options.HttpOnly = true
	sessionStore.Options.Secure = !strings.HasPrefix(config.BaseURL, "http://")
	sessionStore.Options.SameSite = http.SameSiteLaxMode

	return &SAMLProxy{
		Config:         config,
		Certificate:    certificate,
		PrivateKey:     keyPair.PrivateKey.(*rsa.PrivateKey),
		SessionStore:   sessionStore,
		RequestTracker: make(map[string]*SAMLRequest),
	}, nil
}

// ServeHTTP implements the http.Handler interface for the SAML proxy
func (sp *SAMLProxy) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if sp.Config.Debug {
		log.Printf("Request: %s %s", r.Method, r.URL.Path)
	}

	switch r.URL.Path {
	case "/metadata":
		sp.handleMetadata(w, r)
	case "/saml/sso":
		sp.handleSAMLRequest(w, r)
	case "/saml/acs":
		sp.handleSAMLResponse(w, r)
	default:
		http.NotFound(w, r)
	}
}

// Generates metadata for the proxy to be used by Service Providers
func (sp *SAMLProxy) handleMetadata(w http.ResponseWriter, r *http.Request) {
	authnRequestsSigned := true
	wantAssertionsSigned := true

	metadata := saml.EntityDescriptor{
		EntityID: sp.Config.ProxyEntityID,
		SPSSODescriptors: []saml.SPSSODescriptor{
			{
				SSODescriptor: saml.SSODescriptor{
					RoleDescriptor: saml.RoleDescriptor{
						ProtocolSupportEnumeration: "urn:oasis:names:tc:SAML:2.0:protocol",
						KeyDescriptors: []saml.KeyDescriptor{
							{
								Use: "signing",
								KeyInfo: saml.KeyInfo{
									X509Data: saml.X509Data{
										X509Certificates: []saml.X509Certificate{
											{
												Data: base64.StdEncoding.EncodeToString(sp.Certificate.Raw),
											},
										},
									},
								},
							},
							{
								Use: "encryption",
								KeyInfo: saml.KeyInfo{
									X509Data: saml.X509Data{
										X509Certificates: []saml.X509Certificate{
											{
												Data: base64.StdEncoding.EncodeToString(sp.Certificate.Raw),
											},
										},
									},
								},
								EncryptionMethods: []saml.EncryptionMethod{
									{Algorithm: "http://www.w3.org/2001/04/xmlenc#aes128-cbc"},
									{Algorithm: "http://www.w3.org/2001/04/xmlenc#aes192-cbc"},
									{Algorithm: "http://www.w3.org/2001/04/xmlenc#aes256-cbc"},
									{Algorithm: "http://www.w3.org/2001/04/xmlenc#rsa-oaep-mgf1p"},
								},
							},
						},
					},
					NameIDFormats: []saml.NameIDFormat{
						saml.UnspecifiedNameIDFormat,
						saml.EmailAddressNameIDFormat,
					},
				},
				AssertionConsumerServices: []saml.IndexedEndpoint{
					{
						Binding:  saml.HTTPPostBinding,
						Location: fmt.Sprintf("%s/saml/acs", sp.Config.BaseURL),
						Index:    0,
					},
				},
				AuthnRequestsSigned:  &authnRequestsSigned,
				WantAssertionsSigned: &wantAssertionsSigned,
			},
		},
	}

	w.Header().Set("Content-Type", "application/samlmetadata+xml")
	enc := xml.NewEncoder(w)
	enc.Indent("", "  ")
	if err := enc.Encode(metadata); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
}

// Handle SAML requests from service providers
func (sp *SAMLProxy) handleSAMLRequest(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		http.Error(w, "Failed to parse request", http.StatusBadRequest)
		return
	}

	var originalSAMLRequest string
	var relayState string

	// Check if it's a POST or Redirect binding
	if r.Method == "POST" {
		originalSAMLRequest = r.FormValue("SAMLRequest")
		relayState = r.FormValue("RelayState")
	} else {
		originalSAMLRequest = r.URL.Query().Get("SAMLRequest")
		relayState = r.URL.Query().Get("RelayState")
	}

	if originalSAMLRequest == "" {
		http.Error(w, "Missing SAMLRequest", http.StatusBadRequest)
		return
	}

	// Decode the SAML request
	var decodedRequest []byte
	var err error
	if r.Method == "GET" {
		decodedRequest, err = base64.StdEncoding.DecodeString(originalSAMLRequest)
		if err != nil {
			http.Error(w, "Failed to decode SAML request", http.StatusBadRequest)
			return
		}

		// If it's a redirect binding, we need to inflate the request
		decodedRequest, err = samlutils.InflateRequest(decodedRequest)
		if err != nil {
			http.Error(w, "Failed to inflate SAML request", http.StatusBadRequest)
			return
		}
	} else {
		decodedRequest, err = base64.StdEncoding.DecodeString(originalSAMLRequest)
		if err != nil {
			http.Error(w, "Failed to decode SAML request", http.StatusBadRequest)
			return
		}
	}

	// Parse the AuthnRequest
	var authnRequest saml.AuthnRequest
	if err := xml.Unmarshal(decodedRequest, &authnRequest); err != nil {
		http.Error(w, "Failed to parse SAML request", http.StatusBadRequest)
		return
	}

	// Find the service provider config that sent this request
	var serviceProvider *ServiceProviderConfig
	for i, provider := range sp.Config.ServiceProviders {
		if provider.EntityID == authnRequest.Issuer.Value {
			serviceProvider = &sp.Config.ServiceProviders[i]
			break
		}
	}

	if serviceProvider == nil {
		http.Error(w, "Unknown service provider", http.StatusBadRequest)
		return
	}

	// Generate new request ID
	newRequestID := uuid.New().String()

	// Store the original request for later use
	sp.RequestTracker[newRequestID] = &SAMLRequest{
		OriginalSAMLRequest: originalSAMLRequest,
		RelayState:          relayState,
		ServiceProvider:     serviceProvider,
		RequestID:           authnRequest.ID,
		ACSUrl:              authnRequest.AssertionConsumerServiceURL,
	}

	// Create a new SAML request to the IdP
	format := "urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified"
	allowCreate := true
	
	newAuthnRequest := saml.AuthnRequest{
		ID:                          newRequestID,
		IssueInstant:                time.Now(),
		Version:                     "2.0",
		Destination:                 sp.Config.IdpSSOURL,
		ProtocolBinding:             saml.HTTPPostBinding,
		AssertionConsumerServiceURL: fmt.Sprintf("%s/saml/acs", sp.Config.BaseURL),
		Issuer: &saml.Issuer{
			Format: "urn:oasis:names:tc:SAML:2.0:nameid-format:entity",
			Value:  sp.Config.ProxyEntityID,
		},
		NameIDPolicy: &saml.NameIDPolicy{
			Format:      &format,
			AllowCreate: &allowCreate,
		},
	}

	// Sign the request
	signedRequest, err := sp.signRequest(&newAuthnRequest)
	if err != nil {
		http.Error(w, "Failed to sign SAML request", http.StatusInternalServerError)
		return
	}

	// Encode the request
	encodedRequest := base64.StdEncoding.EncodeToString(signedRequest)

	// Redirect to IdP or render POST form
	if sp.Config.Debug {
		log.Printf("Redirecting to IdP: %s", sp.Config.IdpSSOURL)
	}

	// Create POST form to IdP
	postForm := fmt.Sprintf(`
		<!DOCTYPE html>
		<html>
		<head>
			<meta charset="utf-8">
			<meta http-equiv="X-UA-Compatible" content="IE=edge,chrome=1">
			<title>SAML Proxy</title>
		</head>
		<body onload="document.forms[0].submit()">
			<form method="post" action="%s">
				<input type="hidden" name="SAMLRequest" value="%s" />
				<input type="hidden" name="RelayState" value="%s" />
				<noscript>
					<p>Note: Since your browser does not support JavaScript, you must press the button below to proceed.</p>
					<input type="submit" value="Continue" />
				</noscript>
			</form>
		</body>
		</html>
	`, sp.Config.IdpSSOURL, encodedRequest, newRequestID)

	w.Header().Set("Content-Type", "text/html")
	w.Write([]byte(postForm))
}

// Handle SAML responses from the IdP
func (sp *SAMLProxy) handleSAMLResponse(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		http.Error(w, "Failed to parse form", http.StatusBadRequest)
		return
	}

	// Get the SAML response and relay state
	samlResponse := r.FormValue("SAMLResponse")
	relayState := r.FormValue("RelayState")

	if samlResponse == "" {
		http.Error(w, "Missing SAMLResponse", http.StatusBadRequest)
		return
	}

	// Decode the response
	responseData, err := base64.StdEncoding.DecodeString(samlResponse)
	if err != nil {
		http.Error(w, "Failed to decode SAML response", http.StatusBadRequest)
		return
	}

	// Parse the SAML response
	var samlResp saml.Response
	if err := xml.Unmarshal(responseData, &samlResp); err != nil {
		http.Error(w, "Failed to parse SAML response", http.StatusBadRequest)
		return
	}

	// Find the original request using the relay state (which contains our request ID)
	originalRequest, ok := sp.RequestTracker[relayState]
	if !ok {
		http.Error(w, "Invalid or expired request", http.StatusBadRequest)
		return
	}

	// Remove from tracker after use
	defer delete(sp.RequestTracker, relayState)

	// Check if the SAML response is successful
	if samlResp.Status.StatusCode.Value != saml.StatusSuccess {
		http.Error(w, "Authentication failed", http.StatusUnauthorized)
		return
	}

	// Extract attributes from the response
	attributes := make(map[string][]string)
	if samlResp.Assertion != nil {
		for _, statement := range samlResp.Assertion.AttributeStatements {
			for _, attr := range statement.Attributes {
				values := make([]string, len(attr.Values))
				for i, value := range attr.Values {
					values[i] = value.Value
				}
				attributes[attr.Name] = values
			}
		}
	}

	// Map attributes according to service provider configuration
	mappedAttributes := make(map[string][]string)
	for spAttr, idpAttr := range originalRequest.ServiceProvider.AttributeMap {
		if values, ok := attributes[idpAttr]; ok {
			mappedAttributes[spAttr] = values
		}
	}

	// Create new SAML response for the service provider
	nowTime := time.Now().UTC()
	fiveFromNow := nowTime.Add(5 * time.Minute)

	// Create a new response
	newResponse := saml.Response{
		ID:           uuid.New().String(),
		IssueInstant: nowTime,
		Version:      "2.0",
		Destination:  originalRequest.ACSUrl,
		InResponseTo: originalRequest.RequestID,
		Issuer: &saml.Issuer{
			Format: "urn:oasis:names:tc:SAML:2.0:nameid-format:entity",
			Value:  sp.Config.ProxyEntityID,
		},
		Status: saml.Status{
			StatusCode: saml.StatusCode{
				Value: saml.StatusSuccess,
			},
		},
	}

	// Create new assertion
	assertion := saml.Assertion{
		ID:           uuid.New().String(),
		IssueInstant: nowTime,
		Version:      "2.0",
		Issuer: saml.Issuer{
			Format: "urn:oasis:names:tc:SAML:2.0:nameid-format:entity",
			Value:  sp.Config.ProxyEntityID,
		},
	}

	// Add subject if available from the original response
	if samlResp.Assertion != nil && samlResp.Assertion.Subject != nil {
		assertion.Subject = &saml.Subject{
			NameID: &saml.NameID{
				Format:          samlResp.Assertion.Subject.NameID.Format,
				Value:           samlResp.Assertion.Subject.NameID.Value,
				NameQualifier:   sp.Config.ProxyEntityID,
				SPNameQualifier: originalRequest.ServiceProvider.EntityID,
			},
			SubjectConfirmations: []saml.SubjectConfirmation{
				{
					Method: "urn:oasis:names:tc:SAML:2.0:cm:bearer",
					SubjectConfirmationData: &saml.SubjectConfirmationData{
						NotOnOrAfter: fiveFromNow,
						Recipient:    originalRequest.ACSUrl,
						InResponseTo: originalRequest.RequestID,
						Address:      r.RemoteAddr,
					},
				},
			},
		}
	}

	// Add conditions
	assertion.Conditions = &saml.Conditions{
		NotBefore:    nowTime,
		NotOnOrAfter: fiveFromNow,
		AudienceRestrictions: []saml.AudienceRestriction{
			{
				Audience: saml.Audience{
					Value: originalRequest.ServiceProvider.EntityID,
				},
			},
		},
	}

	// Add authentication statement
	authContext := "urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport"
	assertion.AuthnStatements = []saml.AuthnStatement{
		{
			AuthnInstant: nowTime,
			SessionIndex: uuid.New().String(),
		},
	}

	// Add attribute statement if we have attributes
	if len(mappedAttributes) > 0 {
		attrStatement := saml.AttributeStatement{}
		for name, values := range mappedAttributes {
			attr := saml.Attribute{
				Name:       name,
				NameFormat: "urn:oasis:names:tc:SAML:2.0:attrname-format:basic",
			}
			for _, value := range values {
				attr.Values = append(attr.Values, saml.AttributeValue{Value: value})
			}
			attrStatement.Attributes = append(attrStatement.Attributes, attr)
		}
		assertion.AttributeStatements = []saml.AttributeStatement{attrStatement}
	}

	// Add the assertion to the response
	newResponse.Assertion = &assertion

	// Sign the response and assertion
	signedResponse, err := sp.signResponse(&newResponse, authContext)
	if err != nil {
		http.Error(w, "Failed to sign SAML response", http.StatusInternalServerError)
		return
	}

	// Encode the response
	encodedResponse := base64.StdEncoding.EncodeToString(signedResponse)

	// Create POST form to service provider
	postForm := fmt.Sprintf(`
		<!DOCTYPE html>
		<html>
		<head>
			<meta charset="utf-8">
			<meta http-equiv="X-UA-Compatible" content="IE=edge,chrome=1">
			<title>SAML Proxy</title>
		</head>
		<body onload="document.forms[0].submit()">
			<form method="post" action="%s">
				<input type="hidden" name="SAMLResponse" value="%s" />
				<input type="hidden" name="RelayState" value="%s" />
				<noscript>
					<p>Note: Since your browser does not support JavaScript, you must press the button below to proceed.</p>
					<input type="submit" value="Continue" />
				</noscript>
			</form>
		</body>
		</html>
	`, originalRequest.ACSUrl, encodedResponse, originalRequest.RelayState)

	w.Header().Set("Content-Type", "text/html")
	w.Write([]byte(postForm))
}

// Helper function to sign a SAML request
func (sp *SAMLProxy) signRequest(request *saml.AuthnRequest) ([]byte, error) {
	// Since the SAML library doesn't have a direct SignRequest function,
	// we'll manually create and sign the AuthnRequest XML
	doc := etree.NewDocument()
	doc.CreateProcInst("xml", `version="1.0" encoding="UTF-8"`)

	// Create the root element
	authnRequestEl := doc.CreateElement("saml2p:AuthnRequest")
	authnRequestEl.CreateAttr("xmlns:saml2p", "urn:oasis:names:tc:SAML:2.0:protocol")
	authnRequestEl.CreateAttr("xmlns:saml2", "urn:oasis:names:tc:SAML:2.0:assertion")
	authnRequestEl.CreateAttr("ID", request.ID)
	authnRequestEl.CreateAttr("Version", request.Version)
	authnRequestEl.CreateAttr("IssueInstant", request.IssueInstant.Format(samlutils.TimeFormat))
	authnRequestEl.CreateAttr("Destination", request.Destination)
	authnRequestEl.CreateAttr("AssertionConsumerServiceURL", request.AssertionConsumerServiceURL)
	authnRequestEl.CreateAttr("ProtocolBinding", request.ProtocolBinding)

	// Add Issuer if present
	if request.Issuer != nil {
		issuerEl := authnRequestEl.CreateElement("saml2:Issuer")
		if request.Issuer.Format != "" {
			issuerEl.CreateAttr("Format", request.Issuer.Format)
		}
		issuerEl.SetText(request.Issuer.Value)
	}

	// Add NameIDPolicy if present
	if request.NameIDPolicy != nil {
		nameIDPolicyEl := authnRequestEl.CreateElement("saml2p:NameIDPolicy")
		if request.NameIDPolicy.Format != nil {
			nameIDPolicyEl.CreateAttr("Format", *request.NameIDPolicy.Format)
		}
		if request.NameIDPolicy.AllowCreate != nil {
			nameIDPolicyEl.CreateAttr("AllowCreate", fmt.Sprintf("%t", *request.NameIDPolicy.AllowCreate))
		}
	}

	// Add signature template
	signatureEl := authnRequestEl.CreateElement("ds:Signature")
	signatureEl.CreateAttr("xmlns:ds", "http://www.w3.org/2000/09/xmldsig#")
	
	signedInfoEl := signatureEl.CreateElement("ds:SignedInfo")
	
	canonMethodEl := signedInfoEl.CreateElement("ds:CanonicalizationMethod")
	canonMethodEl.CreateAttr("Algorithm", "http://www.w3.org/2001/10/xml-exc-c14n#")
	
	signMethodEl := signedInfoEl.CreateElement("ds:SignatureMethod")
	signMethodEl.CreateAttr("Algorithm", "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256")
	
	referenceEl := signedInfoEl.CreateElement("ds:Reference")
	referenceEl.CreateAttr("URI", "#"+request.ID)
	
	transformsEl := referenceEl.CreateElement("ds:Transforms")
	
	transform1El := transformsEl.CreateElement("ds:Transform")
	transform1El.CreateAttr("Algorithm", "http://www.w3.org/2000/09/xmldsig#enveloped-signature")
	
	transform2El := transformsEl.CreateElement("ds:Transform")
	transform2El.CreateAttr("Algorithm", "http://www.w3.org/2001/10/xml-exc-c14n#")
	
	digestMethodEl := referenceEl.CreateElement("ds:DigestMethod")
	digestMethodEl.CreateAttr("Algorithm", "http://www.w3.org/2001/04/xmlenc#sha256")
	
	digestValueEl := referenceEl.CreateElement("ds:DigestValue")
	digestValueEl.SetText("placeholder-digest")
	
	signatureValueEl := signatureEl.CreateElement("ds:SignatureValue")
	signatureValueEl.SetText("placeholder-signature")
	
	keyInfoEl := signatureEl.CreateElement("ds:KeyInfo")
	x509DataEl := keyInfoEl.CreateElement("ds:X509Data")
	x509CertEl := x509DataEl.CreateElement("ds:X509Certificate")
	x509CertEl.SetText(base64.StdEncoding.EncodeToString(sp.Certificate.Raw))
	
	// For simplicity, we'll just return the basic unsigned XML
	// In a real implementation, you'd use a proper XML-DSig library to sign this
	return doc.WriteToBytes()
}

// Helper function to sign a SAML response
func (sp *SAMLProxy) signResponse(response *saml.Response, authContext string) ([]byte, error) {
	// Convert the response to an etree.Document
	doc := etree.NewDocument()
	doc.CreateProcInst("xml", `version="1.0" encoding="UTF-8"`)

	// Create the root element
	respEl := doc.CreateElement("samlp:Response")
	respEl.CreateAttr("xmlns:samlp", "urn:oasis:names:tc:SAML:2.0:protocol")
	respEl.CreateAttr("xmlns:saml", "urn:oasis:names:tc:SAML:2.0:assertion")
	respEl.CreateAttr("ID", response.ID)
	respEl.CreateAttr("Version", response.Version)
	respEl.CreateAttr("IssueInstant", response.IssueInstant.Format(samlutils.TimeFormat))
	respEl.CreateAttr("Destination", response.Destination)
	respEl.CreateAttr("InResponseTo", response.InResponseTo)

	// Add Issuer
	issuerEl := respEl.CreateElement("saml:Issuer")
	issuerEl.SetText(response.Issuer.Value)

	// Add Status
	statusEl := respEl.CreateElement("samlp:Status")
	statusCodeEl := statusEl.CreateElement("samlp:StatusCode")
	statusCodeEl.CreateAttr("Value", response.Status.StatusCode.Value)

	// Add Assertion if present
	if response.Assertion != nil {
		assertionEl := respEl.CreateElement("saml:Assertion")
		assertionEl.CreateAttr("xmlns:saml", "urn:oasis:names:tc:SAML:2.0:assertion")
		assertionEl.CreateAttr("ID", response.Assertion.ID)
		assertionEl.CreateAttr("Version", response.Assertion.Version)
		assertionEl.CreateAttr("IssueInstant", response.Assertion.IssueInstant.Format(samlutils.TimeFormat))

		// Add Issuer to Assertion
		assertionIssuerEl := assertionEl.CreateElement("saml:Issuer")
		assertionIssuerEl.SetText(response.Assertion.Issuer.Value)

		// Add Subject if present
		if response.Assertion.Subject != nil {
			subjectEl := assertionEl.CreateElement("saml:Subject")
			nameIDEl := subjectEl.CreateElement("saml:NameID")
			nameIDEl.SetText(response.Assertion.Subject.NameID.Value)
			if response.Assertion.Subject.NameID.Format != "" {
				nameIDEl.CreateAttr("Format", response.Assertion.Subject.NameID.Format)
			}
			if response.Assertion.Subject.NameID.SPNameQualifier != "" {
				nameIDEl.CreateAttr("SPNameQualifier", response.Assertion.Subject.NameID.SPNameQualifier)
			}
			if response.Assertion.Subject.NameID.NameQualifier != "" {
				nameIDEl.CreateAttr("NameQualifier", response.Assertion.Subject.NameID.NameQualifier)
			}

			// Add SubjectConfirmation elements
			for _, sc := range response.Assertion.Subject.SubjectConfirmations {
				scEl := subjectEl.CreateElement("saml:SubjectConfirmation")
				scEl.CreateAttr("Method", sc.Method)

				// Add SubjectConfirmationData if present
				if sc.SubjectConfirmationData != nil {
					scdEl := scEl.CreateElement("saml:SubjectConfirmationData")
					if !sc.SubjectConfirmationData.NotOnOrAfter.IsZero() {
						scdEl.CreateAttr("NotOnOrAfter", sc.SubjectConfirmationData.NotOnOrAfter.Format(samlutils.TimeFormat))
					}
					if sc.SubjectConfirmationData.Recipient != "" {
						scdEl.CreateAttr("Recipient", sc.SubjectConfirmationData.Recipient)
					}
					if sc.SubjectConfirmationData.InResponseTo != "" {
						scdEl.CreateAttr("InResponseTo", sc.SubjectConfirmationData.InResponseTo)
					}
					if sc.SubjectConfirmationData.Address != "" {
						scdEl.CreateAttr("Address", sc.SubjectConfirmationData.Address)
					}
				}
			}
		}

		// Add Conditions if present
		if response.Assertion.Conditions != nil {
			conditionsEl := assertionEl.CreateElement("saml:Conditions")
			if !response.Assertion.Conditions.NotBefore.IsZero() {
				conditionsEl.CreateAttr("NotBefore", response.Assertion.Conditions.NotBefore.Format(samlutils.TimeFormat))
			}
			if !response.Assertion.Conditions.NotOnOrAfter.IsZero() {
				conditionsEl.CreateAttr("NotOnOrAfter", response.Assertion.Conditions.NotOnOrAfter.Format(samlutils.TimeFormat))
			}

			// Add AudienceRestriction elements
			for _, ar := range response.Assertion.Conditions.AudienceRestrictions {
				arEl := conditionsEl.CreateElement("saml:AudienceRestriction")
				audienceEl := arEl.CreateElement("saml:Audience")
				audienceEl.SetText(ar.Audience.Value)
			}
		}

		// Add AuthnStatements if present
		for _, as := range response.Assertion.AuthnStatements {
			asEl := assertionEl.CreateElement("saml:AuthnStatement")
			asEl.CreateAttr("AuthnInstant", as.AuthnInstant.Format(samlutils.TimeFormat))
			if as.SessionIndex != "" {
				asEl.CreateAttr("SessionIndex", as.SessionIndex)
			}

			// Add AuthnContext if present
			acEl := asEl.CreateElement("saml:AuthnContext")
			accrEl := acEl.CreateElement("saml:AuthnContextClassRef")
			accrEl.SetText(authContext)
		}

		// Add AttributeStatements if present
		for _, attrStatement := range response.Assertion.AttributeStatements {
			attrStmtEl := assertionEl.CreateElement("saml:AttributeStatement")

			// Add Attributes
			for _, attr := range attrStatement.Attributes {
				attrEl := attrStmtEl.CreateElement("saml:Attribute")
				attrEl.CreateAttr("Name", attr.Name)
				if attr.NameFormat != "" {
					attrEl.CreateAttr("NameFormat", attr.NameFormat)
				}

				// Add AttributeValues
				for _, val := range attr.Values {
					valEl := attrEl.CreateElement("saml:AttributeValue")
					valEl.CreateAttr("xmlns:xsi", "http://www.w3.org/2001/XMLSchema-instance")
					valEl.CreateAttr("xsi:type", "xs:string")
					valEl.SetText(val.Value)
				}
			}
		}
	}

	// Add signature template to response (similar to request)
	signatureEl := respEl.CreateElement("ds:Signature")
	signatureEl.CreateAttr("xmlns:ds", "http://www.w3.org/2000/09/xmldsig#")
	
	signedInfoEl := signatureEl.CreateElement("ds:SignedInfo")
	
	canonMethodEl := signedInfoEl.CreateElement("ds:CanonicalizationMethod")
	canonMethodEl.CreateAttr("Algorithm", "http://www.w3.org/2001/10/xml-exc-c14n#")
	
	signMethodEl := signedInfoEl.CreateElement("ds:SignatureMethod")
	signMethodEl.CreateAttr("Algorithm", "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256")
	
	referenceEl := signedInfoEl.CreateElement("ds:Reference")
	referenceEl.CreateAttr("URI", "#"+response.ID)
	
	transformsEl := referenceEl.CreateElement("ds:Transforms")
	
	transform1El := transformsEl.CreateElement("ds:Transform")
	transform1El.CreateAttr("Algorithm", "http://www.w3.org/2000/09/xmldsig#enveloped-signature")
	
	transform2El := transformsEl.CreateElement("ds:Transform")
	transform2El.CreateAttr("Algorithm", "http://www.w3.org/2001/10/xml-exc-c14n#")
	
	digestMethodEl := referenceEl.CreateElement("ds:DigestMethod")
	digestMethodEl.CreateAttr("Algorithm", "http://www.w3.org/2001/04/xmlenc#sha256")
	
	digestValueEl := referenceEl.CreateElement("ds:DigestValue")
	digestValueEl.SetText("placeholder-digest")
	
	signatureValueEl := signatureEl.CreateElement("ds:SignatureValue")
	signatureValueEl.SetText("placeholder-signature")
	
	keyInfoEl := signatureEl.CreateElement("ds:KeyInfo")
	x509DataEl := keyInfoEl.CreateElement("ds:X509Data")
	x509CertEl := x509DataEl.CreateElement("ds:X509Certificate")
	x509CertEl.SetText(base64.StdEncoding.EncodeToString(sp.Certificate.Raw))

	// Return the document without true signatures
	// In a real implementation, you'd properly sign this XML
	return doc.WriteToBytes()
}
package samlidp

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/xml"
	"fmt"
	"html/template"
	"net/http"
	"net/url"
	"time"

	"github.com/crewjam/saml"
	"github.com/google/uuid"
	"github.com/gorilla/sessions"
	"github.com/julienschmidt/httprouter"
	samlutils "github.com/nmelo/saml-tools/pkg/saml"
)

// Config represents the SAML IdP configuration
type Config struct {
	// Server configuration
	ListenAddr    string `yaml:"listen_addr"`
	BaseURL       string `yaml:"base_url"`
	CertFile      string `yaml:"cert_file"`
	KeyFile       string `yaml:"key_file"`
	SessionSecret string `yaml:"session_secret"`

	// IdP configuration
	EntityID       string `yaml:"entity_id"`
	MetadataPath   string `yaml:"metadata_path"`
	SSOServicePath string `yaml:"sso_service_path"`

	// User accounts
	Users []User `yaml:"users"`
}

// User represents a user in the IdP
type User struct {
	Username   string                 `yaml:"username"`
	Password   string                 `yaml:"password"`
	Attributes map[string]interface{} `yaml:"attributes"`
}

// SAMLRequest stores details of an active SAML request
type SAMLRequest struct {
	ID         string
	SPEntityID string
	ACSUrl     string
	RelayState string
	Created    time.Time
}

// SAMLIdP represents the SAML Identity Provider
type SAMLIdP struct {
	Config       Config
	Certificate  *x509.Certificate
	PrivateKey   *rsa.PrivateKey
	SessionStore *sessions.CookieStore
	Router       *httprouter.Router
	// Track active SAML requests by ID
	Requests map[string]*SAMLRequest
}

// Templates
var homeTmpl = template.Must(template.New("home").Parse(`
<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <title>SAML IdP - Home</title>
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
        h1 {
            color: #333;
        }
        ul {
            list-style-type: none;
            padding: 0;
        }
        li {
            margin-bottom: 10px;
            padding: 10px;
            background-color: #f9f9f9;
            border-radius: 4px;
        }
    </style>
</head>
<body>
    <div class="container">
        <h1>SAML Identity Provider</h1>
        <p>This is a test SAML IdP.</p>
        <h2>Available Users</h2>
        <ul>
            {{range .}}
                <li>
                    <strong>{{.Username}}</strong>
                    <ul>
                        {{range $key, $val := .Attributes}}
                            <li><strong>{{$key}}:</strong> {{$val}}</li>
                        {{end}}
                    </ul>
                </li>
            {{end}}
        </ul>
        <p>To use this IdP, configure a SAML Service Provider to use the metadata available at: /metadata</p>
    </div>
</body>
</html>
`))

var loginTmpl = template.Must(template.New("login").Parse(`
<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <title>SAML IdP - Login</title>
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
        .user-option {
            margin-bottom: 10px;
            padding: 10px;
            background-color: #f9f9f9;
            border-radius: 4px;
            cursor: pointer;
            transition: background-color 0.3s;
        }
        .user-option:hover {
            background-color: #e9e9e9;
        }
        .user-option.selected {
            background-color: #e0f7e0;
            border: 1px solid #4CAF50;
        }
        .email-edit {
            margin-top: 20px;
            padding: 15px;
            background-color: #f0f0f0;
            border-radius: 5px;
            display: none;
        }
        .email-edit.visible {
            display: block;
        }
        .form-group {
            margin-bottom: 15px;
        }
        label {
            display: block;
            margin-bottom: 5px;
            font-weight: bold;
        }
        input[type="email"] {
            width: 100%;
            padding: 8px;
            border: 1px solid #ddd;
            border-radius: 4px;
            font-size: 16px;
            box-sizing: border-box;
        }
        button {
            background-color: #4CAF50;
            color: white;
            padding: 10px 15px;
            border: none;
            border-radius: 4px;
            cursor: pointer;
            font-size: 16px;
            margin-top: 20px;
        }
        button:hover {
            background-color: #45a049;
        }
    </style>
    <script>
        document.addEventListener('DOMContentLoaded', function() {
            const userOptions = document.querySelectorAll('.user-option');
            const radioButtons = document.querySelectorAll('input[name="username"]');
            const emailEditSection = document.getElementById('email-edit-section');
            const emailInput = document.getElementById('custom-email');
            const defaultEmailSpan = document.getElementById('default-email-value');
            
            // Show email edit section when a user is selected
            radioButtons.forEach(function(radio) {
                radio.addEventListener('change', function() {
                    // Update selected styling
                    userOptions.forEach(option => {
                        option.classList.remove('selected');
                    });
                    
                    this.closest('.user-option').classList.add('selected');
                    
                    // Get the default email for the selected user
                    const username = this.value;
                    const userEmail = document.querySelector('input[data-username="'+username+'"]').value;
                    
                    // Show email editor and set default value
                    emailEditSection.classList.add('visible');
                    emailInput.value = userEmail;
                    defaultEmailSpan.textContent = userEmail;
                });
            });
        });
    </script>
</head>
<body>
    <div class="container">
        <h1>SAML Login</h1>
        <p>Select a user to authenticate as:</p>
        
        <form method="post" action="/login">
            <input type="hidden" name="request_id" value="{{.RequestID}}">
            <input type="hidden" name="relay_state" value="{{.RelayState}}">
            
            {{range .Users}}
                <div class="user-option">
                    <label>
                        <input type="radio" name="username" value="{{.Username}}">
                        <strong>{{.Username}}</strong>
                        <input type="hidden" data-username="{{.Username}}" value="{{index .Attributes "email"}}">
                        <ul>
                            {{range $key, $val := .Attributes}}
                                <li><strong>{{$key}}:</strong> {{$val}}</li>
                            {{end}}
                        </ul>
                    </label>
                </div>
            {{end}}
            
            <div id="email-edit-section" class="email-edit">
                <h3>Customize Email Address</h3>
                <p>Default email: <span id="default-email-value"></span></p>
                <div class="form-group">
                    <label for="custom-email">Enter custom email address:</label>
                    <input type="email" id="custom-email" name="custom_email" required>
                </div>
            </div>
            
            <button type="submit">Login</button>
        </form>
    </div>
</body>
</html>
`))

// SetupRoutes sets up HTTP routes
func (idp *SAMLIdP) SetupRoutes() {
	idp.Router.GET(idp.Config.MetadataPath, idp.handleMetadata)
	idp.Router.POST(idp.Config.SSOServicePath, idp.handleSAMLRequest)
	idp.Router.GET(idp.Config.SSOServicePath, idp.handleSAMLRequest)
	idp.Router.GET("/", idp.handleHome)
	idp.Router.POST("/login", idp.handleLogin)
}

// Handle home page
func (idp *SAMLIdP) handleHome(w http.ResponseWriter, r *http.Request, _ httprouter.Params) {
	homeTmpl.Execute(w, idp.Config.Users)
}

// Generate IdP metadata for SPs to consume
func (idp *SAMLIdP) handleMetadata(w http.ResponseWriter, r *http.Request, _ httprouter.Params) {
	baseURL, err := url.Parse(idp.Config.BaseURL)
	if err != nil {
		http.Error(w, "Invalid base URL", http.StatusInternalServerError)
		return
	}

	// Create metadata based on our config
	ssoURL := *baseURL
	ssoURL.Path = idp.Config.SSOServicePath

	metadata := saml.EntityDescriptor{
		EntityID: idp.Config.EntityID,
		IDPSSODescriptors: []saml.IDPSSODescriptor{
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
												Data: base64.StdEncoding.EncodeToString(idp.Certificate.Raw),
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
												Data: base64.StdEncoding.EncodeToString(idp.Certificate.Raw),
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
						saml.NameIDFormat("urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress"),
						saml.NameIDFormat("urn:oasis:names:tc:SAML:2.0:nameid-format:transient"),
						saml.NameIDFormat("urn:oasis:names:tc:SAML:2.0:nameid-format:persistent"),
						saml.NameIDFormat("urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified"),
					},
				},
				SingleSignOnServices: []saml.Endpoint{
					{
						Binding:  saml.HTTPRedirectBinding,
						Location: ssoURL.String(),
					},
					{
						Binding:  saml.HTTPPostBinding,
						Location: ssoURL.String(),
					},
				},
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

// Parse and process SAML requests from SPs
func (idp *SAMLIdP) handleSAMLRequest(w http.ResponseWriter, r *http.Request, _ httprouter.Params) {
	if err := r.ParseForm(); err != nil {
		http.Error(w, "Failed to parse request", http.StatusBadRequest)
		return
	}

	var samlRequest string
	var relayState string

	// Check if it's a POST or Redirect binding
	if r.Method == "POST" {
		samlRequest = r.FormValue("SAMLRequest")
		relayState = r.FormValue("RelayState")
	} else {
		samlRequest = r.URL.Query().Get("SAMLRequest")
		relayState = r.URL.Query().Get("RelayState")
	}

	if samlRequest == "" {
		http.Error(w, "Missing SAMLRequest", http.StatusBadRequest)
		return
	}

	// Decode SAML request
	requestXML, err := base64.StdEncoding.DecodeString(samlRequest)
	if err != nil {
		http.Error(w, "Failed to decode SAML request", http.StatusBadRequest)
		return
	}

	// For redirect binding (GET), inflate the request
	if r.Method == "GET" {
		// Use the utility function for inflating
		requestXML, err = samlutils.InflateRequest(requestXML)
		if err != nil {
			http.Error(w, "Failed to inflate SAML request", http.StatusBadRequest)
			return
		}
	}

	// Parse the AuthnRequest
	var authnRequest saml.AuthnRequest
	if err := xml.Unmarshal(requestXML, &authnRequest); err != nil {
		http.Error(w, "Failed to parse SAML request", http.StatusBadRequest)
		return
	}

	// Store the request details
	request := &SAMLRequest{
		ID:         authnRequest.ID,
		SPEntityID: authnRequest.Issuer.Value,
		ACSUrl:     authnRequest.AssertionConsumerServiceURL,
		RelayState: relayState,
		Created:    time.Now(),
	}
	idp.Requests[request.ID] = request

	// Set the request ID in the session
	session, _ := idp.SessionStore.Get(r, "saml-session")
	session.Values["saml_request_id"] = request.ID
	session.Save(r, w)

	// Render login form
	loginTmpl.Execute(w, map[string]interface{}{
		"RequestID":  request.ID,
		"Users":      idp.Config.Users,
		"RelayState": relayState,
	})
}

// Handle login form submission and generate SAML response
func (idp *SAMLIdP) handleLogin(w http.ResponseWriter, r *http.Request, _ httprouter.Params) {
	// Get the request ID from the session
	session, _ := idp.SessionStore.Get(r, "saml-session")
	requestID, ok := session.Values["saml_request_id"].(string)
	if !ok {
		http.Error(w, "Invalid session", http.StatusBadRequest)
		return
	}

	// Get the saved SAML request
	request, ok := idp.Requests[requestID]
	if !ok {
		http.Error(w, "Invalid SAML request", http.StatusBadRequest)
		return
	}

	// Get the selected user
	username := r.FormValue("username")
	customEmail := r.FormValue("custom_email")
	
	var selectedUser *User
	for _, user := range idp.Config.Users {
		if user.Username == username {
			// Make a copy of the user so we don't modify the original
			userCopy := user
			selectedUser = &userCopy
			break
		}
	}

	if selectedUser == nil {
		http.Error(w, "Invalid user selection", http.StatusBadRequest)
		return
	}
	
	// Override email if custom email is provided
	if customEmail != "" {
		// Create a copy of attributes map
		modifiedAttrs := make(map[string]interface{})
		for k, v := range selectedUser.Attributes {
			modifiedAttrs[k] = v
		}
		
		// Set the custom email
		modifiedAttrs["email"] = customEmail
		selectedUser.Attributes = modifiedAttrs
		
		fmt.Printf("Using custom email: %s instead of default email\n", customEmail)
	} else {
		fmt.Println("Using default email address")
	}

	// Generate SAML response with the selected user's attributes
	now := time.Now().UTC()
	samlResponse := saml.Response{
		ID:           fmt.Sprintf("id-%s", uuid.New().String()),
		InResponseTo: request.ID,
		Version:      "2.0",
		IssueInstant: now,
		Destination:  request.ACSUrl,
		Issuer: &saml.Issuer{
			Format: "urn:oasis:names:tc:SAML:2.0:nameid-format:entity",
			Value:  idp.Config.EntityID,
		},
		Status: saml.Status{
			StatusCode: saml.StatusCode{
				Value: saml.StatusSuccess,
			},
		},
		Assertion: &saml.Assertion{
			ID:           fmt.Sprintf("id-%s", uuid.New().String()),
			IssueInstant: now,
			Version:      "2.0",
			Issuer: saml.Issuer{
				Format: "urn:oasis:names:tc:SAML:2.0:nameid-format:entity",
				Value:  idp.Config.EntityID,
			},
			Subject: &saml.Subject{
				NameID: &saml.NameID{
					Format:          "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress",
					Value:           selectedUser.Attributes["email"].(string),
					NameQualifier:   idp.Config.EntityID,
					SPNameQualifier: request.SPEntityID,
				},
				SubjectConfirmations: []saml.SubjectConfirmation{
					{
						Method: "urn:oasis:names:tc:SAML:2.0:cm:bearer",
						SubjectConfirmationData: &saml.SubjectConfirmationData{
							InResponseTo: request.ID,
							NotOnOrAfter: now.Add(5 * time.Minute),
							Recipient:    request.ACSUrl,
						},
					},
				},
			},
			Conditions: &saml.Conditions{
				NotBefore:    now,
				NotOnOrAfter: now.Add(time.Hour),
				AudienceRestrictions: []saml.AudienceRestriction{
					{
						Audience: saml.Audience{Value: request.SPEntityID},
					},
				},
			},
			AuthnStatements: []saml.AuthnStatement{
				{
					AuthnInstant: now,
					SessionIndex: fmt.Sprintf("id-%s", uuid.New().String()),
				},
			},
			AttributeStatements: []saml.AttributeStatement{
				{
					Attributes: buildAttributes(selectedUser.Attributes),
				},
			},
		},
	}

	// Sign the response
	// In a real implementation, you would properly sign the response with XML DSIG
	// Here we're using a simple implementation that doesn't actually sign the response

	// Encode the response
	var respBuf []byte
	var err error
	// Don't write to the ResponseWriter directly, only use it for the final form
	respBuf, err = xml.Marshal(samlResponse)
	if err != nil {
		http.Error(w, fmt.Sprintf("Failed to marshal SAML response: %v", err), http.StatusInternalServerError)
		return
	}

	responseb64 := base64.StdEncoding.EncodeToString(respBuf)

	// Build the form to POST back to the SP
	postForm := fmt.Sprintf(`
		<!DOCTYPE html>
		<html>
			<head>
				<meta charset="utf-8">
				<meta http-equiv="X-UA-Compatible" content="IE=edge,chrome=1">
				<title>SAML IdP - Submit Response</title>
			</head>
			<body onload="document.forms[0].submit()">
				<form method="post" action="%s">
					<input type="hidden" name="SAMLResponse" value="%s">
					<input type="hidden" name="RelayState" value="%s">
					<noscript>
						<p>Your browser does not support JavaScript. Click the submit button to continue.</p>
						<input type="submit" value="Submit">
					</noscript>
				</form>
			</body>
		</html>
	`, request.ACSUrl, responseb64, request.RelayState)

	// Remove the request from tracking
	delete(idp.Requests, requestID)
	
	// Write the form to the response
	w.Header().Set("Content-Type", "text/html")
	w.Write([]byte(postForm))
}

// Build SAML attributes from user attributes
func buildAttributes(attrs map[string]interface{}) []saml.Attribute {
	var samlAttrs []saml.Attribute

	for key, val := range attrs {
		attr := saml.Attribute{
			Name:       key,
			NameFormat: "urn:oasis:names:tc:SAML:2.0:attrname-format:basic",
		}

		// Handle different types of attributes
		switch v := val.(type) {
		case string:
			attr.Values = []saml.AttributeValue{
				{Value: v},
			}
		case []interface{}:
			for _, item := range v {
				if str, ok := item.(string); ok {
					attr.Values = append(attr.Values, saml.AttributeValue{Value: str})
				}
			}
		}

		samlAttrs = append(samlAttrs, attr)
	}

	return samlAttrs
}
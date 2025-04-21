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
        }
    </style>
</head>
<body>
    <div class="container">
        <h1>SAML Identity Provider</h1>
        <p>Available users:</p>
        <ul>
            {{range .Users}}
                <li><strong>{{.Username}}</strong></li>
            {{end}}
        </ul>
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
            
            // When a user option is clicked, select its radio button
            userOptions.forEach(option => {
                option.addEventListener('click', function() {
                    const radio = this.querySelector('input[type="radio"]');
                    radio.checked = true;
                    
                    // Highlight the selected option
                    userOptions.forEach(opt => opt.classList.remove('selected'));
                    this.classList.add('selected');
                    
                    // Get the user's default email
                    const userEmail = this.querySelector('input[type="hidden"]').value;
                    
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
        
        {{if .ACSUrl}}
        <div style="background-color: #f8f9fa; border: 1px solid #e9ecef; border-radius: 4px; padding: 10px; margin-bottom: 20px;">
            <p style="margin: 0;"><strong>After login, you will be redirected to:</strong></p>
            <code style="display: block; word-break: break-all; padding: 8px; background-color: #e9ecef; border-radius: 4px; margin-top: 5px;">{{.ACSUrl}}</code>
        </div>
        {{end}}
        
        <form method="post" action="/login">
            <input type="hidden" name="request_id" value="{{.RequestID}}">
            <input type="hidden" name="relay_state" value="{{.RelayState}}">
            <!-- Fallback in case session is lost -->
            <input type="hidden" name="acs_url" value="{{.ACSUrl}}">
            
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
	idp.Router.GET("/", idp.handleHome)
	idp.Router.GET(idp.Config.MetadataPath, idp.handleMetadata)
	idp.Router.GET(idp.Config.SSOServicePath, idp.handleSAMLRequest)
	idp.Router.POST(idp.Config.SSOServicePath, idp.handleSAMLRequest)
	idp.Router.POST("/login", idp.handleLogin)
}

// Home page handler
func (idp *SAMLIdP) handleHome(w http.ResponseWriter, r *http.Request, _ httprouter.Params) {
	homeTmpl.Execute(w, map[string]interface{}{
		"Users": idp.Config.Users,
	})
}

// Handle metadata requests
func (idp *SAMLIdP) handleMetadata(w http.ResponseWriter, r *http.Request, _ httprouter.Params) {
	baseURL, err := url.Parse(idp.Config.BaseURL)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	ssoURL, err := url.Parse(idp.Config.SSOServicePath)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	ssoURL = baseURL.ResolveReference(ssoURL)

	metadata := saml.EntityDescriptor{
		EntityID:      idp.Config.EntityID,
		ValidUntil:    time.Now().Add(time.Hour * 24 * 7), // 1 week valid
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
							},
						},
					},
					NameIDFormats: []saml.NameIDFormat{
						saml.NameIDFormat("urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress"),
						saml.NameIDFormat("urn:oasis:names:tc:SAML:2.0:nameid-format:transient"),
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
	session, err := idp.SessionStore.Get(r, "saml-session")
	if err != nil {
		fmt.Println("Error getting session for storing request ID:", err)
		// Will continue without session, using form values as fallback
	} else {
		session.Values["saml_request_id"] = request.ID
		fmt.Println("Storing request ID in session:", request.ID)
		err = session.Save(r, w)
		if err != nil {
			fmt.Println("Failed to save session:", err)
			// Continue anyway, we'll use form values as fallback
		} else {
			fmt.Println("Session saved successfully with request ID:", request.ID)
		}
	}

	// Render login form
	err = loginTmpl.Execute(w, map[string]interface{}{
		"RequestID":  request.ID,
		"Users":      idp.Config.Users,
		"RelayState": relayState,
		"ACSUrl":     request.ACSUrl,
	})
	if err != nil {
		http.Error(w, "Failed to render login form", http.StatusInternalServerError)
		return
	}
}

// Handle login form submission and generate SAML response
func (idp *SAMLIdP) handleLogin(w http.ResponseWriter, r *http.Request, _ httprouter.Params) {
	if err := r.ParseForm(); err != nil {
		http.Error(w, "Failed to parse form", http.StatusBadRequest)
		return
	}

	// Try to get the request ID from the session first
	var requestID string
	var request *SAMLRequest
	var ok bool
	var err error
	
	// First try the session
	session, err := idp.SessionStore.Get(r, "saml-session")
	if err != nil {
		fmt.Println("Failed to get session:", err)
		// We'll try form values as fallback
	} else {
		// Try to get request ID from session
		sessionRequestID, sessionOk := session.Values["saml_request_id"].(string)
		if sessionOk && sessionRequestID != "" {
			fmt.Println("Found request ID in session:", sessionRequestID)
			requestID = sessionRequestID
			
			// Look for the request in our map
			request, ok = idp.Requests[requestID]
			if ok {
				fmt.Println("Found request in map with ACS URL:", request.ACSUrl)
			} else {
				fmt.Println("Request ID from session not found in Requests map")
			}
		} else {
			fmt.Println("No request ID in session")
		}
	}
	
	// If we couldn't get the request from the session, try the form values
	if request == nil {
		formRequestID := r.FormValue("request_id")
		if formRequestID != "" {
			fmt.Println("Using request ID from form:", formRequestID)
			requestID = formRequestID
			
			// Try to get the request from our map
			request, ok = idp.Requests[requestID]
			if !ok {
				// Last resort - create a request from form values
				formAcsURL := r.FormValue("acs_url")
				formRelayState := r.FormValue("relay_state")
				
				if formAcsURL != "" {
					fmt.Println("Creating request from form values, ACS URL:", formAcsURL)
					// Create a request with form values
					request = &SAMLRequest{
						ID:         requestID,
						ACSUrl:     formAcsURL,
						RelayState: formRelayState,
						Created:    time.Now(),
					}
					// Store it for potential future use
					idp.Requests[requestID] = request
				} else {
					http.Error(w, "Missing request information", http.StatusBadRequest)
					return
				}
			}
		} else {
			http.Error(w, "No request ID provided", http.StatusBadRequest)
			return
		}
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
	notOnOrAfter := now.Add(time.Minute * 5)
	sessionNotOnOrAfter := now.Add(time.Hour * 8)
	
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
	}
	
	// Create and populate assertion
	assertion := saml.Assertion{
		ID:           fmt.Sprintf("id-%s", uuid.New().String()),
		IssueInstant: now,
		Issuer: saml.Issuer{
			Format: "urn:oasis:names:tc:SAML:2.0:nameid-format:entity",
			Value:  idp.Config.EntityID,
		},
		Subject: &saml.Subject{
			NameID: &saml.NameID{
				Format:          "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress",
				Value:           selectedUser.Attributes["email"].(string),
				SPNameQualifier: request.SPEntityID,
			},
			SubjectConfirmations: []saml.SubjectConfirmation{
				{
					Method: "urn:oasis:names:tc:SAML:2.0:cm:bearer",
					SubjectConfirmationData: &saml.SubjectConfirmationData{
						InResponseTo: request.ID,
						NotOnOrAfter: notOnOrAfter,
						Recipient:    request.ACSUrl,
					},
				},
			},
		},
		Conditions: &saml.Conditions{
			NotBefore:    now,
			NotOnOrAfter: notOnOrAfter,
			AudienceRestrictions: []saml.AudienceRestriction{
				{
					Audience: saml.Audience{Value: request.SPEntityID},
				},
			},
		},
		AuthnStatements: []saml.AuthnStatement{
			{
				AuthnInstant:        now,
				SessionIndex:        fmt.Sprintf("id-%s", uuid.New().String()),
				SessionNotOnOrAfter: &sessionNotOnOrAfter,
				AuthnContext: saml.AuthnContext{
					AuthnContextClassRef: &saml.AuthnContextClassRef{
						Value: "urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport",
					},
				},
			},
		},
		AttributeStatements: []saml.AttributeStatement{
			{
				Attributes: buildSAMLAttributes(selectedUser.Attributes),
			},
		},
	}

	// Sign the assertion
	assertionXML, err := xml.Marshal(assertion)
	if err != nil {
		http.Error(w, "Failed to marshal assertion", http.StatusInternalServerError)
		return
	}

	// Sign the assertion XML
	signedAssertionXML, err := samlutils.SignXML(assertionXML, idp.Certificate, idp.PrivateKey)
	if err != nil {
		http.Error(w, "Failed to sign assertion", http.StatusInternalServerError)
		return
	}

	// Parse signed assertion back into a struct
	var signedAssertion saml.Assertion
	if err := xml.Unmarshal(signedAssertionXML, &signedAssertion); err != nil {
		http.Error(w, "Failed to unmarshal signed assertion", http.StatusInternalServerError)
		return
	}

	// Add the signed assertion to the response
	samlResponse.Assertion = &signedAssertion

	// Encode the response for sending back
	buffer, err := xml.Marshal(samlResponse)
	if err != nil {
		http.Error(w, "Failed to marshal SAML response", http.StatusInternalServerError)
		return
	}

	// Base64 encode the response
	encodedResponse := base64.StdEncoding.EncodeToString(buffer)

	// Create auto-submit form to send the response back to the SP
	autoSubmitTmpl := `
	<!DOCTYPE html>
	<html>
	<head>
		<meta charset="UTF-8">
		<title>Redirecting...</title>
	</head>
	<body onload="document.forms[0].submit()">
		<noscript>
			<p>Your browser has JavaScript disabled. Please click the Continue button to proceed.</p>
		</noscript>
		<form method="post" action="%s">
			<input type="hidden" name="SAMLResponse" value="%s" />
			<input type="hidden" name="RelayState" value="%s" />
			<input type="submit" value="Continue" />
		</form>
	</body>
	</html>
	`

	w.Write([]byte(fmt.Sprintf(autoSubmitTmpl, request.ACSUrl, encodedResponse, request.RelayState)))
}

// Helper function to build SAML attributes from a map
func buildSAMLAttributes(attributes map[string]interface{}) []saml.Attribute {
	var samlAttributes []saml.Attribute
	
	for key, value := range attributes {
		var attributeValues []saml.AttributeValue
		
		// Handle different types of attribute values
		switch v := value.(type) {
		case string:
			attributeValues = append(attributeValues, saml.AttributeValue{Value: v})
		case []interface{}:
			// Handle arrays (like roles)
			for _, item := range v {
				if strItem, ok := item.(string); ok {
					attributeValues = append(attributeValues, saml.AttributeValue{Value: strItem})
				}
			}
		default:
			// Convert other types to string
			attributeValues = append(attributeValues, saml.AttributeValue{Value: fmt.Sprintf("%v", v)})
		}
		
		samlAttributes = append(samlAttributes, saml.Attribute{
			Name:       key,
			NameFormat: "urn:oasis:names:tc:SAML:2.0:attrname-format:basic",
			Values:     attributeValues,
		})
	}
	
	return samlAttributes
}
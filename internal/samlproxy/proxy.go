package samlproxy

import (
	"crypto/rsa"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"encoding/xml"
	"errors"
	"fmt"
	"log"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/beevik/etree"
	"github.com/crewjam/saml"
	"github.com/crewjam/saml/xmlenc"
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
	IdentityProvider    *IdentityProviderConfig  // The IdP selected for this request
	RequestID           string
	OriginalRequestID   string                   // Original SP request ID (for InResponseTo)
	ACSUrl              string
	CreatedAt           time.Time                // When the request was created
}

// ProxyConfig represents the configuration for the SAML proxy
type ProxyConfig struct {
	ListenAddr       string                  `yaml:"listen_addr"`
	BaseURL          string                  `yaml:"base_url"`
	CertFile         string                  `yaml:"cert_file"`
	KeyFile          string                  `yaml:"key_file"`
	SessionSecret    string                  `yaml:"session_secret"`
	ProxyEntityID    string                  `yaml:"proxy_entity_id"`
	ServiceProviders []ServiceProviderConfig `yaml:"service_providers"`
	IdentityProviders []IdentityProviderConfig `yaml:"identity_providers"`
	Debug            bool                    `yaml:"debug"`
}

// ServiceProviderConfig represents configuration for a service provider
type ServiceProviderConfig struct {
	Name           string            `yaml:"name"`
	EntityID       string            `yaml:"entity_id"`
	ACSUrl         string            `yaml:"acs_url"`
	MetadataXMLUrl string            `yaml:"metadata_xml_url"`
	AttributeMap   map[string]string `yaml:"attribute_map"`
	DefaultIdP     string            `yaml:"default_idp"`     // ID of the default IdP to use, or empty for prompt
}

// IdentityProviderConfig represents configuration for an identity provider
type IdentityProviderConfig struct {
	ID             string `yaml:"id"`              // Unique identifier for this IdP
	Name           string `yaml:"name"`            // Display name for the IdP
	Description    string `yaml:"description"`     // Description to show in the selection UI
	LogoURL        string `yaml:"logo_url"`        // Optional logo URL for the IdP
	MetadataURL    string `yaml:"metadata_url"`    // URL to fetch IdP metadata
	EntityID       string `yaml:"entity_id"`       // Entity ID of the IdP
	SSOURL         string `yaml:"sso_url"`         // Single Sign-On URL of the IdP
	DefaultIdP     bool   `yaml:"default_idp"`     // Whether this is the default IdP
}

// NewSAMLProxy creates a new SAML proxy from the given configuration file
// CSS for the IdP selection page
const idpSelectionCSS = `
body {
    font-family: Arial, sans-serif;
    line-height: 1.6;
    margin: 0;
    padding: 0;
    background-color: #f5f5f5;
    display: flex;
    justify-content: center;
    align-items: center;
    min-height: 100vh;
}
.container {
    background-color: #fff;
    padding: 40px;
    border-radius: 8px;
    box-shadow: 0 2px 4px rgba(0, 0, 0, 0.1);
    text-align: center;
    max-width: 500px;
    width: 100%;
}
h1, h2, h3 {
    color: #333;
	margin-bottom: -20px;
}
h1 {
    text-align: center;
    margin-bottom: 20px;
}
.idp-list {
    display: flex;
    flex-direction: column;
    gap: 20px;
    margin-top: 30px;
}
.idp-card {
    display: flex;
    align-items: center;
    border: 1px solid #e0e0e0;
    border-radius: 8px;
    padding: 20px;
    background-color: #fff;
    transition: all 0.2s;
    cursor: pointer;
    text-decoration: none;
    color: inherit;
}
.idp-card:hover {
    border-color: #007bff;
    box-shadow: 0 4px 8px rgba(0, 0, 0, 0.1);
}
.idp-logo {
    width: 60px;
    height: 60px;
    margin-right: 20px;
    border-radius: 8px;
    background-color: #f8f9fa;
    display: flex;
    align-items: center;
    justify-content: center;
    font-size: 24px;
    font-weight: bold;
    color: #007bff;
}
.idp-info {
    flex: 1;
    text-align: left;
}
.idp-name {
    font-size: 18px;
    font-weight: bold;
    color: #333;
    margin-bottom: 5px;
}
.idp-description {
    font-size: 14px;
    color: #666;
}
.status-link {
    color: #007bff;
    text-decoration: none;
    font-size: 14px;
}
.status-link:hover {
    text-decoration: underline;
}
`

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

	// Validate that we have at least one identity provider
	if len(config.IdentityProviders) == 0 {
		return nil, fmt.Errorf("no identity providers configured")
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
	// Always enable debug mode to diagnose issues
	sp.Config.Debug = true

	if sp.Config.Debug {
		log.Printf("Request: %s %s", r.Method, r.URL.Path)
	}

	switch r.URL.Path {
	case "/metadata":
		sp.handleMetadata(w, r)
	case "/status":
		sp.handleStatus(w, r)
	case "/saml/sso":
		sp.handleSAMLRequest(w, r)
	case "/saml/acs":
		sp.handleSAMLResponse(w, r)
	case "/saml/select-idp":
		sp.handleIdPSelection(w, r)
	case "/saml/complete-request":
		sp.handleCompleteRequest(w, r)
	case "/assets/css/style.css":
		sp.serveStaticCSS(w, r)
	case "/api/save-sp-config":
		sp.handleSaveServiceProviderConfig(w, r)
	default:
		http.NotFound(w, r)
	}
}

// Serve the CSS for the IdP selection page
func (sp *SAMLProxy) serveStaticCSS(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/css")
	w.Write([]byte(idpSelectionCSS))
}

// SaveConfig saves the current configuration to the specified file
func (sp *SAMLProxy) SaveConfig(configFile string) error {
	// Marshal the config to YAML
	configData, err := yaml.Marshal(sp.Config)
	if err != nil {
		return fmt.Errorf("could not marshal config to YAML: %v", err)
	}

	// Create a backup of the existing file if it exists
	if _, err := os.Stat(configFile); err == nil {
		// File exists, create a backup
		backupFile := configFile + ".bak"

		// Read the existing file
		existingData, err := os.ReadFile(configFile)
		if err != nil {
			return fmt.Errorf("could not read existing config file for backup: %v", err)
		}

		// Write the backup file
		if err := os.WriteFile(backupFile, existingData, 0644); err != nil {
			return fmt.Errorf("could not create backup config file: %v", err)
		}

		fmt.Printf("Created backup of config file at %s\n", backupFile)
	}

	// Write to the file
	if err := os.WriteFile(configFile, configData, 0644); err != nil {
		return fmt.Errorf("could not write config file: %v", err)
	}

	return nil
}

// Handle saving the Service Provider configuration
func (sp *SAMLProxy) handleSaveServiceProviderConfig(w http.ResponseWriter, r *http.Request) {
	// Only allow POST requests
	if r.Method != "POST" {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusMethodNotAllowed)
		w.Write([]byte(`{"success": false, "message": "Method not allowed"}`))
		return
	}

	// Parse the form data
	if err := r.ParseForm(); err != nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		w.Write([]byte(`{"success": false, "message": "Error parsing form data"}`))
		return
	}

	// Get the service provider ID and the default IdP ID
	spID := r.FormValue("sp_id")
	defaultIdPID := r.FormValue("default_idp_id")

	// Always show this debug info for important operations
	fmt.Printf("\n==== SERVICE PROVIDER CONFIG UPDATE ====\n")
	fmt.Printf("Received SP config change: SP Entity ID=%s, Default IdP ID=%s\n", spID, defaultIdPID)

	// Show all SPs for comparison
	fmt.Println("Currently configured Service Providers:")
	for i, provider := range sp.Config.ServiceProviders {
		fmt.Printf("[%d] EntityID: %s, Name: %s, DefaultIdP: %s\n",
			i, provider.EntityID, provider.Name, provider.DefaultIdP)
	}

	// Show all IdPs for comparison
	fmt.Println("Currently configured Identity Providers:")
	for i, idp := range sp.Config.IdentityProviders {
		fmt.Printf("[%d] ID: %s, Name: %s, EntityID: %s\n",
			i, idp.ID, idp.Name, idp.EntityID)
	}

	// Print all service provider EntityIDs for debugging
	if sp.Config.Debug {
		fmt.Println("Available Service Provider EntityIDs:")
		for i, provider := range sp.Config.ServiceProviders {
			fmt.Printf("[%d] %s\n", i, provider.EntityID)
		}
	}

	// URL-decode the service provider ID (in case it was encoded in the form data)
	decodedSpID, err := url.QueryUnescape(spID)
	if err != nil {
		if sp.Config.Debug {
			fmt.Printf("Error decoding SP ID '%s': %v\n", spID, err)
		}
		// Continue with the original ID if decoding fails
		decodedSpID = spID
	} else if decodedSpID != spID {
		if sp.Config.Debug {
			fmt.Printf("Decoded SP ID: '%s' to '%s'\n", spID, decodedSpID)
		}
		spID = decodedSpID
	}

	// Additional debug
	if sp.Config.Debug {
		fmt.Printf("Looking for Service Provider with Entity ID: '%s'\n", spID)
	}

	// Validate the service provider ID
	var spIndex = -1
	for i, provider := range sp.Config.ServiceProviders {
		if provider.EntityID == spID {
			spIndex = i
			break
		}
	}

	if spIndex < 0 {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		errMsg := fmt.Sprintf("Invalid Service Provider ID: '%s'", spID)
		jsonResp := fmt.Sprintf(`{"success": false, "message": "%s"}`, strings.ReplaceAll(errMsg, `"`, `\"`))
		w.Write([]byte(jsonResp))
		return
	}

	// Validate the IdP ID or handle special values
	idpValid := false
	if defaultIdPID == "prompt" {
		idpValid = true
		// Empty string means prompt (no default)
		defaultIdPID = ""
	} else {
		for _, idp := range sp.Config.IdentityProviders {
			if idp.ID == defaultIdPID {
				idpValid = true
				break
			}
		}
	}

	if !idpValid && defaultIdPID != "" {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		w.Write([]byte(`{"success": false, "message": "Invalid Identity Provider ID"}`))
		return
	}

	// Update the service provider's default IdP
	fmt.Printf("Updating service provider '%s' default IdP from '%s' to '%s'\n",
		sp.Config.ServiceProviders[spIndex].Name,
		sp.Config.ServiceProviders[spIndex].DefaultIdP,
		defaultIdPID)

	sp.Config.ServiceProviders[spIndex].DefaultIdP = defaultIdPID

	// Log the change
	if defaultIdPID == "" {
		fmt.Printf("Updated Service Provider '%s' to always prompt for IdP selection\n",
			sp.Config.ServiceProviders[spIndex].Name)
	} else {
		fmt.Printf("Updated Service Provider '%s' to use default IdP: '%s'\n",
			sp.Config.ServiceProviders[spIndex].Name,
			defaultIdPID)
	}

	// Try to save the configuration to disk
	// We'll use the path from which the config was loaded initially
	// Note: We get this from the arguments passed to the program
	var configFile string
	if len(os.Args) > 1 {
		configFile = os.Args[1]
	}

	if configFile != "" {
		if err := sp.SaveConfig(configFile); err != nil {
			fmt.Printf("Error saving configuration: %v\n", err)
			// Create a sanitized error message for JSON
			errMessage := strings.ReplaceAll(err.Error(), `"`, `\"`)

			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusInternalServerError)
			w.Write([]byte(fmt.Sprintf(`{"success": false, "message": "Error saving configuration: %s"}`, errMessage)))
			return
		}

		fmt.Printf("Configuration saved to %s\n", configFile)
	} else {
		fmt.Printf("Warning: Config file path not available. Changes will persist in memory but will be lost on restart.\n")
		fmt.Printf("If you want to save configurations permanently, please restart the proxy with a config file path.\n")
	}

	// Even if we can't save to disk, the changes are still in memory
	fmt.Printf("Configuration updated for service provider '%s'\n", sp.Config.ServiceProviders[spIndex].Name)

	// Return a success response
	w.Header().Set("Content-Type", "application/json")
	w.Write([]byte(`{"success": true, "message": "Configuration updated successfully"}`))
}

// Handle status page to display current proxy configuration
func (sp *SAMLProxy) handleStatus(w http.ResponseWriter, r *http.Request) {
	// Styles for the status page
	const statusCSS = `
	body {
		font-family: Arial, sans-serif;
		line-height: 1.6;
		margin: 0;
		padding: 20px;
		background-color: #f5f5f5;
	}
	.container {
		max-width: 1200px;
		margin: 0 auto;
		background-color: #fff;
		padding: 20px;
		border-radius: 8px;
		box-shadow: 0 2px 4px rgba(0, 0, 0, 0.1);
	}
	h1, h2, h3 {
		color: #333;
	}
	h1 {
		text-align: center;
		margin-bottom: 20px;
	}
	h2 {
		border-bottom: 1px solid #eee;
		padding-bottom: 10px;
		margin-top: 30px;
	}
	table {
		width: 100%;
		border-collapse: collapse;
		margin-bottom: 20px;
	}
	th, td {
		padding: 10px;
		border: 1px solid #ddd;
		text-align: left;
	}
	th {
		background-color: #f8f9fa;
		font-weight: bold;
	}
	.param-value {
		font-family: monospace;
		word-break: break-all;
	}
	.badge {
		display: inline-block;
		padding: 4px 8px;
		border-radius: 4px;
		font-size: 12px;
		font-weight: bold;
		margin-left: 10px;
		background-color: #28a745;
		color: white;
	}
	pre {
		background-color: #f8f9fa;
		padding: 15px;
		border-radius: 5px;
		overflow-x: auto;
		font-family: monospace;
		font-size: 14px;
		border: 1px solid #e9ecef;
	}
	/* Configuration controls */
	.idp-select {
		padding: 8px;
		border-radius: 4px;
		border: 1px solid #ddd;
		background-color: #fff;
		min-width: 200px;
	}
	.save-button {
		margin-left: 8px;
		padding: 8px 12px;
		background-color: #007bff;
		color: white;
		border: none;
		border-radius: 4px;
		cursor: pointer;
	}
	.save-button:hover {
		background-color: #0069d9;
	}
	.save-status {
		margin-left: 10px;
		font-size: 14px;
	}
	.success {
		color: #28a745;
	}
	.error {
		color: #dc3545;
	}
	`

	html := fmt.Sprintf(`<!DOCTYPE html>
	<html>
	<head>
		<title>SAML Proxy Status</title>
		<meta name="viewport" content="width=device-width, initial-scale=1.0">
		<style>%s</style>
	</head>
	<body>
		<div class="container">
			<h1>SAML Proxy Status</h1>
			
			<h2>General Configuration</h2>
			<table>
				<tr>
					<th>Proxy Entity ID</th>
					<td class="param-value">%s</td>
				</tr>
				<tr>
					<th>Base URL</th>
					<td class="param-value">%s</td>
				</tr>
				<tr>
					<th>Listen Address</th>
					<td class="param-value">%s</td>
				</tr>
				<tr>
					<th>Debug Mode</th>
					<td class="param-value">%t</td>
				</tr>
				<tr>
					<th>Active Requests</th>
					<td class="param-value">%d</td>
				</tr>
			</table>
			
			<h2>Identity Providers (%d configured)</h2>
			<table>
				<thead>
					<tr>
						<th>ID</th>
						<th>Name</th>
						<th>Entity ID</th>
						<th>SSO URL</th>
						<th>Metadata URL</th>
						<th>Default</th>
					</tr>
				</thead>
				<tbody>`,
		statusCSS,
		sp.Config.ProxyEntityID,
		sp.Config.BaseURL,
		sp.Config.ListenAddr,
		sp.Config.Debug,
		len(sp.RequestTracker),
		len(sp.Config.IdentityProviders))

	// Add rows for each IdP
	for _, idp := range sp.Config.IdentityProviders {
		defaultBadge := ""
		if idp.DefaultIdP {
			defaultBadge = "✓"
		}

		html += fmt.Sprintf(`
					<tr>
						<td class="param-value">%s</td>
						<td>%s</td>
						<td class="param-value">%s</td>
						<td class="param-value">%s</td>
						<td class="param-value">%s</td>
						<td class="param-value">%s</td>
					</tr>`,
			idp.ID,
			idp.Name,
			idp.EntityID,
			idp.SSOURL,
			idp.MetadataURL,
			defaultBadge)
	}

	// Close IdP table and add SP table
	html += fmt.Sprintf(`
				</tbody>
			</table>
			
			<h2>Service Providers (%d configured)</h2>
			<table>
				<thead>
					<tr>
						<th>Name</th>
						<th>Entity ID</th>
						<th>ACS URL</th>
						<th>Attributes</th>
						<th>Default IdP</th>
					</tr>
				</thead>
				<tbody>`,
		len(sp.Config.ServiceProviders))

	// Add rows for each SP
	for _, provider := range sp.Config.ServiceProviders {
		// Format the attribute map
		attrMap := ""
		for spAttr, idpAttr := range provider.AttributeMap {
			attrMap += fmt.Sprintf("%s &rarr; %s<br>", idpAttr, spAttr)
		}

		// Create a URL-safe ID for the HTML elements
		safeID := strings.ReplaceAll(provider.EntityID, ":", "_")
		safeID = strings.ReplaceAll(safeID, "/", "_")
		safeID = strings.ReplaceAll(safeID, ".", "_")

		// Create dropdown for IdP selection - store both IDs for reference
		idpDropdown := fmt.Sprintf(`<select id="idp-select-%s" class="idp-select" data-sp-id="%s" data-safe-id="%s">
			<option value="prompt"`, safeID, provider.EntityID, safeID)

		// Mark 'prompt' as selected if no default IdP is set
		if provider.DefaultIdP == "" {
			idpDropdown += ` selected`
		}

		idpDropdown += `>Always prompt user</option>`

		// Add options for each Identity Provider
		for _, idp := range sp.Config.IdentityProviders {
			// Debug the IdP IDs being compared
			if sp.Config.Debug && provider.DefaultIdP != "" {
				fmt.Printf("Comparing IdP IDs - Provider Default: '%s', Current IdP: '%s', Match: %v\n",
					provider.DefaultIdP, idp.ID, provider.DefaultIdP == idp.ID)
			}

			idpDropdown += `<option value="` + idp.ID + `"`

			// Mark the current default as selected
			if provider.DefaultIdP == idp.ID {
				idpDropdown += ` selected`
			}

			// Add a "default" indicator if this is the global default IdP
			defaultMarker := ""
			if idp.DefaultIdP {
				defaultMarker = " (Global Default)"
			}

			idpDropdown += `>` + idp.Name + defaultMarker + `</option>`
		}

		idpDropdown += fmt.Sprintf(`</select>
						<button class="save-button" data-sp-id="%s" data-safe-id="%s">Save</button>
						<span class="save-status" id="save-status-%s"></span>`,
						provider.EntityID, safeID, safeID)

		html += fmt.Sprintf(`
					<tr>
						<td>%s</td>
						<td class="param-value">%s</td>
						<td class="param-value">%s</td>
						<td class="param-value">%s</td>
						<td class="param-value">%s</td>
					</tr>`,
			provider.Name,
			provider.EntityID,
			provider.ACSUrl,
			attrMap,
			idpDropdown)
	}

	// Close the document
	html += `
				</tbody>
			</table>
			
			<h2>Certificate Information</h2>
			<table>
				<tr>
					<th>Subject</th>
					<td class="param-value">`

	// Add certificate information if available
	if sp.Certificate != nil {
		html += sp.Certificate.Subject.CommonName
	} else {
		html += "No certificate loaded"
	}

	html += `</td>
				</tr>
				<tr>
					<th>Issuer</th>
					<td class="param-value">`

	if sp.Certificate != nil {
		html += sp.Certificate.Issuer.CommonName
	} else {
		html += "N/A"
	}

	html += `</td>
				</tr>
				<tr>
					<th>Serial Number</th>
					<td class="param-value">`

	if sp.Certificate != nil {
		html += sp.Certificate.SerialNumber.String()
	} else {
		html += "N/A"
	}

	html += `</td>
				</tr>
				<tr>
					<th>Not Before</th>
					<td class="param-value">`

	if sp.Certificate != nil {
		html += sp.Certificate.NotBefore.Format(time.RFC3339)
	} else {
		html += "N/A"
	}

	html += `</td>
				</tr>
				<tr>
					<th>Not After</th>
					<td class="param-value">`

	if sp.Certificate != nil {
		html += sp.Certificate.NotAfter.Format(time.RFC3339)
	} else {
		html += "N/A"
	}

	html += `</td>
				</tr>
			</table>
			
			<h2>Metadata Endpoints</h2>
			<table>
				<tr>
					<th>Metadata URL</th>
					<td class="param-value"><a href="/metadata" target="_blank">`

	html += fmt.Sprintf("%s/metadata", sp.Config.BaseURL)

	html += `</a></td>
				</tr>
			</table>
		</div>

		<script>
		// Add event listeners to all save buttons
		document.addEventListener('DOMContentLoaded', function() {
			// Get all save buttons
			const saveButtons = document.querySelectorAll('.save-button');
			
			// Add click event listener to each button
			saveButtons.forEach(button => {
				button.addEventListener('click', function() {
					// Get the SP ID from the button's data attribute
					const spId = this.getAttribute("data-sp-id"); const safeId = this.getAttribute("data-safe-id");
					
					// Get the selected IdP ID from the dropdown
					const selectElement = document.getElementById("idp-select-" + safeId);
					const idpId = selectElement.value;
					
					// Get the status element
					const statusElement = document.getElementById("save-status-" + safeId);
					statusElement.textContent = 'Saving...';
					statusElement.className = 'save-status';
					
					// Create the form data as URLSearchParams (simpler than FormData)
					const params = new URLSearchParams();
					params.append('sp_id', spId);
					params.append('default_idp_id', idpId);
					
					// Log what we're sending
					console.log('Saving configuration:', {
						sp_id: spId,
						default_idp_id: idpId
					});
					
					// Send the request
					fetch('/api/save-sp-config', {
						method: 'POST',
						headers: {
							'Content-Type': 'application/x-www-form-urlencoded',
						},
						body: params
					})
					.then(response => {
						console.log('Response status:', response.status);
						if (!response.ok) {
							return response.text().then(text => {
								try {
									// Try to parse as JSON
									const data = JSON.parse(text);
									console.error('Error response data:', data);
									return data;
								} catch (e) {
									// If not JSON, return the raw text
									console.error('Error response text:', text);
									throw new Error("Server error: " + response.status + " - " + text);
								}
							});
						}
						return response.json();
					})
					.then(data => {
						if (data.success) {
							statusElement.textContent = 'Saved!';
							statusElement.className = 'save-status success';
							
							// Clear the success message after 3 seconds
							setTimeout(() => {
								statusElement.textContent = '';
							}, 3000);
						} else {
							statusElement.textContent = '✗ Error: ' + data.message;
							statusElement.className = 'save-status error';
						}
					})
					.catch(error => {
						console.error('Error in fetch operation:', error);
						statusElement.textContent = '✗ Error: ' + error.message;
						statusElement.className = 'save-status error';
					});
				});
			});
		});
		</script>
	</body>
	</html>`

	w.Header().Set("Content-Type", "text/html")
	w.Write([]byte(html))
}

// Generates metadata for the proxy to be used by both Service Providers and Identity Providers
func (sp *SAMLProxy) handleMetadata(w http.ResponseWriter, r *http.Request) {
	authnRequestsSigned := true
	wantAssertionsSigned := true
	wantAuthnRequestsSigned := true

	// Common key descriptor elements for both SP and IdP roles
	keyDescriptors := []saml.KeyDescriptor{
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
	}

	// Common name ID formats for both SP and IdP roles
	nameIDFormats := []saml.NameIDFormat{
		saml.UnspecifiedNameIDFormat,
		saml.EmailAddressNameIDFormat,
		saml.TransientNameIDFormat,
		saml.PersistentNameIDFormat,
	}

	metadata := saml.EntityDescriptor{
		EntityID: sp.Config.ProxyEntityID,

		// As a Service Provider to upstream IdPs
		SPSSODescriptors: []saml.SPSSODescriptor{
			{
				SSODescriptor: saml.SSODescriptor{
					RoleDescriptor: saml.RoleDescriptor{
						ProtocolSupportEnumeration: "urn:oasis:names:tc:SAML:2.0:protocol",
						KeyDescriptors:             keyDescriptors,
					},
					NameIDFormats: nameIDFormats,
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

		// As an Identity Provider to downstream SPs (clients)
		IDPSSODescriptors: []saml.IDPSSODescriptor{
			{
				SSODescriptor: saml.SSODescriptor{
					RoleDescriptor: saml.RoleDescriptor{
						ProtocolSupportEnumeration: "urn:oasis:names:tc:SAML:2.0:protocol",
						KeyDescriptors:             keyDescriptors,
					},
					NameIDFormats: nameIDFormats,
				},
				WantAuthnRequestsSigned: &wantAuthnRequestsSigned,
				SingleSignOnServices: []saml.Endpoint{
					{
						Binding:  saml.HTTPPostBinding,
						Location: fmt.Sprintf("%s/saml/sso", sp.Config.BaseURL),
					},
					{
						Binding:  saml.HTTPRedirectBinding,
						Location: fmt.Sprintf("%s/saml/sso", sp.Config.BaseURL),
					},
				},
				// The SignAssertions field doesn't exist directly in IDPSSODescriptor
				// The proxy will sign assertions in the samlResponse handler
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
// Handler for the IdP selection page
func (sp *SAMLProxy) handleIdPSelection(w http.ResponseWriter, r *http.Request) {
	// Get request ID from query param
	requestID := r.URL.Query().Get("request_id")
	if requestID == "" {
		http.Error(w, "Missing request ID", http.StatusBadRequest)
		return
	}

	// Get the original SAML request from the tracker
	_, exists := sp.RequestTracker[requestID]
	if !exists {
		http.Error(w, "Invalid or expired request ID", http.StatusBadRequest)
		return
	}

	// Render the IdP selection template
	html := `<!DOCTYPE html>
<html>
<head>
    <title>SAML Proxy</title>
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <link rel="stylesheet" href="/assets/css/style.css">
</head>
<body>
    <div class="container">
        <h2>Login with:</h2>
        <div class="idp-list">
`

	// Add each IdP as a card with detailed parameters
	for _, idp := range sp.Config.IdentityProviders {
		// Create a safe ID for HTML elements
		safeID := strings.ReplaceAll(idp.ID, " ", "_")
		safeID = strings.ReplaceAll(safeID, ".", "_")
		safeID = strings.ReplaceAll(safeID, "-", "_")

		// Build IdP card with detailed parameters
		var logoContent string
		if idp.LogoURL != "" {
			logoContent = fmt.Sprintf(`<img src="%s" alt="%s logo" style="max-width: 100%%; max-height: 100%%;">`, idp.LogoURL, idp.Name)
		} else {
			// Use first letter as fallback logo
			logoContent = string(idp.Name[0])
		}
		
		html += fmt.Sprintf(`
            <div>
                <a href="/saml/complete-request?request_id=%s&idp_id=%s" class="idp-card">
                    <div class="idp-logo">
                        %s
                    </div>
                    <div class="idp-info">
                        <div class="idp-name">%s</div>
                        <div class="idp-description">%s</div>
                    </div>
                </a>
            </div>`,
            requestID,
            idp.ID,
            logoContent,
            idp.Name,
            idp.Description)
	}

	html += `
        </div>
	<p><a href="/status" class="status-link">Set defaults</a></p>
    </div>
</body>
</html>`

	w.Header().Set("Content-Type", "text/html")
	w.Write([]byte(html))
}

// Handler to complete the SAML request with the selected IdP
func (sp *SAMLProxy) handleCompleteRequest(w http.ResponseWriter, r *http.Request) {
	// Get request ID and IdP ID from query params
	requestID := r.URL.Query().Get("request_id")
	idpID := r.URL.Query().Get("idp_id")

	if requestID == "" || idpID == "" {
		http.Error(w, "Missing request ID or IdP ID", http.StatusBadRequest)
		return
	}

	// Get the original SAML request from the tracker
	originalRequest, exists := sp.RequestTracker[requestID]
	if !exists {
		http.Error(w, "Invalid or expired request ID", http.StatusBadRequest)
		return
	}

	// Find the selected IdP
	var selectedIdP *IdentityProviderConfig
	for i, idp := range sp.Config.IdentityProviders {
		if idp.ID == idpID {
			selectedIdP = &sp.Config.IdentityProviders[i]
			break
		}
	}

	if selectedIdP == nil {
		http.Error(w, "Invalid IdP ID", http.StatusBadRequest)
		return
	}

	// Update the request with the selected IdP
	originalRequest.IdentityProvider = selectedIdP

	// We need to keep using the same requestID as the key in the RequestTracker
	// so make sure it's stored in the RelayState field
	originalRequest.RelayState = requestID

	// Now forward the request to the selected IdP
	sp.forwardRequestToIdP(w, r, originalRequest)
}

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
	fmt.Printf("\n==== SAML REQUEST RECEIVED ====\n")
	fmt.Printf("AuthnRequest from EntityID: %s\n", authnRequest.Issuer.Value)

	// Show all SPs for comparison
	fmt.Println("Currently configured Service Providers:")
	for i, provider := range sp.Config.ServiceProviders {
		fmt.Printf("[%d] EntityID: %s, Name: %s, DefaultIdP: %s\n",
			i, provider.EntityID, provider.Name, provider.DefaultIdP)
	}

	var serviceProvider *ServiceProviderConfig
	for i, provider := range sp.Config.ServiceProviders {
		if provider.EntityID == authnRequest.Issuer.Value {
			serviceProvider = &sp.Config.ServiceProviders[i]
			fmt.Printf("Found matching SP: %s (DefaultIdP: %s)\n", provider.Name, provider.DefaultIdP)
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
	samlRequest := &SAMLRequest{
		OriginalSAMLRequest: originalSAMLRequest,
		RelayState:          relayState,
		ServiceProvider:     serviceProvider,
		RequestID:           authnRequest.ID,
		OriginalRequestID:   authnRequest.ID, // Store the original ID from the SP
		ACSUrl:              authnRequest.AssertionConsumerServiceURL,
		CreatedAt:           time.Now(),
	}
	sp.RequestTracker[newRequestID] = samlRequest

	// First check if this SP has a specific default IdP configured
	var selectedIdP *IdentityProviderConfig

	// Debug SP configuration
	if sp.Config.Debug {
		fmt.Printf("Checking for SP-specific default IdP for '%s' (EntityID: %s)\n",
			serviceProvider.Name, serviceProvider.EntityID)
		fmt.Printf("SP default IdP setting: '%s'\n", serviceProvider.DefaultIdP)
	}

	if serviceProvider.DefaultIdP != "" {
		// Find the IdP specified as default for this SP
		foundMatch := false
		for i, idp := range sp.Config.IdentityProviders {
			if sp.Config.Debug {
				fmt.Printf("  Checking IdP: %s (ID: %s)\n", idp.Name, idp.ID)
			}

			if idp.ID == serviceProvider.DefaultIdP {
				selectedIdP = &sp.Config.IdentityProviders[i]
				foundMatch = true
				fmt.Printf("Using SP-specific default IdP: %s (%s) for SP: %s\n",
					idp.Name, idp.ID, serviceProvider.Name)
				break
			}
		}

		if !foundMatch && sp.Config.Debug {
			fmt.Printf("WARNING: Could not find configured default IdP with ID: '%s'\n",
				serviceProvider.DefaultIdP)
		}
	}

	// If no SP-specific default was found, fall back to global default
	if selectedIdP == nil {
		for i, idp := range sp.Config.IdentityProviders {
			if idp.DefaultIdP {
				selectedIdP = &sp.Config.IdentityProviders[i]
				if sp.Config.Debug {
					fmt.Printf("Using global default IdP: %s (%s)\n", idp.Name, idp.ID)
				}
				break
			}
		}
	}

	// If we have a selected IdP (from SP-specific default or global default) or only one IdP configured, use it directly
	if selectedIdP != nil || len(sp.Config.IdentityProviders) == 1 {
		// Use selected IdP or the only IdP available if no default is set
		if selectedIdP == nil {
			selectedIdP = &sp.Config.IdentityProviders[0]
			if sp.Config.Debug {
				fmt.Printf("Using the only available IdP: %s (%s)\n", selectedIdP.Name, selectedIdP.ID)
			}
		}

		samlRequest.IdentityProvider = selectedIdP

		// Make sure the relay state is set to the request ID so we can retrieve it later
		samlRequest.RelayState = newRequestID

		sp.forwardRequestToIdP(w, r, samlRequest)
		return
	}

	// If there are multiple IdPs and no default is set, redirect to selection page
	if sp.Config.Debug {
		fmt.Printf("No default IdP found and multiple IdPs configured, redirecting to selection page\n")
		fmt.Printf("Service Provider default IdP setting: '%s'\n", serviceProvider.DefaultIdP)

		for i, idp := range sp.Config.IdentityProviders {
			fmt.Printf("Available IdP #%d: %s (ID: '%s')\n", i, idp.Name, idp.ID)
		}
	}

	redirectURL := fmt.Sprintf("%s/saml/select-idp?request_id=%s", sp.Config.BaseURL, newRequestID)
	http.Redirect(w, r, redirectURL, http.StatusFound)
}

// forwardRequestToIdP forwards the SAML request to the selected Identity Provider
func (sp *SAMLProxy) forwardRequestToIdP(w http.ResponseWriter, r *http.Request, samlRequest *SAMLRequest) {
	if samlRequest.IdentityProvider == nil {
		http.Error(w, "No Identity Provider selected for this request", http.StatusBadRequest)
		return
	}

	// Create a new SAML request to the IdP
	format := "urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified"
	allowCreate := true

	// Use a time slightly in the past to account for clock drift
	// Many IdPs have a 5-minute tolerance window
	issueInstant := time.Now().UTC().Add(-30 * time.Second)

	// Generate a new unique ID for the request to the IdP
	newID := samlutils.GenerateID("id-")

	// Update the stored request ID but preserve the original request ID for the final response
	samlRequest.RequestID = newID
	// originalRequestID is already set and preserved

	newAuthnRequest := saml.AuthnRequest{
		ID:                          newID,
		IssueInstant:                issueInstant,
		Version:                     "2.0",
		Destination:                 samlRequest.IdentityProvider.SSOURL,
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

	// Debug logging
	if sp.Config.Debug {
		fmt.Printf("Sending SAML request to IdP %s:\n", samlRequest.IdentityProvider.Name)
		fmt.Printf("  Original SP Request ID: %s\n", samlRequest.OriginalRequestID)
		fmt.Printf("  Current Request ID for IdP: %s\n", newAuthnRequest.ID)
		fmt.Printf("  IssueInstant: %s\n", newAuthnRequest.IssueInstant.Format(time.RFC3339))
		fmt.Printf("  Destination: %s\n", newAuthnRequest.Destination)
		fmt.Printf("  ACS URL: %s\n", newAuthnRequest.AssertionConsumerServiceURL)
	}

	// Sign the request
	signedRequest, err := sp.signRequest(&newAuthnRequest)
	if err != nil {
		http.Error(w, "Failed to sign SAML request", http.StatusInternalServerError)
		return
	}

	// For debugging, print the first part of the XML
	if sp.Config.Debug && len(signedRequest) > 100 {
		fmt.Printf("Signed request (first 100 chars): %s\n", string(signedRequest[:100]))
	}

	// Encode the request
	encodedRequest := base64.StdEncoding.EncodeToString(signedRequest)

	// Redirect to IdP or render POST form
	if sp.Config.Debug {
		log.Printf("Forwarding request to IdP: %s", samlRequest.IdentityProvider.SSOURL)
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
	`, samlRequest.IdentityProvider.SSOURL, encodedRequest, samlRequest.RelayState)

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

	// Check if the response has an encrypted assertion
	if samlResp.EncryptedAssertion != nil {
		fmt.Println("==== ENCRYPTED ASSERTION DETECTED ====")

		// Log decryption attempt with certificate details
		fmt.Println("Attempting to decrypt assertion using proxy certificate...")

		// Print certificate details for debugging
		if sp.Certificate != nil {
			fmt.Printf("Using certificate: Subject=%s, Issuer=%s\n",
				sp.Certificate.Subject.CommonName,
				sp.Certificate.Issuer.CommonName)
			fmt.Printf("Certificate serial number: %s\n", sp.Certificate.SerialNumber.String())
			certFingerprint := sha256.Sum256(sp.Certificate.Raw)
			fmt.Printf("Certificate SHA-256 fingerprint: %x\n", certFingerprint)
		} else {
			fmt.Println("WARNING: No certificate available!")
		}

		// Try to decrypt the assertion using our private key
		fmt.Println("Starting decryption process...")

		// Dump the XML structure for debugging
		assertionDoc := etree.NewDocument()
		assertionDoc.AddChild(samlResp.EncryptedAssertion)
		assertionXML, _ := assertionDoc.WriteToString()
		fmt.Printf("Encrypted assertion XML structure:\n%s\n", assertionXML)

		// Use the xmlenc.Decrypt function from the crewjam/saml library
		plaintextBytes, err := xmlenc.Decrypt(sp.PrivateKey, samlResp.EncryptedAssertion)
		if err != nil {
			fmt.Printf("Failed to decrypt assertion: %v\n", err)

			// Additional debugging for common encryption issues
			if strings.Contains(err.Error(), "padding") {
				fmt.Println("This appears to be a padding error, which often indicates the wrong private key was used")
			} else if strings.Contains(err.Error(), "no key") {
				fmt.Println("This appears to be an issue with finding the correct key for decryption")
			} else if strings.Contains(err.Error(), "cannot find required element: EncryptionMethod") ||
				strings.Contains(err.Error(), "algorithm not supported") {
				fmt.Println("The encrypted assertion uses an unsupported encryption format")
				fmt.Println("Trying manual extraction of encrypted data...")

				// Look for the EncryptedData element
				encDataEl := samlResp.EncryptedAssertion.FindElement("//xenc:EncryptedData")
				if encDataEl != nil {
					// Check encryption method
					encMethodEl := encDataEl.FindElement(".//xenc:EncryptionMethod")
					if encMethodEl != nil {
						algorithm := encMethodEl.SelectAttrValue("Algorithm", "")
						fmt.Printf("Encryption algorithm: %s\n", algorithm)

						// Check if it's AES-256-GCM (XMLEnc 1.1 algorithm)
						if algorithm == "http://www.w3.org/2009/xmlenc11#aes256-gcm" {
							fmt.Println("Detected AES-256-GCM encryption (XMLEnc 1.1)")
							fmt.Println("This algorithm is not directly supported by the library")
							fmt.Println("Using a fallback approach...")

							// Extract the key details
							encKeyEl := encDataEl.FindElement(".//xenc:EncryptedKey")
							if encKeyEl != nil {
								// Get the cipher value
								cipherValueEl := encKeyEl.FindElement(".//xenc:CipherValue")
								if cipherValueEl != nil {
									keyData := cipherValueEl.Text()
									fmt.Printf("Found encrypted key data (%d bytes)\n", len(keyData))

									// Get the encrypted data
									encDataValueEl := encDataEl.FindElement("./xenc:CipherData/xenc:CipherValue")
									if encDataValueEl != nil {
										encDataValue := encDataValueEl.Text()
										fmt.Printf("Found encrypted data (%d bytes)\n", len(encDataValue))

										fmt.Println("Unfortunately, direct decryption of AES-256-GCM from XMLEnc 1.1 is not implemented")
										fmt.Println("You may need to update the IdP configuration to use a compatible encryption algorithm")
										fmt.Println("Compatible algorithms include: AES-128-CBC, AES-256-CBC, or disable encryption")
									} else {
										fmt.Println("Failed to find CipherValue for encrypted data")
									}
								} else {
									fmt.Println("Failed to find CipherValue for encrypted key")
								}
							} else {
								fmt.Println("Failed to find EncryptedKey element")
							}
						} else {
							fmt.Printf("Unsupported encryption algorithm: %s\n", algorithm)
							fmt.Println("Please check the IdP configuration for supported algorithms")
						}
					} else {
						fmt.Println("Failed to find EncryptionMethod element")
					}
				} else {
					fmt.Println("Failed to find EncryptedData element")
				}
			}

			http.Error(w, "Failed to decrypt SAML assertion", http.StatusInternalServerError)
			return
		}

		// Log success
		fmt.Println("Successfully decrypted assertion!")

		// Parse the decrypted XML into a saml.Assertion
		decryptedAssertion := &saml.Assertion{}
		if err := xml.Unmarshal(plaintextBytes, decryptedAssertion); err != nil {
			fmt.Printf("Failed to parse decrypted assertion: %v\n", err)
			http.Error(w, "Failed to parse decrypted assertion", http.StatusInternalServerError)
			return
		}

		// Replace the encrypted assertion with the decrypted one
		samlResp.Assertion = decryptedAssertion
		samlResp.EncryptedAssertion = nil

		fmt.Println("Decrypted assertion successfully parsed and added to response")
	} else if samlResp.Assertion == nil {
		fmt.Println("==== WARNING: NO ASSERTION FOUND ====")
		fmt.Println("The SAML response contains neither an Assertion nor an EncryptedAssertion")
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

	// Log SAML response metadata
	fmt.Printf("==== SAML RESPONSE RECEIVED ====\n")
	fmt.Printf("Response ID: %s\n", samlResp.ID)
	fmt.Printf("IssueInstant: %s\n", samlResp.IssueInstant.Format(time.RFC3339))
	fmt.Printf("InResponseTo: %s\n", samlResp.InResponseTo)
	fmt.Printf("Issuer: %s\n", samlResp.Issuer.Value)
	fmt.Printf("Status: %s\n", samlResp.Status.StatusCode.Value)

	// Log request ID tracking
	fmt.Printf("==== REQUEST ID TRACKING ====\n")
	fmt.Printf("Original SP Request ID: %s\n", originalRequest.OriginalRequestID)
	fmt.Printf("Current Request ID: %s\n", originalRequest.RequestID)
	fmt.Printf("Will use Original SP Request ID for InResponseTo\n")

	// Extract and log subject information
	if samlResp.Assertion != nil && samlResp.Assertion.Subject != nil && samlResp.Assertion.Subject.NameID != nil {
		fmt.Printf("Subject NameID: %s\n", samlResp.Assertion.Subject.NameID.Value)
		fmt.Printf("Subject Format: %s\n", samlResp.Assertion.Subject.NameID.Format)
	}
	if samlResp.Assertion != nil {
		fmt.Printf("==== SAML ATTRIBUTES ====\n")

		for _, statement := range samlResp.Assertion.AttributeStatements {
			for _, attr := range statement.Attributes {
				values := make([]string, len(attr.Values))
				for i, value := range attr.Values {
					values[i] = value.Value
				}
				attributes[attr.Name] = values

				// Log each attribute and its values
				fmt.Printf("Attribute '%s':\n", attr.Name)
				for i, value := range values {
					fmt.Printf("  Value %d: %s\n", i+1, value)
				}
			}
		}

		// Log assertion conditions if present
		if samlResp.Assertion.Conditions != nil {
			fmt.Printf("==== ASSERTION CONDITIONS ====\n")
			fmt.Printf("NotBefore: %s\n", samlResp.Assertion.Conditions.NotBefore.Format(time.RFC3339))
			fmt.Printf("NotOnOrAfter: %s\n", samlResp.Assertion.Conditions.NotOnOrAfter.Format(time.RFC3339))

			for _, audience := range samlResp.Assertion.Conditions.AudienceRestrictions {
				fmt.Printf("Audience: %s\n", audience.Audience.Value)
			}
		}

		// Log authentication statements
		if len(samlResp.Assertion.AuthnStatements) > 0 {
			fmt.Printf("==== AUTHN STATEMENTS ====\n")
			for i, stmt := range samlResp.Assertion.AuthnStatements {
				fmt.Printf("AuthnStatement %d:\n", i+1)
				fmt.Printf("  AuthnInstant: %s\n", stmt.AuthnInstant.Format(time.RFC3339))
				fmt.Printf("  SessionIndex: %s\n", stmt.SessionIndex)
				if stmt.AuthnContext.AuthnContextClassRef != nil {
					fmt.Printf("  AuthnContextClassRef: %s\n", *stmt.AuthnContext.AuthnContextClassRef)
				}
			}
		}
	}

	// Add information about which IdP was used
	if originalRequest.IdentityProvider != nil {
		attributes["idp_id"] = []string{originalRequest.IdentityProvider.ID}
		attributes["idp_name"] = []string{originalRequest.IdentityProvider.Name}
		fmt.Printf("==== IDP INFORMATION ====\n")
		fmt.Printf("IdP ID: %s\n", originalRequest.IdentityProvider.ID)
		fmt.Printf("IdP Name: %s\n", originalRequest.IdentityProvider.Name)
	}

	// Map attributes according to service provider configuration
	mappedAttributes := make(map[string][]string)

	fmt.Printf("==== MAPPING ATTRIBUTES TO SERVICE PROVIDER ====\n")
	fmt.Printf("Service Provider: %s (Entity ID: %s)\n",
		originalRequest.ServiceProvider.Name,
		originalRequest.ServiceProvider.EntityID)

	for spAttr, idpAttr := range originalRequest.ServiceProvider.AttributeMap {
		if values, ok := attributes[idpAttr]; ok {
			mappedAttributes[spAttr] = values
			fmt.Printf("Mapping '%s' -> '%s': %v\n", idpAttr, spAttr, values)
		} else {
			fmt.Printf("No values found for IdP attribute '%s' to map to SP attribute '%s'\n",
				idpAttr, spAttr)
		}
	}

	// Log the final set of attributes that will be sent to the SP
	fmt.Printf("==== FINAL ATTRIBUTES FOR SERVICE PROVIDER ====\n")
	for attr, values := range mappedAttributes {
		fmt.Printf("Attribute '%s':\n", attr)
		for i, val := range values {
			fmt.Printf("  Value %d: %s\n", i+1, val)
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
		InResponseTo: originalRequest.OriginalRequestID, // Use the original request ID from the SP
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
						InResponseTo: originalRequest.OriginalRequestID, // Use the original request ID from the SP
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
	// Create the AuthnRequest XML document
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

	// Add signature element at the proper position (right after Issuer)
	signatureEl := etree.NewElement("ds:Signature")
	signatureEl.CreateAttr("xmlns:ds", "http://www.w3.org/2000/09/xmldsig#")
	authnRequestEl.InsertChildAt(1, signatureEl)

	// Use the utility to sign the request
	if err := samlutils.SignElement(authnRequestEl, request.ID, sp.Certificate, sp.PrivateKey); err != nil {
		return nil, fmt.Errorf("failed to sign SAML request: %v", err)
	}

	// Return the fully signed XML document
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

	// First we'll create and sign the assertion, then add it to the response
	var assertionEl *etree.Element

	// Create the assertion if present
	if response.Assertion != nil {
		// Create a separate document for the assertion to sign it independently
		assertionDoc := etree.NewDocument()
		assertionEl = assertionDoc.CreateElement("saml:Assertion")
		assertionEl.CreateAttr("xmlns:saml", "urn:oasis:names:tc:SAML:2.0:assertion")
		assertionEl.CreateAttr("xmlns:xs", "http://www.w3.org/2001/XMLSchema")
		assertionEl.CreateAttr("xmlns:xsi", "http://www.w3.org/2001/XMLSchema-instance")
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

		// Now sign the assertion
		// Create signature for assertion
		signatureEl := etree.NewElement("ds:Signature")
		signatureEl.CreateAttr("xmlns:ds", "http://www.w3.org/2000/09/xmldsig#")
		assertionEl.InsertChildAt(1, signatureEl)

		// Sign the assertion using XML digital signature
		if err := samlutils.SignElement(assertionEl, response.Assertion.ID, sp.Certificate, sp.PrivateKey); err != nil {
			return nil, fmt.Errorf("failed to sign assertion: %v", err)
		}

		// Now add the signed assertion to the main response document
		respEl.AddChild(assertionEl.Copy())
	}

	// Now sign the entire response
	// Create signature for response
	signatureEl := etree.NewElement("ds:Signature")
	signatureEl.CreateAttr("xmlns:ds", "http://www.w3.org/2000/09/xmldsig#")
	respEl.InsertChildAt(1, signatureEl)

	// Sign the response using XML digital signature
	if err := samlutils.SignElement(respEl, response.ID, sp.Certificate, sp.PrivateKey); err != nil {
		return nil, fmt.Errorf("failed to sign response: %v", err)
	}

	// Return the fully signed document
	return doc.WriteToBytes()
}

package main

import (
	"flag"
	"log"
	"net/http"

	"github.com/nmelo/saml-tools/internal/samlidp"
)

func main() {
	configFile := flag.String("config", "configs/samlidp.yaml", "Path to config file")
	flag.Parse()

	// Create the SAML IdP
	idp, err := samlidp.NewSAMLIdP(*configFile)
	if err != nil {
		log.Fatalf("Failed to create SAML IdP: %v", err)
	}

	// Start the server
	log.Printf("Starting SAML IdP on %s", idp.Config.ListenAddr)
	log.Printf("Metadata available at: %s%s", idp.Config.BaseURL, idp.Config.MetadataPath)
	log.Fatal(http.ListenAndServe(idp.Config.ListenAddr, idp.Router))
}
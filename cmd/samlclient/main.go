package main

import (
	"flag"
	"log"
	"net/http"

	"github.com/nmelo/saml-tools/internal/samlclient"
)

func main() {
	configFile := flag.String("config", "configs/samlclient.yaml", "Path to config file")
	flag.Parse()

	// Create the SAML client
	client, err := samlclient.NewSAMLClient(*configFile)
	if err != nil {
		log.Fatalf("Failed to create SAML client: %v", err)
	}

	// Initialize SAML middleware
	if err := client.InitializeSAMLMiddleware(); err != nil {
		log.Fatalf("Failed to initialize SAML middleware: %v", err)
	}

	// Set up routes
	handler := client.SetupRoutes()

	// Start the server
	log.Printf("Starting SAML client on %s", client.Config.ListenAddr)
	log.Printf("Service Provider metadata available at %s%s", client.Config.BaseURL, client.Config.MetadataPath)
	log.Fatal(http.ListenAndServe(client.Config.ListenAddr, handler))
}

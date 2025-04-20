package main

import (
	"flag"
	"log"
	"net/http"

	"github.com/nmelo/saml-tools/internal/samlproxy"
)

func main() {
	configFile := flag.String("config", "configs/samlproxy.yaml", "Path to config file")
	flag.Parse()

	// Create the SAML proxy
	proxy, err := samlproxy.NewSAMLProxy(*configFile)
	if err != nil {
		log.Fatalf("Failed to create SAML proxy: %v", err)
	}

	// Set up HTTP server
	server := &http.Server{
		Addr:    proxy.Config.ListenAddr,
		Handler: proxy,
	}

	// Start the server
	log.Printf("Starting SAML proxy on %s", proxy.Config.ListenAddr)
	log.Printf("SAML Proxy metadata URL: %s/metadata", proxy.Config.BaseURL)
	log.Fatal(server.ListenAndServe())
}
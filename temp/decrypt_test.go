package main

import (
	"crypto/rsa"
	"fmt"
	
	"github.com/beevik/etree"
	"github.com/crewjam/saml"
)

func main() {
	// Just inspecting the API
	doc := etree.NewDocument()
	encryptedAssertion := doc.CreateElement("saml:EncryptedAssertion")
	
	// Try to find methods for decrypting
	fmt.Println("Checking for Decrypt methods in saml package...")
}

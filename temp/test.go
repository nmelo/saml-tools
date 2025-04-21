package main

import "fmt"

func main() {
	fmt.Println("To decrypt an EncryptedAssertion in crewjam/saml:")
	fmt.Println("\n1. Get the saml.Response object with EncryptedAssertion (etree.Element)")
	fmt.Println("2. Call xmlenc.Decrypt() with your private key and the EncryptedAssertion")
	fmt.Println("3. Parse the resulting bytes into a saml.Assertion\n")
	
	// Pseudo-code for decryption
	fmt.Println("Code example:")
	fmt.Println(`
// Assume we have a saml.Response and a *rsa.PrivateKey
func decryptAssertion(response *saml.Response, privateKey *rsa.PrivateKey) (*saml.Assertion, error) {
    if response.EncryptedAssertion == nil {
        return nil, fmt.Errorf("no EncryptedAssertion found")
    }
    
    // Decrypt the assertion using xmlenc.Decrypt
    plaintextBytes, err := xmlenc.Decrypt(privateKey, response.EncryptedAssertion)
    if err \!= nil {
        return nil, fmt.Errorf("failed to decrypt assertion: %v", err)
    }
    
    // Parse the plaintext XML into a saml.Assertion
    assertion := &saml.Assertion{}
    err = xml.Unmarshal(plaintextBytes, assertion)
    if err \!= nil {
        return nil, fmt.Errorf("failed to unmarshal assertion: %v", err)
    }
    
    return assertion, nil
}`)
}

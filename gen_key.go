package jwt

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"io/ioutil"
	"log"
)

func GenerateAndSaveKeys(privateKeyPath, publicKeyPath string) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 4096)
	if err != nil {
		log.Fatalf("generate RSA key error: %v", err)
	}

	privateKeyString := privateKeyToBase64(privateKey)

	publicKeyString := publicKeyToBase64(&privateKey.PublicKey)

	err = ioutil.WriteFile(privateKeyPath, []byte(privateKeyString), 0o644)
	if err != nil {
		log.Fatalf("failed to write private key to file: %v", err)
	}

	err = ioutil.WriteFile(publicKeyPath, []byte(publicKeyString), 0o644)
	if err != nil {
		log.Fatalf("failed to write public key to file: %v", err)
	}

	log.Println("Private and public keys have been saved to private_key.txt and public_key.txt")
}

func privateKeyToBase64(key *rsa.PrivateKey) string {
	privBytes := x509.MarshalPKCS1PrivateKey(key)
	privPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: privBytes})

	return base64.StdEncoding.EncodeToString(privPEM)
}

func publicKeyToBase64(key *rsa.PublicKey) string {
	pubBytes, err := x509.MarshalPKIXPublicKey(key)
	if err != nil {
		log.Fatalf("failed to marshal public key: %v", err)
	}

	pubPEM := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: pubBytes})

	return base64.StdEncoding.EncodeToString(pubPEM)
}

package jwt

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"log"
	"os"
)

func GenerateAndSaveKeys(privateKeyPath, publicKeyPath string) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 4096) // Sử dụng 4096 bit cho RS512
	if err != nil {
		log.Fatalf("generate RSA key error: %v", err)
	}

	privateKeyBytes := x509.MarshalPKCS1PrivateKey(privateKey)
	privateKeyPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: privateKeyBytes})
	privateKeyString := base64.StdEncoding.EncodeToString(privateKeyPEM)

	err = os.WriteFile(privateKeyPath, []byte(privateKeyString), 0o600)
	if err != nil {
		log.Fatalf("save private key error: %v", err)
	}

	pubASN1, err := x509.MarshalPKIXPublicKey(&privateKey.PublicKey)
	if err != nil {
		log.Fatalf("save public key error: %v", err)
	}
	publicKeyPEM := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: pubASN1})
	publicKeyString := base64.StdEncoding.EncodeToString(publicKeyPEM)
	err = os.WriteFile(publicKeyPath, []byte(publicKeyString), 0o644)
	if err != nil {
		log.Fatalf("save public key error: %v", err)
	}
}

func parsePrivateKey(base64Key string) (*rsa.PrivateKey, error) {
	pemBytes, err := base64.StdEncoding.DecodeString(base64Key)
	if err != nil {
		return nil, err
	}

	block, _ := pem.Decode(pemBytes)
	if block == nil {
		return nil, err
	}

	privateKey, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		return nil, err
	}

	return privateKey, nil
}

func parsePublicKey(base64Key string) (*rsa.PublicKey, error) {
	pemBytes, err := base64.StdEncoding.DecodeString(base64Key)
	if err != nil {
		return nil, err
	}

	block, _ := pem.Decode(pemBytes)
	if block == nil {
		return nil, err
	}

	pub, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, err
	}

	publicKey, ok := pub.(*rsa.PublicKey)
	if !ok {
		return nil, err
	}

	return publicKey, nil
}

package cypher

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"errors"
)

type AsymmetricCypher struct {
	keys KeyPair
}

func NewAsymmetricCypher(keys KeyPair) AsymmetricCypher {
	c := AsymmetricCypher{
		keys: keys,
	}
	return c
}

func (a AsymmetricCypher) Encrypt(key string, message string) (string, error) {
	publicKey, err := ParseRSAPublicKeyFromPEM(key)
	if err != nil {
		return "", errors.New("error while parse public key")
	}
	encryptedBytes, err := rsa.EncryptOAEP(
		sha256.New(),
		rand.Reader,
		publicKey,
		[]byte(message),
		nil)
	if err != nil {
		panic(err)
	}
	encoded := base64.StdEncoding.EncodeToString(encryptedBytes)
	return encoded, nil
}

func (a AsymmetricCypher) Decrypt(key string, message string) (string, error) {
	privateKey, err := ParseRSAPrivateKeyFromPEM(key)
	if err != nil {
		return "", errors.New("error while parse private key")
	}
	decoded, err := base64.StdEncoding.DecodeString(message)
	decryptedBytes, err := privateKey.Decrypt(nil, decoded, &rsa.OAEPOptions{Hash: crypto.SHA256})
	if err != nil {
		panic(err)
	}

	return string(decryptedBytes), nil
}

package cypher

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"io"
)

type SymmetricCypher struct {
}

func NewSymmetricCypher() SymmetricCypher {
	c := SymmetricCypher{}
	return c
}

func (a SymmetricCypher) Encrypt(password string, message string) (string, error) {
	key, salt, err := deriveKey([]byte(password), nil)
	if err != nil {
		return "", err
	}

	c, err := aes.NewCipher([]byte(key))
	if err != nil {
		return "", err
	}
	gcm, err := cipher.NewGCM(c)

	if err != nil {
		return "", nil
	}

	nonce := make([]byte, gcm.NonceSize())
	if _, err = io.ReadFull(rand.Reader, nonce); err != nil {
		return "", err
	}

	encryptedBytes := gcm.Seal(nonce, nonce, []byte(message), nil)
	cypherText := append(encryptedBytes, salt...)
	encoded := base64.StdEncoding.EncodeToString(cypherText)
	return encoded, nil
}

func (a SymmetricCypher) Decrypt(password string, message string) (string, error) {
	decoded, err := base64.StdEncoding.DecodeString(message)
	salt, data := decoded[len(decoded)-32:], decoded[:len(decoded)-32]

	key, _, err := deriveKey([]byte(password), salt)
	if err != nil {
		return "", err
	}

	c, err := aes.NewCipher(key)
	if err != nil {
		fmt.Println(err)
	}

	gcm, err := cipher.NewGCM(c)
	if err != nil {
		fmt.Println(err)
	}

	nonce, ciphertext := data[:gcm.NonceSize()], data[gcm.NonceSize():]
	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		fmt.Println(err)
	}
	return string(plaintext), nil
}

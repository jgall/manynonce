// Package multinonce provides utilities to encrypt messages with the standard nonce size, but using the number of nonces given.
// This is useful for avoiding nonce collisions within the restriction of using the standard nonce size
package multinonce

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"errors"
	"io"
)

// ToAES encrypts the given message using the given master key and number of nonces provided
func ToAES(message []byte, masterkey []byte, nonces int) ([]byte, error) {
	if nonces <= 0 {
		return nil, errors.New("Number of nonces must be greater than 0")
	}
	ciphertext := message

	for i := 0; i < nonces; i++ {
		block, err := aes.NewCipher(masterkey)
		if err != nil {
			return nil, err
		}
		aesgcm, err := cipher.NewGCM(block)
		if err != nil {
			return nil, err
		}
		nonce := make([]byte, aesgcm.NonceSize())
		if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
			return nil, err
		}
		ciphertext = append(nonce, aesgcm.Seal(nil, nonce, ciphertext, nil)...)
	}
	return ciphertext, nil
}

// FromAES decrypts the given ciphertext using the given masterkey and number of nonces provided
func FromAES(ciphertext []byte, masterkey []byte, nonces int) ([]byte, error) {
	return nil, nil
}

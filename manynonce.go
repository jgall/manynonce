// Package manynonce provides utilities to encrypt messages with the standard nonce size, but using the number of nonces given.
// This is useful for avoiding nonce collisions within the restriction of using the standard nonce size (although honestly any number over 2-3 is overkill).
package manynonce

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
	block, err := aes.NewCipher(masterkey)
	if err != nil {
		return nil, err
	}
	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	ciphertext := message
	for i := 0; i < nonces; i++ {
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
	if nonces <= 0 {
		return nil, errors.New("Number of nonces must be greater than 0")
	}
	block, err := aes.NewCipher(masterkey)
	if err != nil {
		return nil, err
	}
	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	msg := ciphertext
	for i := 0; i < nonces; i++ {
		msg, err = aesgcm.Open(nil, msg[0:aesgcm.NonceSize()], msg[aesgcm.NonceSize():], nil)
		if err != nil {
			return nil, err
		}
	}
	return msg, nil
}

package manynonce

import (
	"testing"
)

func TestMultiNonce(t *testing.T) {
	secretMessage := []byte("I'm super secret shhhhh don't tell anyone")
	masterkey := []byte("my-secret-32-byte-master-enc-key")
	for i := 1; i <= 10; i++ {
		ciphertext, err := ToAES(secretMessage, masterkey, i)
		if err != nil {
			t.Error(err)
			return
		}
		plaintext, err := FromAES(ciphertext, masterkey, i)
		if err != nil {
			t.Error(err)
			return
		}
		if string(plaintext) != string(secretMessage) {
			t.Errorf("expected: %v, got %v", string(secretMessage), string(plaintext))
		}
	}
}

// Copyright (c) 2015, xrstf | MIT licensed

package boxer

import (
	"bytes"
	"testing"
	"time"

	"golang.org/x/crypto/nacl/secretbox"
)

func TestCreateNonce(t *testing.T) {
	now := time.Now()

	nonce1, err := createNonce(now)
	if err != nil {
		t.Fatal(err)
	}

	nonce2, err := createNonce(now)
	if err != nil {
		t.Fatal(err)
	}

	if bytes.Equal(nonce1[:], nonce2[:]) {
		t.Fatal("Two nonces generated at the same time should not collide.")
	}
}

func TestDeriveKey(t *testing.T) {
	bxr := NewDefaultBoxer()
	pwd := []byte("password")
	salt := new([SaltLength]byte) // empty, but not important in this test

	key1, err := bxr.DeriveKey(pwd, salt)
	if err != nil {
		t.Fatal(err)
	}

	key2, err := bxr.DeriveKey(pwd, salt)
	if err != nil {
		t.Fatal(err)
	}

	if !bytes.Equal(key1[:], key2[:]) {
		t.Fatal("Deriving a key from a password+salt should always yield the same result.")
	}
}

func TestDeriveKeyFromPassword(t *testing.T) {
	bxr := NewDefaultBoxer()
	pwd := []byte("password")

	key1, salt1, err := bxr.DeriveKeyFromPassword(pwd)
	if err != nil {
		t.Fatal(err)
	}

	key2, salt2, err := bxr.DeriveKeyFromPassword(pwd)
	if err != nil {
		t.Fatal(err)
	}

	if bytes.Equal(salt1[:], salt2[:]) {
		t.Fatal("Deriving a key from a password should use new salts each time.")
	}

	if bytes.Equal(key1[:], key2[:]) {
		t.Fatal("Deriving a key from a password should result in new keys every time, as the salt is different.")
	}
}

func TestEncryptNoData(t *testing.T) {
	bxr := NewDefaultBoxer()
	pwd := []byte("password")
	data := make([]byte, 0)

	_, err := bxr.Encrypt(data, pwd)
	if err == nil {
		t.Fatal("Trying to encrypt no data should yield an error.")
	}
}

func TestEncryptWithEmptyPassword(t *testing.T) {
	bxr := NewDefaultBoxer()
	pwd := make([]byte, 0)
	data := []byte("it's a secret to everybody")

	_, err := bxr.Encrypt(data, pwd)
	if err == nil {
		t.Fatal("Trying to encrypt without a password should yield an error.")
	}
}

func TestDecryptInvalidData(t *testing.T) {
	bxr := NewDefaultBoxer()
	pwd := []byte("password")
	data := [][]byte{
		make([]byte, 0),
		make([]byte, 1),
		make([]byte, SaltLength+NonceLength),
		make([]byte, SaltLength+NonceLength+secretbox.Overhead),
	}

	for idx, input := range data {
		_, err := bxr.Decrypt(input, pwd)
		if err == nil {
			t.Fatalf("The %d. bogus dataset should not be decryptable.", idx+1)
		}
	}
}

func TestDecryptVanillaCase(t *testing.T) {
	bxr := NewDefaultBoxer()
	pwd := []byte("password")
	data := []byte("it's a secret to everybody")

	ciphertext, err := bxr.Encrypt(data, pwd)
	if err != nil {
		t.Fatal(err)
	}

	// try with the correct password
	plaintext, err := bxr.Decrypt(ciphertext, pwd)
	if err != nil {
		t.Fatal(err)
	}

	if !bytes.Equal(data, plaintext) {
		t.Fatal("Decrypting did not yield the original input.")
	}

	// and now the same with a wrong password
	plaintext, err = bxr.Decrypt(ciphertext, []byte("Password"))
	if err == nil {
		t.Fatal("Decrypting with the wrong password should not succeed.")
	}
}

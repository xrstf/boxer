// Copyright (c) 2015, xrstf | MIT licensed

// Package boxer implements a convenience wrapper around the NaCl package.
//
// Its main goal is to hide the management of nonces and salts from the user.
// Passwords will be automatically stretched using PBKDF2 with SHA-256, the
// nonce includes the current time to make collisions less likely.
//
// Note that the key stretching is performed on each encryption/decryption, so
// if you plan to perform a lot of crypto operations in a short time, this might
// be too expensive.
package boxer

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"time"

	"golang.org/x/crypto/nacl/secretbox"
	"golang.org/x/crypto/pbkdf2"
)

// The length of the salt used for key derivation via PBKDF2.
const SaltLength = 8

// The length of the nonce used for the secretbox implementation.
const NonceLength = 24

// The length of the encryption key for the secretbox implementation.
const KeyLength = 32

// Encrypt some data with a password
//
// This function automatically stretches the password to meet the KeyLength
// requirement, as well as calculate a fresh nonce. The function returns an
// error if not enough data is avialable in rand.Reader, otherwise the first
// value will be the encryption result, containing the salt and nonce.
func Encrypt(data []byte, password []byte) ([]byte, error) {
	// derive a new encryption key for this message
	key, salt, err := DeriveKeyFromPassword(password)
	if err != nil {
		return nil, errors.New("Could not derive encryption key from password: " + err.Error())
	}

	// create a fresh nonce
	nonce, err := CreateNonce()
	if err != nil {
		return nil, errors.New("Could not create nonce: " + err.Error())
	}

	// seal the data in a nacl box; the box will have the kd salt and nonce prepended
	box := make([]byte, SaltLength+NonceLength)
	copy(box, salt[:])
	copy(box[SaltLength:], nonce[:])

	// let the magic happen
	box = secretbox.Seal(box, data, nonce, key)

	return box, nil
}

// Decrypt data
//
// This function decrypts data originally encrypted using Encrypt(). It will extract
// the PBKDF2 salt and nonce and apply the required transformations. An error is
// returned when the ciphertext is too short or the password does not match. Otherwise,
// the raw decrypted message is returned.
func Decrypt(ciphertext []byte, password []byte) ([]byte, error) {
	minLength := SaltLength + NonceLength + secretbox.Overhead + 1

	if len(ciphertext) < minLength {
		return nil, errors.New(fmt.Sprintf("The ciphertext is too short (%d bytes) to be valid. It needs to be at least %d bytes.", len(ciphertext), minLength))
	}

	salt := new([SaltLength]byte)
	nonce := new([NonceLength]byte)

	// first comes the salt, then the nonce, then the box itself
	copy(salt[:], ciphertext[:SaltLength])
	copy(nonce[:], ciphertext[SaltLength:(SaltLength+NonceLength)])

	box := ciphertext[(SaltLength + NonceLength):]
	key := DeriveKey(password, salt)

	plain, success := secretbox.Open(nil, box, nonce, key)
	if !success {
		return nil, errors.New("Decrypting failed, probably due to a wrong password.")
	}

	return plain, nil
}

// Derive a key for NaCl's secretbox from a password
//
// secretbox requires a key with exactly 32 bytes. This function uses PBKDF2 to
// derive a key from a given password. Note that the result is randomized, as it
// contains a random salt.
// The first byte slice is the key, the second one is the generated salt. You need
// to keep the salt (it does not need to be encrypted, consider it "public") and
// use it again to re-create the same key from a password.
// If you use Encrypt() and Decrypt(), all this is already taken care of.
func DeriveKeyFromPassword(password []byte) (*[KeyLength]byte, *[SaltLength]byte, error) {
	// create the salt for key derivation
	salt := new([SaltLength]byte)

	_, err := rand.Reader.Read(salt[:])
	if err != nil {
		return nil, nil, errors.New("Could not gather sufficient random data to perform encryption: " + err.Error())
	}

	return DeriveKey(password, salt), salt, nil
}

// Derive a key from a password and salt
//
// This is just a wrapper around PBKDF2 with 8192 iterations and using SHA-256.
func DeriveKey(password []byte, salt *[SaltLength]byte) *[KeyLength]byte {
	// create encryption key (32byte) from the password using PBKDF2 (RFC 2898)
	key := new([KeyLength]byte)
	copy(key[:], pbkdf2.Key(password, salt[:], 8192, KeyLength, sha256.New))

	return key
}

// Create a nonce
//
// Nonces MUST be used exactly once for encrypting a message. They can be appended
// to the ciphertext, as they do not need to stay secret.
// This implementation returns a nonce consisting of the current time including
// milliseconds and 16 random bytes. It returns an error if rand.Reader could not
// provide enough entropy.
func CreateNonce() (*[NonceLength]byte, error) {
	nonce := new([NonceLength]byte)
	now := time.Now().UnixNano()

	binary.BigEndian.PutUint64(nonce[:], uint64(now))

	_, err := rand.Reader.Read(nonce[8:])
	if err != nil {
		return nil, err
	}

	return nonce, nil
}

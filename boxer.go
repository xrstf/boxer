// Copyright (c) 2015, xrstf | MIT licensed

// Package boxer implements a convenience wrapper around the NaCl package.
//
// Its main goal is to hide the management of nonces and salts from the user.
// Passwords will be automatically stretched using scrypt, the nonce includes
// the current time to make collisions less likely.
//
// Note that the key stretching is performed on each encryption/decryption, so
// if you plan to perform a lot of crypto operations in a short time, this might
// be too expensive.
package boxer

import (
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"time"

	"golang.org/x/crypto/nacl/secretbox"
	"golang.org/x/crypto/scrypt"
)

// The length of the salt used for scrypt.
const SaltLength = 24

// The length of the nonce used for the secretbox implementation.
const NonceLength = 24

// The length of the encryption key for the secretbox implementation.
const KeyLength = 32

// This structure contains the parameters used for running scrypt. As time passes,
// they need to be adjusted to take newer CPU/GPU generations into account. Use
// DefaultScryptParameters() to get a good set of parameters as of 2015. Note that
// the Cost factor highly depends on your usecase: if you plan to do many crypto
// runs in a short time, a high Cost factor can open you up to Denial-of-Service
// attacks.
type ScryptParameters struct {
	// cost parameter
	Cost int

	// R value
	R int

	// P value
	P int
}

// Return a sane set of default values as of 2015.
func DefaultScryptParameters() ScryptParameters {
	return ScryptParameters{16384, 8, 1}
}

// A Boxer can open and seal boxes to encrypt/decrypt data.
//
// Boxes created by this type are only compatible to other Boxers with the
// identical params struct. Also, use *either* password-based encryption
// *or* key-based encryption, but don't mix the two, as their random salt
// will make it basically impossible to get the keys right.
type Boxer struct {
	params ScryptParameters
}

// Create a new Boxer based on a given scrypt parameter set.
func NewBoxer(params ScryptParameters) *Boxer {
	return &Boxer{params}
}

// Create a new Boxer with the default scrypt parameters of this package.
func NewDefaultBoxer() *Boxer {
	return &Boxer{DefaultScryptParameters()}
}

// Encrypt some data with a password
//
// This function automatically stretches the password to meet the KeyLength
// requirement, as well as calculate a fresh nonce. The function returns an
// error if the data/password is empty or not enough data is available in
// rand.Reader, otherwise the first value will be the encryption result,
// containing the salt and nonce.
func (b *Boxer) Encrypt(data []byte, password []byte) ([]byte, error) {
	if len(data) == 0 {
		return nil, errors.New("Cannot encrypt zero-length data.")
	}

	if len(password) == 0 {
		return nil, errors.New("Empty passwords are not allowed for encryption.")
	}

	// derive a new encryption key for this message
	key, salt, err := b.DeriveKeyFromPassword(password)
	if err != nil {
		return nil, errors.New("Could not derive encryption key from password: " + err.Error())
	}

	// create a fresh nonce
	nonce, err := b.CreateNonce()
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
// the scrypt salt and nonce and apply the required transformations. An error is
// returned when the ciphertext is too short or the password does not match. Otherwise,
// the raw decrypted message is returned.
func (b *Boxer) Decrypt(ciphertext []byte, password []byte) ([]byte, error) {
	minLength := SaltLength + NonceLength + secretbox.Overhead + 1

	if len(ciphertext) < minLength {
		return nil, fmt.Errorf("The ciphertext is too short (%d bytes) to be valid. It needs to be at least %d bytes.", len(ciphertext), minLength)
	}

	// figure out the salt to derive the key used for encryption
	salt := new([SaltLength]byte)
	copy(salt[:], ciphertext[:SaltLength])

	key, err := b.DeriveKey(password, salt)
	if err != nil {
		return nil, err
	}

	// find the secretbox nonce (if follows the SaltLength bytes at the beginning of ciphertext)
	nonce := new([NonceLength]byte)
	copy(nonce[:], ciphertext[SaltLength:(SaltLength+NonceLength)])

	// slice out the secretbox
	box := ciphertext[(SaltLength + NonceLength):]

	// ... and open it
	plain, success := secretbox.Open(nil, box, nonce, key)
	if !success {
		return nil, errors.New("Decrypting failed, probably due to a wrong password.")
	}

	return plain, nil
}

// Derive a key for NaCl's secretbox from a password
//
// secretbox requires a key with exactly 32 bytes. This function uses scrypt to
// derive a key from a given password. Note that the result is randomized, as it
// contains a random salt.
// The first byte array is the key, the second one is the generated salt. You need
// to keep the salt (it does not need to be encrypted, consider it "public") and
// use it again to re-create the same key from a password.
func (b *Boxer) DeriveKeyFromPassword(password []byte) (*[KeyLength]byte, *[SaltLength]byte, error) {
	// create the salt for key derivation
	salt := new([SaltLength]byte)

	_, err := rand.Reader.Read(salt[:])
	if err != nil {
		return nil, nil, errors.New("Could not gather sufficient random data to perform encryption: " + err.Error())
	}

	key, err := b.DeriveKey(password, salt)
	if err != nil {
		return nil, nil, err
	}

	return key, salt, nil
}

// Derive a key from a password and salt
//
// This is just a wrapper around scrypt.
func (b *Boxer) DeriveKey(password []byte, salt *[SaltLength]byte) (*[KeyLength]byte, error) {
	// create encryption key (32byte) from the password
	key := new([KeyLength]byte)

	result, err := scrypt.Key(password, salt[:], b.params.Cost, b.params.R, b.params.P, KeyLength)
	if err != nil {
		return nil, err
	}

	copy(key[:], result)

	return key, nil
}

// Create a nonce
//
// Nonces MUST be used exactly once for encrypting a message. They can be appended
// to the ciphertext, as they do not need to stay secret.
// This implementation returns a nonce consisting of the current time including
// milliseconds and 16 random bytes. It returns an error if rand.Reader could not
// provide enough entropy.
func (b *Boxer) CreateNonce() (*[NonceLength]byte, error) {
	return createNonce(time.Now())
}

func createNonce(t time.Time) (*[NonceLength]byte, error) {
	nonce := new([NonceLength]byte)
	now := t.UnixNano()

	binary.BigEndian.PutUint64(nonce[:], uint64(now))

	_, err := rand.Reader.Read(nonce[8:])
	if err != nil {
		return nil, err
	}

	return nonce, nil
}

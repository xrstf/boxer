Boxer - NaCl for Humans
=======================

This Go package implements a convenience wrapper around the NaCl package.

Its main goal is to hide the management of nonces and salts from the user.
Passwords will be automatically stretched using PBKDF2 with SHA-256, the
nonce includes the current time to make collisions less likely.

Note that the key stretching is performed on each encryption/decryption, so
if you plan to perform a lot of crypto operations in a short time, this might
be too expensive.

Disclaimer
----------

I am by no means a security expert. Do not blindly trust this code, read it
and judge by yourself. If you find a flaw, please open an issue and tell me.

On that note: This package is *very* opinionated. It solves a very narrow
usecase and should not be applied to every problem that sounds like "I need
to encrypt stuff". It also serves as a demonstration on how to use the NaCl
library.

Installation
------------

```
go get github.com/xrstf/boxer
```

Usage
-----

```go
dataToEncrypt := "I am something to keep secret."
password := "sup3r s3cur3"

// encrypt
ciphertext, err := boxer.Encrypt([]byte(dataToEncrypt), []byte(password))
if err != nil {
	panic(err)
}

// and decrypt again
plaintext, err := boxer.Decrypt(ciphertext, []byte(password))
if err != nil {
	panic(err)
}

fmt.Println(plaintext)
```

License
-------

This code is licensed under the MIT license.

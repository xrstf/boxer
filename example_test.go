// Copyright (c) 2015, xrstf | MIT licensed

package boxer_test

import (
	"fmt"

	"github.com/xrstf/boxer"
)

func Example() {
	dataToEncrypt := "I am something to keep secret."
	password := "sup3r s3cur3"

	// create a Boxer with default scrypt settings
	bxr := boxer.NewDefaultBoxer()

	// encrypt data
	ciphertext, err := bxr.Encrypt([]byte(dataToEncrypt), []byte(password))
	if err != nil {
		panic(err)
	}

	// decrypt it again
	plaintext, err := bxr.Decrypt(ciphertext, []byte(password))
	if err != nil {
		panic(err)
	}

	fmt.Println(plaintext)
}

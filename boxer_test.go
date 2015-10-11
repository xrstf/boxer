// Copyright (c) 2015, xrstf | MIT licensed

package boxer_test

import (
	"fmt"

	"github.com/xrstf/boxer"
)

func ExampleEncrypt() {
	dataToEncrypt := "I am something to keep secret."
	password := "sup3r s3cur3"

	ciphertext, err := boxer.Encrypt([]byte(dataToEncrypt), []byte(password))
	if err != nil {
		panic(err)
	}

	// store ciphertext somewhere
	fmt.Printf("ciphertext = %x\n", ciphertext)
}

func ExampleDecrypt() {
	ciphertext := []byte{0xDE, 0xAD, 0xBE, 0xEF} // ciphertext from Encrypt()
	password := "sup3r s3cur3"

	plaintext, err := boxer.Decrypt(ciphertext, []byte(password))
	if err != nil {
		panic(err)
	}

	fmt.Println(plaintext)
}

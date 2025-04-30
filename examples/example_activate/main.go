package main

import (
	"fmt"

	"github.com/landru29/cryptolens-golang/cryptolens"
)

func main() {
	token := "WyI0NjUiLCJBWTBGTlQwZm9WV0FyVnZzMEV1Mm9LOHJmRDZ1SjF0Vk52WTU0VzB2Il0="
	publicKey := "<RSAKeyValue><Modulus>khbyu3/vAEBHi339fTuo2nUaQgSTBj0jvpt5xnLTTF35FLkGI+5Z3wiKfnvQiCLf+5s4r8JB/Uic/i6/iNjPMILlFeE0N6XZ+2pkgwRkfMOcx6eoewypTPUoPpzuAINJxJRpHym3V6ZJZ1UfYvzRcQBD/lBeAYrvhpCwukQMkGushKsOS6U+d+2C9ZNeP+U+uwuv/xu8YBCBAgGb8YdNojcGzM4SbCtwvJ0fuOfmCWZvUoiumfE4x7rAhp1pa9OEbUe0a5HL+1v7+JLBgkNZ7Z2biiHaM6za7GjHCXU8rojatEQER+MpgDuQV3ZPx8RKRdiJgPnz9ApBHFYDHLDzDw==</Modulus><Exponent>AQAB</Exponent></RSAKeyValue>"

	client, err := cryptolens.NewClient()
	if err != nil {
		fmt.Println("Cannot initialize client")
		return
	}

	licenseKey, err := client.KeyActivate(token, cryptolens.KeyActivateArguments{
		ProductId:   3646,
		Key:         "MPDWY-PQAOW-FKSCH-SGAAU",
		MachineCode: "289jf2afs3",
	})
	if err != nil || !licenseKey.HasValidSignature(publicKey) {
		fmt.Println("License key activation failed!")
		return
	}

	fmt.Printf("License key for product with id: %d\n", licenseKey.ProductId)

	if licenseKey.HasExpired() {
		fmt.Println("License key has expired")
		return
	}

	if licenseKey.F1 {
		fmt.Println("Welcome! Pro version enabled!")
	} else {
		fmt.Println("Welcome!")
	}
}

package main

import (
	"bufio"
	"fmt"
	"github.com/juliocesargba/cypher-chat/internal/cypher"
	"golang.org/x/term"
	"os"
	"syscall"
)

func main() {
	var option string
	s := bufio.NewScanner(os.Stdin)
	fmt.Println("1 - Symmetric\n2 - Asymmetric\n3 - Exit")
	s.Scan()
	option = s.Text()
	switch option {
	case "1":
		runSymmetric(s)
	case "2":
		runAsymmetric(s)
	case "3":
		fmt.Println("Bye")
	}
}

func runSymmetric(s *bufio.Scanner) {
	var option string
	var message string
	var c cypher.Cypher
	c = cypher.NewSymmetricCypher()
	fmt.Println("Inform the key to encrypt/decrypt data")
	key, err := term.ReadPassword(syscall.Stdin)
	if err != nil {
		os.Exit(1)
	}

	for {
		fmt.Println("1 - Encrypt message\n2 - Decrypt message\n3 - Exit")
		_, _ = fmt.Scanln(&option)
		switch option {
		case "1":
			fmt.Println("Inform plain message:")
			s.Scan()
			message = s.Text()
			encrypted, _ := c.Encrypt(string(key), message)
			fmt.Println("Encrypted Message")
			fmt.Println(encrypted)
		case "2":
			fmt.Println("Inform encrypted message:")
			s.Scan()
			message = s.Text()
			plain, _ := c.Decrypt(string(key), message)
			fmt.Println("Plain message")
			fmt.Println(plain)
		case "3":
			fmt.Println("Exiting, Thanks!!!!")
			return
		}
	}

}

func runAsymmetric(s *bufio.Scanner) {
	keys, err := cypher.NewKeyPair()
	if err != nil {
		panic("error while generate keys")
	}

	c := cypher.NewAsymmetricCypher(keys)

	var option string
	var message string
	for {
		fmt.Println("1 - Encrypt message\n2 - Decrypt message\n3 - Exit")
		_, _ = fmt.Scanln(&option)
		switch option {
		case "1":
			fmt.Println("Inform plain message:")
			s.Scan()
			message = s.Text()
			encrypted, _ := c.Encrypt(keys.PublicKey, message)
			fmt.Println("Encrypted Message")
			fmt.Println(encrypted)
		case "2":
			fmt.Println("Inform encrypted message:")
			s.Scan()
			message = s.Text()
			plain, _ := c.Decrypt(keys.PrivateKey, message)
			fmt.Println("Plain message")
			fmt.Println(plain)
		case "3":
			fmt.Println("Exiting, Thanks!!!!")
			return
		}
	}
}

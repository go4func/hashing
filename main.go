package main

import (
	"fmt"
	"time"

	"github.com/pkg/errors"
	"golang.org/x/crypto/bcrypt"
)

func main() {
	for {
		// get password
		raw, err := getInput("enter the password: ")
		if err != nil {
			panic(err)
		}

		// hash password
		hashed, err := bCrypt(raw, bcrypt.DefaultCost)
		if err != nil {
			panic(err)
		}
		// encode version of hashed password
		fmt.Printf("hashed password %s\n", hashed)

		// get password again for comparing
		raw, err = getInput("enter the password again: ")
		if err != nil {
			panic(err)
		}
		fmt.Printf("password match? %v\n\n", comparePasswords(hashed, raw))
	}

}

func getInput(text string) ([]byte, error) {
	fmt.Print(text)

	password := make([]byte, 0)
	_, err := fmt.Scan(&password)
	if err != nil {
		return nil, errors.Wrap(err, "failed to scan input")
	}

	return password, nil
}

func bCrypt(password []byte, cost int) ([]byte, error) {
	start := time.Now()
	defer func() {
		fmt.Printf("bcrypt with cost= %d finished in %v\n", cost, time.Since(start))
	}()

	hashed, err := bcrypt.GenerateFromPassword(password, cost)
	if err != nil {
		return nil, errors.Wrap(err, "failed to generate password")
	}

	return hashed, nil
}

func comparePasswords(hashed, raw []byte) bool {
	if err := bcrypt.CompareHashAndPassword(hashed, raw); err != nil {
		fmt.Println("passwords is not the same: ", err.Error())
		return false
	}
	return true
}

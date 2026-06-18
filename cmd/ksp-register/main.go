package main

import (
	"fmt"
	"os"
	"strings"

	"tpm-cert-proxy/internal/kspregister"
)

func main() {
	args := os.Args[1:]
	if len(args) == 0 {
		usage()
		os.Exit(1)
	}
	cmd := strings.ToLower(args[0])
	switch cmd {
	case "-register", "register":
		if err := kspregister.Register(); err != nil {
			fatal(err)
		}
		fmt.Println("Registered Fred Proxy Key Storage Provider.")
	case "-unregister", "unregister":
		if err := kspregister.Unregister(); err != nil {
			fatal(err)
		}
		fmt.Println("Unregistered Fred Proxy Key Storage Provider.")
	case "-enum", "enum":
		providers, err := kspregister.EnumProviders()
		if err != nil {
			fatal(err)
		}
		for _, p := range providers {
			fmt.Println(p)
		}
	default:
		usage()
		os.Exit(1)
	}
}

func usage() {
	fmt.Fprintf(os.Stderr, "Usage: ksp-register -register | -unregister | -enum\n")
}

func fatal(err error) {
	fmt.Fprintf(os.Stderr, "error: %v\n", err)
	os.Exit(1)
}

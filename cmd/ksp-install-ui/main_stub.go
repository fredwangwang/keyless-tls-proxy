//go:build !windows

package main

import (
	"fmt"
	"os"
)

func main() {
	fmt.Fprintf(os.Stderr, "ksp-install-ui is only supported on Windows.\n")
	os.Exit(1)
}

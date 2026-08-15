//go:build !windows

package main

import (
	"fmt"
	"os"
)

func main() {
	fmt.Fprintf(os.Stderr, "KeylessProxyKsp is only supported on Windows.\n")
	os.Exit(1)
}

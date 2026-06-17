//go:build !windows

package kspregister

import "fmt"

func Register() error {
	return fmt.Errorf("ksp-register requires Windows")
}

func Unregister() error {
	return fmt.Errorf("ksp-register requires Windows")
}

func EnumProviders() ([]string, error) {
	return nil, fmt.Errorf("ksp-register requires Windows")
}

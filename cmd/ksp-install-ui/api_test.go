//go:build windows

package main

import (
	"testing"
)

func TestTestSignValidation(t *testing.T) {
	api := NewAppAPI()

	// Missing thumbprint
	_, err := api.TestSign(TestSignRequest{
		Thumbprint: "",
		Message:    "Hello",
	})
	if err == nil {
		t.Errorf("expected error for empty thumbprint, got nil")
	}

	// Empty message
	_, err = api.TestSign(TestSignRequest{
		Thumbprint: "AABBCCDDEEFF00112233445566778899AABBCCDD",
		Message:    "",
		InputType:  "text",
	})
	if err == nil {
		t.Errorf("expected error for empty message, got nil")
	}

	// Invalid hex digest length
	_, err = api.TestSign(TestSignRequest{
		Thumbprint: "AABBCCDDEEFF00112233445566778899AABBCCDD",
		Message:    "abcd1234",
		InputType:  "hex",
		HashAlgo:   "SHA256",
	})
	if err == nil {
		t.Errorf("expected error for invalid hex length, got nil")
	}

	// Non-hex string
	_, err = api.TestSign(TestSignRequest{
		Thumbprint: "AABBCCDDEEFF00112233445566778899AABBCCDD",
		Message:    "not-a-valid-hex-string-zzzz",
		InputType:  "hex",
		HashAlgo:   "SHA256",
	})
	if err == nil {
		t.Errorf("expected error for invalid hex characters, got nil")
	}
}

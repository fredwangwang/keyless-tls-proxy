package main

import (
	"bufio"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"flag"
	"fmt"
	"os"
	"strconv"
	"strings"

	"github.com/fredwangwang/keyless-tls-proxy/internal/winstore"
)

func cleanThumbprint(tp string) string {
	tp = strings.ToUpper(strings.TrimSpace(tp))
	tp = strings.ReplaceAll(tp, ":", "")
	tp = strings.ReplaceAll(tp, " ", "")
	tp = strings.ReplaceAll(tp, "-", "")
	return tp
}

func selectCertificate(certs []winstore.WinCertInfo, targetThumbprint string, reader *bufio.Reader) (winstore.WinCertInfo, error) {
	if targetThumbprint != "" {
		cleaned := cleanThumbprint(targetThumbprint)
		var matches []winstore.WinCertInfo
		for _, c := range certs {
			if cleanThumbprint(c.Thumbprint) == cleaned {
				matches = append(matches, c)
			}
		}
		if len(matches) == 0 {
			for _, c := range certs {
				if strings.HasPrefix(cleanThumbprint(c.Thumbprint), cleaned) {
					matches = append(matches, c)
				}
			}
		}

		if len(matches) == 1 {
			fmt.Printf("Selected certificate: %s (%s)\n\n", matches[0].Subject, matches[0].Thumbprint)
			return matches[0], nil
		}
		if len(matches) > 1 {
			return winstore.WinCertInfo{}, fmt.Errorf("ambiguous thumbprint %q matched %d certificates", targetThumbprint, len(matches))
		}
		return winstore.WinCertInfo{}, fmt.Errorf("no certificate found matching thumbprint %q", targetThumbprint)
	}

	fmt.Println("Available certificates:")
	for i, c := range certs {
		tpm := "no"
		if c.IsTPM {
			tpm = "yes"
		}
		fmt.Printf(
			"  [%d] %s\n      subject: %s\n      key: %s %d-bit  tpm: %s  provider: %s\n",
			i+1,
			c.Thumbprint,
			c.Subject,
			c.KeyAlgorithm,
			c.KeySize,
			tpm,
			c.ProviderName,
		)
	}

	idx, err := readChoice(reader, len(certs))
	if err != nil {
		return winstore.WinCertInfo{}, err
	}
	return certs[idx], nil
}

func main() {
	message := flag.String("message", "", "message to hash and sign (prompts if empty)")
	padding := flag.String("padding", "", "RSA padding: pkcs1 or pss (prompts if empty)")
	thumbprint := flag.String("thumbprint", "", "certificate thumbprint (hex) to select (prompts if empty)")
	cert := flag.String("cert", "", "alias for -thumbprint")
	flag.Parse()

	targetThumbprint := *thumbprint
	if targetThumbprint == "" {
		targetThumbprint = *cert
	}

	certs, err := winstore.ListCertificates()
	if err != nil {
		fatal(err)
	}

	if len(certs) == 0 {
		fatal(fmt.Errorf("no certificates with private keys found in the Windows MY store"))
	}

	reader := bufio.NewReader(os.Stdin)
	selected, err := selectCertificate(certs, targetThumbprint, reader)
	if err != nil {
		fatal(err)
	}

	text := *message
	if text == "" {
		fmt.Print("Enter text to sign: ")
		text, err = reader.ReadString('\n')
		if err != nil {
			fatal(err)
		}
		text = strings.TrimSpace(text)
	}
	if text == "" {
		fatal(fmt.Errorf("message must not be empty"))
	}

	rsaPadding, err := resolvePadding(reader, *padding)
	if err != nil {
		fatal(err)
	}

	digest := sha256.Sum256([]byte(text))
	signResp, err := winstore.SignHash(
		selected.Thumbprint,
		digest[:],
		winstore.HashSHA256,
		rsaPadding,
	)
	if err != nil {
		fatal(err)
	}

	fmt.Println()
	fmt.Printf("Certificate: %s\n", selected.Subject)
	fmt.Printf("Digest (SHA-256): %s\n", hex.EncodeToString(digest[:]))

	var paddingStr string
	switch signResp.Padding {
	case winstore.RSAPaddingPKCS1:
		paddingStr = "PKCS1"
	case winstore.RSAPaddingPSS:
		paddingStr = "PSS"
	default:
		paddingStr = "UNSPECIFIED"
	}
	fmt.Printf("RSA padding: %s\n", paddingStr)
	fmt.Printf("Signature algorithm: %s\n", signResp.SignatureAlgorithm)
	fmt.Printf("Signature (base64): %s\n", base64.StdEncoding.EncodeToString(signResp.Signature))
	fmt.Printf("Signature (hex): %s\n", hex.EncodeToString(signResp.Signature))
}

func resolvePadding(reader *bufio.Reader, flagValue string) (winstore.RSAPadding, error) {
	value := strings.ToLower(strings.TrimSpace(flagValue))
	if value == "" {
		fmt.Print("RSA padding [pkcs1/pss] (default pkcs1): ")
		line, err := reader.ReadString('\n')
		if err != nil {
			return 0, err
		}
		value = strings.ToLower(strings.TrimSpace(line))
	}
	switch value {
	case "", "pkcs1", "pkcs1v15", "pkcs#1":
		return winstore.RSAPaddingPKCS1, nil
	case "pss", "rsapss", "rsa-pss":
		return winstore.RSAPaddingPSS, nil
	default:
		return 0, fmt.Errorf("padding must be pkcs1 or pss")
	}
}

func readChoice(reader *bufio.Reader, max int) (int, error) {
	for {
		fmt.Printf("Enter certificate number (1-%d): ", max)
		line, err := reader.ReadString('\n')
		if err != nil {
			return 0, err
		}
		n, err := strconv.Atoi(strings.TrimSpace(line))
		if err != nil || n < 1 || n > max {
			fmt.Println("Invalid selection, try again.")
			continue
		}
		return n - 1, nil
	}
}

func fatal(err error) {
	fmt.Fprintf(os.Stderr, "error: %v\n", err)
	os.Exit(1)
}

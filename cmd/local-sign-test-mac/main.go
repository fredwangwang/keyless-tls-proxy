//go:build darwin

package main

/*
#cgo LDFLAGS: -framework Security -framework CoreFoundation
#include <Security/Security.h>
#include <CoreFoundation/CoreFoundation.h>
#include <stdlib.h>
#include <stdio.h>

typedef struct {
    uint8_t *cert_data;
    size_t cert_len;
    SecIdentityRef identity;
    char key_type[32];
    int key_size;
} CertItem;

typedef struct {
    CertItem *items;
    int count;
} CertList;

static CertList get_mac_identities() {
    CertList res = {NULL, 0};
    CFMutableDictionaryRef query = CFDictionaryCreateMutable(kCFAllocatorDefault, 0, &kCFTypeDictionaryKeyCallBacks, &kCFTypeDictionaryValueCallBacks);
    CFDictionarySetValue(query, kSecClass, kSecClassIdentity);
    CFDictionarySetValue(query, kSecMatchLimit, kSecMatchLimitAll);
    CFDictionarySetValue(query, kSecReturnRef, kCFBooleanTrue);

    CFArrayRef result = NULL;
    OSStatus status = SecItemCopyMatching(query, (CFTypeRef *)&result);
    CFRelease(query);

    if (status != errSecSuccess || result == NULL) {
        return res;
    }

    CFIndex count = CFArrayGetCount(result);
    res.items = (CertItem *)calloc(count, sizeof(CertItem));
    res.count = 0;

    for (CFIndex i = 0; i < count; i++) {
        SecIdentityRef identity = (SecIdentityRef)CFArrayGetValueAtIndex(result, i);
        SecCertificateRef cert = NULL;
        if (SecIdentityCopyCertificate(identity, &cert) == errSecSuccess && cert != NULL) {
            CFDataRef data = SecCertificateCopyData(cert);
            if (data != NULL) {
                size_t len = CFDataGetLength(data);
                uint8_t *buf = (uint8_t *)malloc(len);
                CFDataGetBytes(data, CFRangeMake(0, len), buf);
                res.items[res.count].cert_data = buf;
                res.items[res.count].cert_len = len;
                CFRetain(identity);
                res.items[res.count].identity = identity;

                SecKeyRef pubKey = SecCertificateCopyKey(cert);
                if (pubKey != NULL) {
                    CFDictionaryRef attrs = SecKeyCopyAttributes(pubKey);
                    if (attrs != NULL) {
                        CFStringRef kType = (CFStringRef)CFDictionaryGetValue(attrs, kSecAttrKeyType);
                        if (kType != NULL) {
                            CFStringGetCString(kType, res.items[res.count].key_type, sizeof(res.items[res.count].key_type), kCFStringEncodingUTF8);
                        }
                        CFNumberRef kSize = (CFNumberRef)CFDictionaryGetValue(attrs, kSecAttrKeySizeInBits);
                        if (kSize != NULL) {
                            CFNumberGetValue(kSize, kCFNumberIntType, &res.items[res.count].key_size);
                        }
                        CFRelease(attrs);
                    }
                    CFRelease(pubKey);
                }

                res.count++;
                CFRelease(data);
            }
            CFRelease(cert);
        }
    }
    CFRelease(result);
    return res;
}

static uint8_t* sec_sign_hash(SecIdentityRef identity, const uint8_t *digest, size_t digestLen, int isPSS, size_t *outSigLen, char *errOut, size_t errMax) {
    SecKeyRef privKey = NULL;
    OSStatus status = SecIdentityCopyPrivateKey(identity, &privKey);
    if (status != errSecSuccess || privKey == NULL) {
        snprintf(errOut, errMax, "SecIdentityCopyPrivateKey failed with status %d", (int)status);
        return NULL;
    }

    SecKeyAlgorithm alg;
    SecKeyRef pubKey = SecKeyCopyPublicKey(privKey);
    CFStringRef keyType = NULL;
    if (pubKey != NULL) {
        CFDictionaryRef attrs = SecKeyCopyAttributes(pubKey);
        if (attrs != NULL) {
            keyType = (CFStringRef)CFDictionaryGetValue(attrs, kSecAttrKeyType);
            if (keyType != NULL) CFRetain(keyType);
            CFRelease(attrs);
        }
        CFRelease(pubKey);
    }

    if (keyType != NULL && CFEqual(keyType, kSecAttrKeyTypeECSECPrimeRandom)) {
        alg = kSecKeyAlgorithmECDSASignatureDigestX962SHA256;
    } else {
        if (isPSS) {
            alg = kSecKeyAlgorithmRSASignatureDigestPSSSHA256;
        } else {
            alg = kSecKeyAlgorithmRSASignatureDigestPKCS1v15SHA256;
        }
    }
    if (keyType != NULL) CFRelease(keyType);

    CFDataRef dataToSign = CFDataCreate(kCFAllocatorDefault, digest, digestLen);
    CFErrorRef error = NULL;
    CFDataRef sigData = SecKeyCreateSignature(privKey, alg, dataToSign, &error);
    CFRelease(dataToSign);
    CFRelease(privKey);

    if (sigData == NULL) {
        if (error != NULL) {
            CFStringRef desc = CFErrorCopyDescription(error);
            char buf[256];
            CFStringGetCString(desc, buf, sizeof(buf), kCFStringEncodingUTF8);
            snprintf(errOut, errMax, "SecKeyCreateSignature error: %s", buf);
            CFRelease(desc);
            CFRelease(error);
        } else {
            snprintf(errOut, errMax, "SecKeyCreateSignature returned NULL");
        }
        return NULL;
    }

    size_t sigLen = CFDataGetLength(sigData);
    uint8_t *sigBuf = (uint8_t *)malloc(sigLen);
    CFDataGetBytes(sigData, CFRangeMake(0, sigLen), sigBuf);
    CFRelease(sigData);
    *outSigLen = sigLen;
    return sigBuf;
}
*/
import "C"

import (
	"bufio"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/x509"
	"encoding/asn1"
	"encoding/base64"
	"encoding/hex"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"unsafe"
)

type RSAPadding int

const (
	RSAPaddingPKCS1 RSAPadding = iota
	RSAPaddingPSS
)

type MacCertInfo struct {
	Thumbprint     string // SHA-256 fingerprint in uppercase hex
	SHA1Thumbprint string // SHA-1 fingerprint in uppercase hex
	Subject        string
	KeyAlgorithm   string // "RSA" or "ECDSA"
	KeySize        int
	IsSmartCard    bool
	ProviderName   string
	IdentityRef    C.SecIdentityRef
}

type SCAuthIdentity struct {
	Hash      string // Uppercase SHA-1 hash from sc_auth
	Subject   string
	SmartCard string // SmartCard token identifier (if present)
}

func parseSCAuthIdentities() (map[string]SCAuthIdentity, error) {
	out, err := exec.Command("sc_auth", "identities").Output()
	if err != nil {
		return nil, err
	}

	result := make(map[string]SCAuthIdentity)
	lines := strings.Split(string(out), "\n")
	currentSmartCard := "CryptoTokenKit"

	for _, line := range lines {
		trimmed := strings.TrimSpace(line)
		if trimmed == "" {
			continue
		}
		if strings.HasPrefix(trimmed, "SmartCard:") {
			currentSmartCard = strings.TrimSpace(strings.TrimPrefix(trimmed, "SmartCard:"))
			continue
		}
		if strings.HasPrefix(trimmed, "Paired identities:") || strings.HasPrefix(trimmed, "Unpaired identities:") {
			continue
		}

		parts := strings.Fields(trimmed)
		if len(parts) >= 1 && len(parts[0]) == 40 {
			hash := strings.ToUpper(parts[0])
			subj := ""
			if len(parts) > 1 {
				subj = strings.Join(parts[1:], " ")
			}
			result[hash] = SCAuthIdentity{
				Hash:      hash,
				Subject:   subj,
				SmartCard: currentSmartCard,
			}
		}
	}

	return result, nil
}

type subjectPublicKeyInfo struct {
	Algorithm asn1.RawValue
	PublicKey asn1.BitString
}

func computePubKeySHA1(cert *x509.Certificate) string {
	var spki subjectPublicKeyInfo
	if _, err := asn1.Unmarshal(cert.RawSubjectPublicKeyInfo, &spki); err == nil && len(spki.PublicKey.Bytes) > 0 {
		h := sha1.Sum(spki.PublicKey.Bytes)
		return strings.ToUpper(hex.EncodeToString(h[:]))
	}
	return ""
}

func listCertificates() ([]MacCertInfo, error) {
	scIdentities, _ := parseSCAuthIdentities()

	cList := C.get_mac_identities()
	if cList.count == 0 {
		return nil, nil
	}

	rawItems := (*[1 << 20]C.CertItem)(unsafe.Pointer(cList.items))[:cList.count:cList.count]
	var certs []MacCertInfo

	for _, item := range rawItems {
		der := C.GoBytes(unsafe.Pointer(item.cert_data), C.int(item.cert_len))
		cert, err := x509.ParseCertificate(der)
		if err != nil {
			continue
		}

		thumb256Bytes := sha256.Sum256(der)
		thumb256 := hex.EncodeToString(thumb256Bytes[:])

		certSHA1Bytes := sha1.Sum(der)
		certSHA1 := strings.ToUpper(hex.EncodeToString(certSHA1Bytes[:]))

		spkiSHA1Bytes := sha1.Sum(cert.RawSubjectPublicKeyInfo)
		spkiSHA1 := strings.ToUpper(hex.EncodeToString(spkiSHA1Bytes[:]))

		subjKeyID := strings.ToUpper(hex.EncodeToString(cert.SubjectKeyId))
		pubKeySHA1 := computePubKeySHA1(cert)

		keyAlg := "RSA"
		keyTypeC := C.GoString(&item.key_type[0])
		if strings.Contains(strings.ToLower(keyTypeC), "ec") || cert.PublicKeyAlgorithm == x509.ECDSA {
			keyAlg = "ECDSA"
		}

		isSC := false
		provider := "macOS Keychain"

		if scIdentities != nil {
			checkHashes := []string{subjKeyID, pubKeySHA1, certSHA1, spkiSHA1}
			for _, h := range checkHashes {
				if h != "" {
					if sc, ok := scIdentities[h]; ok {
						isSC = true
						if sc.SmartCard != "" {
							provider = sc.SmartCard
						} else {
							provider = "CryptoTokenKit"
						}
						break
					}
				}
			}
		}

		certs = append(certs, MacCertInfo{
			Thumbprint:     strings.ToUpper(thumb256),
			SHA1Thumbprint: certSHA1,
			Subject:        cert.Subject.String(),
			KeyAlgorithm:   keyAlg,
			KeySize:        int(item.key_size),
			IsSmartCard:    isSC,
			ProviderName:   provider,
			IdentityRef:    item.identity,
		})
	}

	return certs, nil
}

func signHash(identity C.SecIdentityRef, digest []byte, padding RSAPadding) ([]byte, error) {
	isPSS := 0
	if padding == RSAPaddingPSS {
		isPSS = 1
	}

	var sigLen C.size_t
	var errBuf [512]C.char
	sigPtr := C.sec_sign_hash(
		identity,
		(*C.uint8_t)(unsafe.Pointer(&digest[0])),
		C.size_t(len(digest)),
		C.int(isPSS),
		&sigLen,
		&errBuf[0],
		512,
	)

	if sigPtr == nil {
		return nil, fmt.Errorf("%s", C.GoString(&errBuf[0]))
	}

	sig := C.GoBytes(unsafe.Pointer(sigPtr), C.int(sigLen))
	C.free(unsafe.Pointer(sigPtr))
	return sig, nil
}

func cleanThumbprint(tp string) string {
	tp = strings.ToUpper(strings.TrimSpace(tp))
	tp = strings.ReplaceAll(tp, ":", "")
	tp = strings.ReplaceAll(tp, " ", "")
	tp = strings.ReplaceAll(tp, "-", "")
	return tp
}

func selectCertificate(certs []MacCertInfo, targetThumbprint string, reader *bufio.Reader) (MacCertInfo, error) {
	if targetThumbprint != "" {
		cleaned := cleanThumbprint(targetThumbprint)
		var matches []MacCertInfo
		for _, c := range certs {
			if cleanThumbprint(c.Thumbprint) == cleaned || cleanThumbprint(c.SHA1Thumbprint) == cleaned {
				matches = append(matches, c)
			}
		}
		if len(matches) == 0 {
			for _, c := range certs {
				if strings.HasPrefix(cleanThumbprint(c.Thumbprint), cleaned) || strings.HasPrefix(cleanThumbprint(c.SHA1Thumbprint), cleaned) {
					matches = append(matches, c)
				}
			}
		}

		if len(matches) == 1 {
			fmt.Printf("Selected certificate: %s (%s)\n\n", matches[0].Subject, matches[0].Thumbprint)
			return matches[0], nil
		}
		if len(matches) > 1 {
			return MacCertInfo{}, fmt.Errorf("ambiguous thumbprint %q matched %d certificates", targetThumbprint, len(matches))
		}
		return MacCertInfo{}, fmt.Errorf("no certificate found matching thumbprint %q", targetThumbprint)
	}

	fmt.Println("Available certificates:")
	for i, c := range certs {
		sc := "no"
		if c.IsSmartCard {
			sc = "yes"
		}
		fmt.Printf(
			"  [%d] %s\n      subject: %s\n      key: %s %d-bit  smartcard: %s  provider: %s\n",
			i+1,
			c.Thumbprint,
			c.Subject,
			c.KeyAlgorithm,
			c.KeySize,
			sc,
			c.ProviderName,
		)
	}

	idx, err := readChoice(reader, len(certs))
	if err != nil {
		return MacCertInfo{}, err
	}
	return certs[idx], nil
}

func main() {
	message := flag.String("message", "", "message to hash and sign (prompts if empty)")
	padding := flag.String("padding", "", "RSA padding: pkcs1 or pss (prompts if empty)")
	thumbprint := flag.String("thumbprint", "", "certificate thumbprint (SHA-256 or SHA-1 hex) to select (prompts if empty)")
	cert := flag.String("cert", "", "alias for -thumbprint")
	flag.Parse()

	targetThumbprint := *thumbprint
	if targetThumbprint == "" {
		targetThumbprint = *cert
	}

	certs, err := listCertificates()
	if err != nil {
		fatal(err)
	}

	if len(certs) == 0 {
		fatal(fmt.Errorf("no certificates with private keys found in macOS Security framework"))
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

	var rsaPadding RSAPadding
	if selected.KeyAlgorithm == "RSA" {
		rsaPadding, err = resolvePadding(reader, *padding)
		if err != nil {
			fatal(err)
		}
	}

	digest := sha256.Sum256([]byte(text))
	signature, err := signHash(selected.IdentityRef, digest[:], rsaPadding)
	if err != nil {
		fatal(err)
	}

	fmt.Println()
	fmt.Printf("Certificate: %s\n", selected.Subject)
	fmt.Printf("Digest (SHA-256): %s\n", hex.EncodeToString(digest[:]))

	sigAlg := selected.KeyAlgorithm + "-SHA256"
	if selected.KeyAlgorithm == "RSA" {
		var paddingStr string
		switch rsaPadding {
		case RSAPaddingPKCS1:
			paddingStr = "PKCS1"
			sigAlg = "RSA-PKCS1v1.5-SHA256"
		case RSAPaddingPSS:
			paddingStr = "PSS"
			sigAlg = "RSA-PSS-SHA256"
		}
		fmt.Printf("RSA padding: %s\n", paddingStr)
	}

	fmt.Printf("Signature algorithm: %s\n", sigAlg)
	fmt.Printf("Signature (base64): %s\n", base64.StdEncoding.EncodeToString(signature))
	fmt.Printf("Signature (hex): %s\n", hex.EncodeToString(signature))
}

func resolvePadding(reader *bufio.Reader, flagValue string) (RSAPadding, error) {
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
		return RSAPaddingPKCS1, nil
	case "pss", "rsapss", "rsa-pss":
		return RSAPaddingPSS, nil
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

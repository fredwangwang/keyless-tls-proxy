//go:build darwin

package certstore

/*
#cgo LDFLAGS: -framework Security -framework CoreFoundation
#include <Security/Security.h>
#include <CoreFoundation/CoreFoundation.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>

typedef struct {
    uint8_t *cert_data;
    size_t cert_len;
    SecIdentityRef identity;
    char key_type[64];
    int key_size;
} MacCertItem;

typedef struct {
    MacCertItem *items;
    int count;
} MacCertList;

static MacCertList get_mac_identities() {
    MacCertList res = {NULL, 0};
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
    res.items = (MacCertItem *)calloc(count, sizeof(MacCertItem));
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

static void free_mac_cert_list(MacCertList *list) {
    if (!list || !list->items) return;
    for (int i = 0; i < list->count; i++) {
        if (list->items[i].cert_data) free(list->items[i].cert_data);
        if (list->items[i].identity) CFRelease(list->items[i].identity);
    }
    free(list->items);
    list->items = NULL;
    list->count = 0;
}

static uint8_t* mac_sign_hash(SecIdentityRef identity, const uint8_t *digest, size_t digestLen, int keyType, int hashAlg, int padding, size_t *outSigLen, char *errOut, size_t errMax) {
    SecKeyRef privKey = NULL;
    OSStatus status = SecIdentityCopyPrivateKey(identity, &privKey);
    if (status != errSecSuccess || privKey == NULL) {
        snprintf(errOut, errMax, "SecIdentityCopyPrivateKey failed with status %d", (int)status);
        return NULL;
    }

    SecKeyAlgorithm alg;
    if (keyType == 1) { // ECDSA
        switch (hashAlg) {
            case 1: alg = kSecKeyAlgorithmECDSASignatureDigestX962SHA256; break;
            case 2: alg = kSecKeyAlgorithmECDSASignatureDigestX962SHA384; break;
            case 3: alg = kSecKeyAlgorithmECDSASignatureDigestX962SHA512; break;
            default:
                CFRelease(privKey);
                snprintf(errOut, errMax, "unsupported hash algorithm for ECDSA");
                return NULL;
        }
    } else { // RSA
        if (padding == 2) { // PSS
            switch (hashAlg) {
                case 1: alg = kSecKeyAlgorithmRSASignatureDigestPSSSHA256; break;
                case 2: alg = kSecKeyAlgorithmRSASignatureDigestPSSSHA384; break;
                case 3: alg = kSecKeyAlgorithmRSASignatureDigestPSSSHA512; break;
                default:
                    CFRelease(privKey);
                    snprintf(errOut, errMax, "unsupported hash algorithm for RSA-PSS");
                    return NULL;
            }
        } else { // PKCS1
            switch (hashAlg) {
                case 1: alg = kSecKeyAlgorithmRSASignatureDigestPKCS1v15SHA256; break;
                case 2: alg = kSecKeyAlgorithmRSASignatureDigestPKCS1v15SHA384; break;
                case 3: alg = kSecKeyAlgorithmRSASignatureDigestPKCS1v15SHA512; break;
                default:
                    CFRelease(privKey);
                    snprintf(errOut, errMax, "unsupported hash algorithm for RSA-PKCS1");
                    return NULL;
            }
        }
    }

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
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"fmt"
	"os/exec"
	"strings"
	"unsafe"
)

type internalMacIdentity struct {
	info        CertificateInfo
	sha1        string
	sha256      string
	identityRef C.SecIdentityRef
}

type scAuthIdentity struct {
	Hash      string
	Subject   string
	SmartCard string
}

func parseSCAuthIdentities() map[string]scAuthIdentity {
	out, err := exec.Command("sc_auth", "identities").Output()
	if err != nil {
		return nil
	}

	result := make(map[string]scAuthIdentity)
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
			result[hash] = scAuthIdentity{
				Hash:      hash,
				Subject:   subj,
				SmartCard: currentSmartCard,
			}
		}
	}
	return result
}

func getMacIdentitiesInternal() ([]internalMacIdentity, func(), error) {
	cList := C.get_mac_identities()
	cleanup := func() {
		C.free_mac_cert_list(&cList)
	}

	if cList.count == 0 {
		return nil, cleanup, nil
	}

	scIdentities := parseSCAuthIdentities()
	rawItems := (*[1 << 20]C.MacCertItem)(unsafe.Pointer(cList.items))[:cList.count:cList.count]
	var results []internalMacIdentity

	for _, item := range rawItems {
		der := C.GoBytes(unsafe.Pointer(item.cert_data), C.int(item.cert_len))
		cert, err := x509.ParseCertificate(der)
		if err != nil {
			continue
		}

		certSHA1Sum := sha1.Sum(der)
		certSHA1 := strings.ToUpper(hex.EncodeToString(certSHA1Sum[:]))

		certSHA256Sum := sha256.Sum256(der)
		certSHA256 := strings.ToUpper(hex.EncodeToString(certSHA256Sum[:]))

		keyAlg, keySize := keyMetadata(cert)
		if keyAlg == "" {
			keyTypeC := C.GoString(&item.key_type[0])
			if strings.Contains(strings.ToLower(keyTypeC), "ec") {
				keyAlg = "ECDSA"
			} else {
				keyAlg = "RSA"
			}
			keySize = int(item.key_size)
		}

		isSmartCard := false
		providerName := "macOS Keychain"

		if scIdentities != nil {
			if sc, ok := scIdentities[certSHA1]; ok {
				isSmartCard = true
				if sc.SmartCard != "" {
					providerName = sc.SmartCard
				} else {
					providerName = "CryptoTokenKit"
				}
			}
		}

		info := CertificateInfo{
			Thumbprint:     certSHA1,
			Subject:        cert.Subject.String(),
			Issuer:         cert.Issuer.String(),
			NotBefore:      cert.NotBefore,
			NotAfter:       cert.NotAfter,
			KeyAlgorithm:   keyAlg,
			KeySize:        keySize,
			HasPrivateKey:  true,
			IsTPM:          isSmartCard,
			ProviderName:   providerName,
			CertificateDER: append([]byte(nil), der...),
		}

		results = append(results, internalMacIdentity{
			info:        info,
			sha1:        certSHA1,
			sha256:      certSHA256,
			identityRef: item.identity,
		})
	}

	return results, cleanup, nil
}

func ListCertificates() ([]CertificateInfo, error) {
	identities, cleanup, err := getMacIdentitiesInternal()
	if err != nil {
		return nil, err
	}
	defer cleanup()

	out := make([]CertificateInfo, 0, len(identities))
	for _, id := range identities {
		out = append(out, id.info)
	}
	return out, nil
}

func SignHash(thumbprint string, digest []byte, hash HashAlgorithm, padding RSAPadding) (*SignResult, error) {
	expectedLen, err := hash.DigestSize()
	if err != nil {
		return nil, err
	}
	if len(digest) != expectedLen {
		return nil, ErrInvalidDigest
	}
	if padding == 0 {
		padding = RSAPaddingPKCS1
	}

	identities, cleanup, err := getMacIdentitiesInternal()
	if err != nil {
		return nil, err
	}
	defer cleanup()

	target := cleanThumbprint(thumbprint)
	var matched *internalMacIdentity

	for i := range identities {
		if cleanThumbprint(identities[i].sha1) == target || cleanThumbprint(identities[i].sha256) == target {
			matched = &identities[i]
			break
		}
	}
	if matched == nil {
		for i := range identities {
			if strings.HasPrefix(cleanThumbprint(identities[i].sha1), target) || strings.HasPrefix(cleanThumbprint(identities[i].sha256), target) {
				matched = &identities[i]
				break
			}
		}
	}

	if matched == nil {
		return nil, ErrCertificateNotFound
	}

	keyTypeInt := 0
	sigAlg := ""

	switch matched.info.KeyAlgorithm {
	case "ECDSA":
		if padding == RSAPaddingPSS {
			return nil, ErrInvalidPadding
		}
		keyTypeInt = 1
		sigAlg = "ECDSA"
	case "RSA":
		keyTypeInt = 0
		if padding == RSAPaddingPSS {
			sigAlg = "RSASSA-PSS"
		} else {
			sigAlg = "RSASSA-PKCS1-v1_5"
		}
	default:
		return nil, fmt.Errorf("unsupported key algorithm %q", matched.info.KeyAlgorithm)
	}

	var sigLen C.size_t
	var errBuf [512]C.char
	sigPtr := C.mac_sign_hash(
		matched.identityRef,
		(*C.uint8_t)(unsafe.Pointer(&digest[0])),
		C.size_t(len(digest)),
		C.int(keyTypeInt),
		C.int(hash),
		C.int(padding),
		&sigLen,
		&errBuf[0],
		512,
	)

	if sigPtr == nil {
		return nil, fmt.Errorf("sign hash: %s", C.GoString(&errBuf[0]))
	}

	sig := C.GoBytes(unsafe.Pointer(sigPtr), C.int(sigLen))
	C.free(unsafe.Pointer(sigPtr))

	return &SignResult{
		Signature:          sig,
		SignatureAlgorithm: sigAlg,
		Padding:            padding,
	}, nil
}

func keyMetadata(cert *x509.Certificate) (string, int) {
	switch pub := cert.PublicKey.(type) {
	case *rsa.PublicKey:
		return "RSA", pub.N.BitLen()
	case *ecdsa.PublicKey:
		return "ECDSA", pub.Curve.Params().BitSize
	default:
		return cert.PublicKeyAlgorithm.String(), 0
	}
}

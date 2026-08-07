#import "TokenSession.h"
#import "Token.h"
#import <os/log.h>
#import <Security/Security.h>
#import <CommonCrypto/CommonDigest.h>

#include "libctkbridge.h"

static BOOL isKeyAlgorithm(TKTokenKeyAlgorithm *algorithm, SecKeyAlgorithm secAlgorithm) {
    if (!algorithm) return NO;
    if ([algorithm respondsToSelector:@selector(isAlgorithm:)]) {
        if ([algorithm isAlgorithm:secAlgorithm]) {
            return YES;
        }
    }
    if ([algorithm isEqual:(__bridge id)secAlgorithm]) {
        return YES;
    }
    return NO;
}

@implementation MacTokenSession

- (instancetype)initWithToken:(MacToken *)token {
    self = [super initWithToken:token];
    if (self) {
        _macToken = token;
    }
    return self;
}

- (BOOL)tokenSession:(TKTokenSession *)session supportsOperation:(TKTokenOperation)operation usingKey:(TKTokenObjectID)keyObjectID algorithm:(TKTokenKeyAlgorithm *)algorithm {
    if (operation == TKTokenOperationSignData) {
        return YES;
    }
    return NO;
}

- (NSData *)tokenSession:(TKTokenSession *)session signData:(NSData *)dataToSign usingKey:(TKTokenObjectID)keyObjectID algorithm:(TKTokenKeyAlgorithm *)algorithm error:(NSError **)error {
    os_log(OS_LOG_DEFAULT, "MacTokenSession signData called. Data length: %lu, alg description: %@",
           (unsigned long)dataToSign.length, algorithm.description);

    NSString *keyIDStr = [[NSString alloc] initWithData:keyObjectID encoding:NSUTF8StringEncoding];
    NSString *thumbprint = keyIDStr;
    if ([keyIDStr hasPrefix:@"key-"]) {
        thumbprint = [keyIDStr substringFromIndex:4];
    }
    if (!thumbprint) {
        if (error) {
            *error = [NSError errorWithDomain:TKErrorDomain code:TKErrorCodeBadParameter userInfo:nil];
        }
        return nil;
    }

    int hashAlg = 0;     // 1 = SHA256, 2 = SHA384, 3 = SHA512
    int rsaPadding = 1;  // 1 = PKCS1, 2 = PSS
    BOOL isMessage = NO;

    if (isKeyAlgorithm(algorithm, kSecKeyAlgorithmRSASignatureDigestPSSSHA256)) {
        rsaPadding = 2; hashAlg = 1; isMessage = NO;
    } else if (isKeyAlgorithm(algorithm, kSecKeyAlgorithmRSASignatureMessagePSSSHA256)) {
        rsaPadding = 2; hashAlg = 1; isMessage = YES;
    } else if (isKeyAlgorithm(algorithm, kSecKeyAlgorithmRSASignatureDigestPSSSHA384)) {
        rsaPadding = 2; hashAlg = 2; isMessage = NO;
    } else if (isKeyAlgorithm(algorithm, kSecKeyAlgorithmRSASignatureMessagePSSSHA384)) {
        rsaPadding = 2; hashAlg = 2; isMessage = YES;
    } else if (isKeyAlgorithm(algorithm, kSecKeyAlgorithmRSASignatureDigestPSSSHA512)) {
        rsaPadding = 2; hashAlg = 3; isMessage = NO;
    } else if (isKeyAlgorithm(algorithm, kSecKeyAlgorithmRSASignatureMessagePSSSHA512)) {
        rsaPadding = 2; hashAlg = 3; isMessage = YES;
    } else if (isKeyAlgorithm(algorithm, kSecKeyAlgorithmRSASignatureDigestPKCS1v15SHA256)) {
        rsaPadding = 1; hashAlg = 1; isMessage = NO;
    } else if (isKeyAlgorithm(algorithm, kSecKeyAlgorithmRSASignatureMessagePKCS1v15SHA256)) {
        rsaPadding = 1; hashAlg = 1; isMessage = YES;
    } else if (isKeyAlgorithm(algorithm, kSecKeyAlgorithmRSASignatureDigestPKCS1v15SHA384)) {
        rsaPadding = 1; hashAlg = 2; isMessage = NO;
    } else if (isKeyAlgorithm(algorithm, kSecKeyAlgorithmRSASignatureMessagePKCS1v15SHA384)) {
        rsaPadding = 1; hashAlg = 2; isMessage = YES;
    } else if (isKeyAlgorithm(algorithm, kSecKeyAlgorithmRSASignatureDigestPKCS1v15SHA512)) {
        rsaPadding = 1; hashAlg = 3; isMessage = NO;
    } else if (isKeyAlgorithm(algorithm, kSecKeyAlgorithmRSASignatureMessagePKCS1v15SHA512)) {
        rsaPadding = 1; hashAlg = 3; isMessage = YES;
    }

    // Standard ASN.1 DigestInfo headers:
    static const uint8_t kSHA256Prefix[] = {0x30, 0x31, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01, 0x05, 0x00, 0x04, 0x20};
    static const uint8_t kSHA384Prefix[] = {0x30, 0x41, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x02, 0x05, 0x00, 0x04, 0x30};
    static const uint8_t kSHA512Prefix[] = {0x30, 0x51, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x03, 0x05, 0x00, 0x04, 0x40};

    NSData *finalDigest = nil;

    // 1. Check for DigestInfo prefix (strip ASN.1 header if present)
    if (dataToSign.length == 51 && memcmp(dataToSign.bytes, kSHA256Prefix, sizeof(kSHA256Prefix)) == 0) {
        finalDigest = [dataToSign subdataWithRange:NSMakeRange(19, 32)];
        hashAlg = 1;
    } else if (dataToSign.length == 67 && memcmp(dataToSign.bytes, kSHA384Prefix, sizeof(kSHA384Prefix)) == 0) {
        finalDigest = [dataToSign subdataWithRange:NSMakeRange(19, 48)];
        hashAlg = 2;
    } else if (dataToSign.length == 83 && memcmp(dataToSign.bytes, kSHA512Prefix, sizeof(kSHA512Prefix)) == 0) {
        finalDigest = [dataToSign subdataWithRange:NSMakeRange(19, 64)];
        hashAlg = 3;
    }

    // 2. If no DigestInfo header matched:
    if (!finalDigest) {
        if (isMessage) {
            if (hashAlg == 0) hashAlg = 1;
            if (hashAlg == 1) {
                uint8_t hash[CC_SHA256_DIGEST_LENGTH];
                CC_SHA256(dataToSign.bytes, (CC_LONG)dataToSign.length, hash);
                finalDigest = [NSData dataWithBytes:hash length:CC_SHA256_DIGEST_LENGTH];
            } else if (hashAlg == 2) {
                uint8_t hash[CC_SHA384_DIGEST_LENGTH];
                CC_SHA384(dataToSign.bytes, (CC_LONG)dataToSign.length, hash);
                finalDigest = [NSData dataWithBytes:hash length:CC_SHA384_DIGEST_LENGTH];
            } else if (hashAlg == 3) {
                uint8_t hash[CC_SHA512_DIGEST_LENGTH];
                CC_SHA512(dataToSign.bytes, (CC_LONG)dataToSign.length, hash);
                finalDigest = [NSData dataWithBytes:hash length:CC_SHA512_DIGEST_LENGTH];
            }
        } else {
            // Digest / Raw mode
            if (dataToSign.length == 32) {
                finalDigest = dataToSign;
                if (hashAlg == 0) hashAlg = 1;
            } else if (dataToSign.length == 48) {
                finalDigest = dataToSign;
                if (hashAlg == 0) hashAlg = 2;
            } else if (dataToSign.length == 64) {
                finalDigest = dataToSign;
                if (hashAlg == 0) hashAlg = 3;
            } else {
                // Unknown length: hash it with selected or default hash algorithm (SHA256)
                if (hashAlg == 0) hashAlg = 1;
                if (hashAlg == 1) {
                    uint8_t hash[CC_SHA256_DIGEST_LENGTH];
                    CC_SHA256(dataToSign.bytes, (CC_LONG)dataToSign.length, hash);
                    finalDigest = [NSData dataWithBytes:hash length:CC_SHA256_DIGEST_LENGTH];
                } else if (hashAlg == 2) {
                    uint8_t hash[CC_SHA384_DIGEST_LENGTH];
                    CC_SHA384(dataToSign.bytes, (CC_LONG)dataToSign.length, hash);
                    finalDigest = [NSData dataWithBytes:hash length:CC_SHA384_DIGEST_LENGTH];
                } else if (hashAlg == 3) {
                    uint8_t hash[CC_SHA512_DIGEST_LENGTH];
                    CC_SHA512(dataToSign.bytes, (CC_LONG)dataToSign.length, hash);
                    finalDigest = [NSData dataWithBytes:hash length:CC_SHA512_DIGEST_LENGTH];
                }
            }
        }
    }

    if (hashAlg == 0) hashAlg = 1; // Fallback to SHA256

    os_log(OS_LOG_DEFAULT, "MacTokenSession signing with hashAlg=%d, rsaPadding=%d, digestLen=%lu",
           hashAlg, rsaPadding, (unsigned long)finalDigest.length);

    uint8_t sigBuf[1024];
    size_t sigLen = sizeof(sigBuf);

    int res = ctk_bridge_sign_hash(
        (char *)[thumbprint UTF8String],
        (uint8_t *)[finalDigest bytes],
        [finalDigest length],
        hashAlg,
        rsaPadding,
        sigBuf,
        &sigLen
    );

    if (res != 0) {
        os_log_error(OS_LOG_DEFAULT, "ctk_bridge_sign_hash failed with error %d", res);
        if (error) {
            *error = [NSError errorWithDomain:TKErrorDomain code:TKErrorCodeCommunicationError userInfo:nil];
        }
        return nil;
    }

    return [NSData dataWithBytes:sigBuf length:sigLen];
}

@end


#import "TokenSession.h"
#import "Token.h"
#import <os/log.h>
#import <Security/Security.h>

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
    os_log(OS_LOG_DEFAULT, "MacTokenSession signData called algorithm: %@", algorithm.description);

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

    int hashAlg = 1;     // SHA256 in certv1 (1 = SHA256, 2 = SHA384, 3 = SHA512)
    int rsaPadding = 1;  // PKCS1 in certv1 (1 = PKCS1, 2 = PSS)

    if (isKeyAlgorithm(algorithm, kSecKeyAlgorithmRSASignatureDigestPSSSHA256) ||
        isKeyAlgorithm(algorithm, kSecKeyAlgorithmRSASignatureMessagePSSSHA256)) {
        rsaPadding = 2; // PSS
        hashAlg = 1;
    } else if (isKeyAlgorithm(algorithm, kSecKeyAlgorithmRSASignatureDigestPSSSHA384) ||
               isKeyAlgorithm(algorithm, kSecKeyAlgorithmRSASignatureMessagePSSSHA384)) {
        rsaPadding = 2; // PSS
        hashAlg = 2;
    } else if (isKeyAlgorithm(algorithm, kSecKeyAlgorithmRSASignatureDigestPSSSHA512) ||
               isKeyAlgorithm(algorithm, kSecKeyAlgorithmRSASignatureMessagePSSSHA512)) {
        rsaPadding = 2; // PSS
        hashAlg = 3;
    } else if (isKeyAlgorithm(algorithm, kSecKeyAlgorithmRSASignatureDigestPKCS1v15SHA384) ||
               isKeyAlgorithm(algorithm, kSecKeyAlgorithmRSASignatureMessagePKCS1v15SHA384)) {
        rsaPadding = 1; // PKCS1
        hashAlg = 2;
    } else if (isKeyAlgorithm(algorithm, kSecKeyAlgorithmRSASignatureDigestPKCS1v15SHA512) ||
               isKeyAlgorithm(algorithm, kSecKeyAlgorithmRSASignatureMessagePKCS1v15SHA512)) {
        rsaPadding = 1; // PKCS1
        hashAlg = 3;
    }

    uint8_t sigBuf[1024];
    size_t sigLen = sizeof(sigBuf);

    int res = ctk_bridge_sign_hash(
        (char *)[thumbprint UTF8String],
        (uint8_t *)[dataToSign bytes],
        [dataToSign length],
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

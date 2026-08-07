#import "Token.h"
#import "TokenDriver.h"
#import "TokenSession.h"
#import <Security/Security.h>
#import <os/log.h>

#include "libctkbridge.h"

@implementation MacToken

- (nullable instancetype)initWithTokenDriver:(MacTokenDriver *)tokenDriver instanceID:(NSString *)instanceID error:(NSError **)error {
    self = [super initWithTokenDriver:(TKTokenDriver *)tokenDriver instanceID:instanceID];
    if (self) {
        NSMutableArray<TKTokenKeychainItem *> *items = [NSMutableArray array];
        int count = ctk_bridge_installed_count();
        os_log(OS_LOG_DEFAULT, "MacToken: discovered %d remote certificates", count);

        for (int i = 0; i < count; i++) {
            ctk_key_info info;
            memset(&info, 0, sizeof(info));
            if (ctk_bridge_get_installed(i, &info) != 0) {
                continue;
            }

            if (info.cert_der_len > 0 && info.cert_der != NULL) {
                NSData *certData = [NSData dataWithBytes:info.cert_der length:info.cert_der_len];
                SecCertificateRef certRef = SecCertificateCreateWithData(kCFAllocatorDefault, (__bridge CFDataRef)certData);
                if (certRef) {
                    NSString *tpStr = [NSString stringWithUTF8String:info.thumbprint];
                    NSString *subjStr = [NSString stringWithUTF8String:info.subject];
                    NSLog(@"MacToken processing cert thumbprint: %@, subject: %@", tpStr, subjStr);

                    NSData *certObjectID = [[NSString stringWithFormat:@"cert-%@", tpStr] dataUsingEncoding:NSUTF8StringEncoding];
                    NSData *keyObjectID  = [[NSString stringWithFormat:@"key-%@", tpStr] dataUsingEncoding:NSUTF8StringEncoding];
                    
                    TKTokenKeychainCertificate *certItem = [[TKTokenKeychainCertificate alloc] initWithCertificate:certRef objectID:certObjectID];
                    if (certItem) {
                        if (subjStr.length > 0) {
                            certItem.label = subjStr;
                        }
                        [items addObject:certItem];
                        NSLog(@"MacToken added certItem: %@", certItem);
                    }

                    TKTokenKeychainKey *keyItem = [[TKTokenKeychainKey alloc] initWithCertificate:certRef objectID:keyObjectID];
                    if (keyItem) {
                        if (subjStr.length > 0) {
                            keyItem.label = subjStr;
                        }
                        
                        SecKeyRef publicKey = SecCertificateCopyKey(certRef);
                        if (publicKey) {
                            NSDictionary *attrs = (__bridge_transfer NSDictionary *)SecKeyCopyAttributes(publicKey);
                            NSData *pubKeyHash = attrs[(__bridge NSString *)kSecAttrApplicationLabel];
                            NSLog(@"MacToken publicKey attrs: %@, pubKeyHash: %@", attrs, pubKeyHash);
                            if (pubKeyHash) {
                                keyItem.publicKeyHash = pubKeyHash;
                            }
                            CFRelease(publicKey);
                        }

                        keyItem.keyType = (__bridge NSString *)kSecAttrKeyTypeRSA;
                        keyItem.keySizeInBits = info.key_size > 0 ? info.key_size : 2048;
                        keyItem.canSign = YES;
                        keyItem.canDecrypt = NO;
                        keyItem.canPerformKeyExchange = NO;
                        keyItem.suitableForLogin = YES;
                        [items addObject:keyItem];
                        NSLog(@"MacToken added keyItem: %@", keyItem);
                    }

                    CFRelease(certRef);
                }
            }
            ctk_bridge_free_key_info(&info);
        }

        printf("MacToken created %ld keychain items (from %d certificates)\n", (long)items.count, count);
        [self.keychainContents fillWithItems:items];
    }
    return self;
}

- (TKTokenSession *)token:(TKToken *)token createSessionWithError:(NSError **)error {
    return [[MacTokenSession alloc] initWithToken:self];
}

@end

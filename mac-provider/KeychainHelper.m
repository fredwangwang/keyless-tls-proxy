#import "KeychainHelper.h"
#import <os/log.h>

NSString * const kKeychainService           = @"com.fredprx.keylessproxy";
NSString * const kKeychainAccountCA         = @"CACertificate";
NSString * const kKeychainAccountClientCert = @"ClientCertificate";
NSString * const kKeychainAccountClientKey  = @"ClientKey";

@implementation KeychainHelper

+ (NSMutableDictionary *)baseQueryForAccount:(NSString *)account accessGroup:(nullable NSString *)accessGroup {
    NSMutableDictionary *query = [NSMutableDictionary dictionaryWithDictionary:@{
        (__bridge id)kSecClass: (__bridge id)kSecClassGenericPassword,
        (__bridge id)kSecAttrService: kKeychainService,
        (__bridge id)kSecAttrAccount: account,
        (__bridge id)kSecUseDataProtectionKeychain: @YES,
    }];
    if (accessGroup.length > 0) {
        query[(__bridge id)kSecAttrAccessGroup] = accessGroup;
    }
    return query;
}

+ (BOOL)saveString:(NSString *)string forAccount:(NSString *)account accessGroup:(nullable NSString *)accessGroup error:(NSError * _Nullable * _Nullable)error {
    if (!string || string.length == 0) {
        return [self deleteForAccount:account accessGroup:accessGroup error:error];
    }

    NSData *data = [string dataUsingEncoding:NSUTF8StringEncoding];
    
    // Always delete any existing items both with and without accessGroup
    if (accessGroup.length > 0) {
        NSMutableDictionary *delWithGroup = [self baseQueryForAccount:account accessGroup:accessGroup];
        SecItemDelete((__bridge CFDictionaryRef)delWithGroup);
        NSMutableDictionary *delWithoutGroup = [self baseQueryForAccount:account accessGroup:nil];
        SecItemDelete((__bridge CFDictionaryRef)delWithoutGroup);
    } else {
        NSMutableDictionary *delWithoutGroup = [self baseQueryForAccount:account accessGroup:nil];
        SecItemDelete((__bridge CFDictionaryRef)delWithoutGroup);
    }

    NSMutableDictionary *addAttributes = [self baseQueryForAccount:account accessGroup:accessGroup];
    addAttributes[(__bridge id)kSecValueData] = data;
    addAttributes[(__bridge id)kSecAttrAccessible] = (__bridge id)kSecAttrAccessibleAfterFirstUnlock;

    OSStatus status = SecItemAdd((__bridge CFDictionaryRef)addAttributes, NULL);
    if (status != errSecSuccess && accessGroup.length > 0) {
        os_log_error(OS_LOG_DEFAULT, "KeychainHelper: SecItemAdd with accessGroup '%{public}@' returned %d. Retrying without accessGroup.", accessGroup, (int)status);
        NSMutableDictionary *fallbackAdd = [self baseQueryForAccount:account accessGroup:nil];
        fallbackAdd[(__bridge id)kSecValueData] = data;
        fallbackAdd[(__bridge id)kSecAttrAccessible] = (__bridge id)kSecAttrAccessibleAfterFirstUnlock;
        status = SecItemAdd((__bridge CFDictionaryRef)fallbackAdd, NULL);
    }

    if (status != errSecSuccess) {
        NSString *errDesc = (__bridge_transfer NSString *)SecCopyErrorMessageString(status, NULL);
        os_log_error(OS_LOG_DEFAULT, "KeychainHelper: Failed to save '%{public}@' to Keychain (code %d: %{public}@)", account, (int)status, errDesc ?: @"Unknown error");
        if (error) {
            *error = [NSError errorWithDomain:NSOSStatusErrorDomain code:status userInfo:@{
                NSLocalizedDescriptionKey: [NSString stringWithFormat:@"Failed to save %@ to Keychain: %@ (code %d)", account, errDesc ?: @"Unknown error", (int)status]
            }];
        }
        return NO;
    }

    return YES;
}

+ (nullable NSString *)loadStringForAccount:(NSString *)account accessGroup:(nullable NSString *)accessGroup error:(NSError * _Nullable * _Nullable)error {
    NSMutableDictionary *query = [self baseQueryForAccount:account accessGroup:accessGroup];
    query[(__bridge id)kSecReturnData] = @YES;
    query[(__bridge id)kSecMatchLimit] = (__bridge id)kSecMatchLimitOne;

    CFTypeRef result = NULL;
    OSStatus status = SecItemCopyMatching((__bridge CFDictionaryRef)query, &result);

    if (status == errSecItemNotFound && accessGroup.length > 0) {
        NSMutableDictionary *fallbackQuery = [self baseQueryForAccount:account accessGroup:nil];
        fallbackQuery[(__bridge id)kSecReturnData] = @YES;
        fallbackQuery[(__bridge id)kSecMatchLimit] = (__bridge id)kSecMatchLimitOne;
        status = SecItemCopyMatching((__bridge CFDictionaryRef)fallbackQuery, &result);
    }

    if (status == errSecItemNotFound) {
        NSMutableDictionary *legacyQuery = [NSMutableDictionary dictionaryWithDictionary:@{
            (__bridge id)kSecClass: (__bridge id)kSecClassGenericPassword,
            (__bridge id)kSecAttrService: kKeychainService,
            (__bridge id)kSecAttrAccount: account,
            (__bridge id)kSecReturnData: @YES,
            (__bridge id)kSecMatchLimit: (__bridge id)kSecMatchLimitOne
        }];
        status = SecItemCopyMatching((__bridge CFDictionaryRef)legacyQuery, &result);
    }

    if (status != errSecSuccess) {
        if (status != errSecItemNotFound) {
            NSString *errDesc = (__bridge_transfer NSString *)SecCopyErrorMessageString(status, NULL);
            os_log_error(OS_LOG_DEFAULT, "KeychainHelper: Failed to load '%{public}@' from Keychain (code %d: %{public}@)", account, (int)status, errDesc ?: @"Unknown error");
            if (error) {
                *error = [NSError errorWithDomain:NSOSStatusErrorDomain code:status userInfo:@{
                    NSLocalizedDescriptionKey: [NSString stringWithFormat:@"Failed to load %@ from Keychain: %@ (code %d)", account, errDesc ?: @"Unknown error", (int)status]
                }];
            }
        }
        return nil;
    }

    NSData *data = (__bridge_transfer NSData *)result;
    if (!data || data.length == 0) {
        return @"";
    }

    return [[NSString alloc] initWithData:data encoding:NSUTF8StringEncoding];
}

+ (BOOL)deleteForAccount:(NSString *)account accessGroup:(nullable NSString *)accessGroup error:(NSError * _Nullable * _Nullable)error {
    NSMutableDictionary *query = [self baseQueryForAccount:account accessGroup:accessGroup];
    OSStatus status = SecItemDelete((__bridge CFDictionaryRef)query);

    if (status != errSecSuccess && status != errSecItemNotFound && accessGroup.length > 0) {
        NSMutableDictionary *fallbackQuery = [self baseQueryForAccount:account accessGroup:nil];
        status = SecItemDelete((__bridge CFDictionaryRef)fallbackQuery);
    }

    if (status != errSecSuccess && status != errSecItemNotFound) {
        NSString *errDesc = (__bridge_transfer NSString *)SecCopyErrorMessageString(status, NULL);
        if (error) {
            *error = [NSError errorWithDomain:NSOSStatusErrorDomain code:status userInfo:@{
                NSLocalizedDescriptionKey: [NSString stringWithFormat:@"Failed to delete %@ from Keychain: %@ (code %d)", account, errDesc ?: @"Unknown error", (int)status]
            }];
        }
        return NO;
    }

    return YES;
}

+ (BOOL)saveCACert:(NSString *)ca clientCert:(NSString *)cert clientKey:(NSString *)key accessGroup:(nullable NSString *)accessGroup error:(NSError * _Nullable * _Nullable)error {
    if (![self saveString:ca forAccount:kKeychainAccountCA accessGroup:accessGroup error:error]) {
        return NO;
    }
    if (![self saveString:cert forAccount:kKeychainAccountClientCert accessGroup:accessGroup error:error]) {
        return NO;
    }
    if (![self saveString:key forAccount:kKeychainAccountClientKey accessGroup:accessGroup error:error]) {
        return NO;
    }
    return YES;
}

+ (BOOL)loadCACert:(NSString * _Nullable * _Nullable)ca clientCert:(NSString * _Nullable * _Nullable)cert clientKey:(NSString * _Nullable * _Nullable)key accessGroup:(nullable NSString *)accessGroup error:(NSError * _Nullable * _Nullable)error {
    NSString *loadedCA   = [self loadStringForAccount:kKeychainAccountCA accessGroup:accessGroup error:error];
    NSString *loadedCert = [self loadStringForAccount:kKeychainAccountClientCert accessGroup:accessGroup error:error];
    NSString *loadedKey  = [self loadStringForAccount:kKeychainAccountClientKey accessGroup:accessGroup error:error];

    if (ca)   *ca   = loadedCA ?: @"";
    if (cert) *cert = loadedCert ?: @"";
    if (key)  *key  = loadedKey ?: @"";

    return (loadedCA.length > 0 && loadedCert.length > 0 && loadedKey.length > 0);
}

+ (BOOL)deleteCredentialsWithAccessGroup:(nullable NSString *)accessGroup error:(NSError * _Nullable * _Nullable)error {
    BOOL ok = YES;
    if (![self deleteForAccount:kKeychainAccountCA accessGroup:accessGroup error:error]) ok = NO;
    if (![self deleteForAccount:kKeychainAccountClientCert accessGroup:accessGroup error:error]) ok = NO;
    if (![self deleteForAccount:kKeychainAccountClientKey accessGroup:accessGroup error:error]) ok = NO;
    return ok;
}

@end

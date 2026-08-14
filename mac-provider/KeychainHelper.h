#import <Foundation/Foundation.h>
#import <Security/Security.h>

NS_ASSUME_NONNULL_BEGIN

extern NSString * const kKeychainService;
extern NSString * const kKeychainAccountCA;
extern NSString * const kKeychainAccountClientCert;
extern NSString * const kKeychainAccountClientKey;

@interface KeychainHelper : NSObject

+ (BOOL)saveString:(NSString *)string forAccount:(NSString *)account accessGroup:(nullable NSString *)accessGroup error:(NSError * _Nullable * _Nullable)error;

+ (nullable NSString *)loadStringForAccount:(NSString *)account accessGroup:(nullable NSString *)accessGroup error:(NSError * _Nullable * _Nullable)error;

+ (BOOL)deleteForAccount:(NSString *)account accessGroup:(nullable NSString *)accessGroup error:(NSError * _Nullable * _Nullable)error;

+ (BOOL)saveCACert:(NSString *)ca clientCert:(NSString *)cert clientKey:(NSString *)key accessGroup:(nullable NSString *)accessGroup error:(NSError * _Nullable * _Nullable)error;

+ (BOOL)loadCACert:(NSString * _Nullable * _Nullable)ca clientCert:(NSString * _Nullable * _Nullable)cert clientKey:(NSString * _Nullable * _Nullable)key accessGroup:(nullable NSString *)accessGroup error:(NSError * _Nullable * _Nullable)error;

+ (BOOL)deleteCredentialsWithAccessGroup:(nullable NSString *)accessGroup error:(NSError * _Nullable * _Nullable)error;

@end

NS_ASSUME_NONNULL_END

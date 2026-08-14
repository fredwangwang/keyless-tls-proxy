#import "TokenDriver.h"
#import "Token.h"
#import "KeychainHelper.h"
#import <os/log.h>
#include "libctkbridge.h"

static NSString *getAppGroupID(void) {
    static NSString *cachedAppGroupID = nil;
    static dispatch_once_t onceToken;
    dispatch_once(&onceToken, ^{
        NSBundle *bundle = [NSBundle bundleForClass:[MacTokenDriver class]];
        cachedAppGroupID = [bundle objectForInfoDictionaryKey:@"AppGroupID"];
        if (!cachedAppGroupID || cachedAppGroupID.length == 0) {
            cachedAppGroupID = [[NSBundle mainBundle] objectForInfoDictionaryKey:@"AppGroupID"];
        }
    });
    return cachedAppGroupID;
}

static void initBridgeIfNeeded(void) {
    static dispatch_once_t onceToken;
    dispatch_once(&onceToken, ^{
        NSString *appGroupID = getAppGroupID();
        NSUserDefaults *defaults = nil;
        if (appGroupID.length > 0) {
            defaults = [[NSUserDefaults alloc] initWithSuiteName:appGroupID];
        }

        NSString *addr = [defaults stringForKey:@"serverAddr"] ?: [defaults stringForKey:@"ServerAddress"];
        
        NSString *ca = nil;
        NSString *cert = nil;
        NSString *key = nil;
        
        NSError *keychainErr = nil;
        [KeychainHelper loadCACert:&ca clientCert:&cert clientKey:&key accessGroup:appGroupID error:&keychainErr];
        
        // Fallback to legacy NSUserDefaults if not found in Keychain
        if (ca.length == 0)   ca   = [defaults stringForKey:@"caContent"]   ?: [defaults stringForKey:@"caPath"];
        if (cert.length == 0) cert = [defaults stringForKey:@"certContent"] ?: [defaults stringForKey:@"certPath"];
        if (key.length == 0)  key  = [defaults stringForKey:@"keyContent"]  ?: [defaults stringForKey:@"keyPath"];

        if (addr.length == 0 || ca.length == 0 || cert.length == 0 || key.length == 0) {
            os_log_error(OS_LOG_DEFAULT, "MacTokenDriver error: missing shared configuration in App Group (%{public}@) / Keychain. addr: %{public}@, ca len: %lu, cert len: %lu, key len: %lu",
                         appGroupID ?: @"nil", addr ?: @"nil", (unsigned long)ca.length, (unsigned long)cert.length, (unsigned long)key.length);
        } else {
            os_log(OS_LOG_DEFAULT, "MacTokenDriver initializing ctk bridge with Keychain config from App Group (%{public}@), server: %{public}@", appGroupID, addr);
            int res = ctk_bridge_init_opts((char *)addr.UTF8String, (char *)ca.UTF8String, (char *)cert.UTF8String, (char *)key.UTF8String);
            os_log(OS_LOG_DEFAULT, "MacTokenDriver ctk_bridge_init_opts res: %d", res);
        }
    });
}

@implementation MacTokenDriver

- (instancetype)init {
    if (self = [super init]) {
        self.delegate = self;
        initBridgeIfNeeded();
    }
    return self;
}

- (void)beginRequestWithExtensionContext:(NSExtensionContext *)context {
}

- (TKToken *)tokenDriver:(TKTokenDriver *)driver tokenForConfiguration:(TKTokenConfiguration *)configuration error:(NSError **)error {
    initBridgeIfNeeded();
    return [[MacToken alloc] initWithTokenDriver:self instanceID:configuration.instanceID error:error];
}

@end


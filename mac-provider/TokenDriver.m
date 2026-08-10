#import "TokenDriver.h"
#import "Token.h"
#import <os/log.h>
#include "libctkbridge.h"

static void initBridgeIfNeeded(void) {
    static dispatch_once_t onceToken;
    dispatch_once(&onceToken, ^{
        NSBundle *bundle = [NSBundle bundleForClass:[MacTokenDriver class]];
        NSString *ca = [bundle pathForResource:@"ca" ofType:@"crt" inDirectory:@"certs"];
        NSString *cert = [bundle pathForResource:@"client" ofType:@"crt" inDirectory:@"certs"];
        NSString *key = [bundle pathForResource:@"client" ofType:@"key" inDirectory:@"certs"];
        
        if (!ca || !cert || !key) {
            os_log_error(OS_LOG_DEFAULT, "MacTokenDriver error: missing certificate file(s) in bundle certs/ (ca: %@, cert: %@, key: %@)", ca, cert, key);
        } else {
            os_log(OS_LOG_DEFAULT, "MacTokenDriver initializing ctk bridge with CA: %@, cert: %@, key: %@", ca, cert, key);
            int res = ctk_bridge_init_opts("192.168.0.133:50051", (char *)ca.UTF8String, (char *)cert.UTF8String, (char *)key.UTF8String);
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


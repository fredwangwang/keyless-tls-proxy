#import <Foundation/Foundation.h>
#import <CryptoTokenKit/CryptoTokenKit.h>
#include "libctkbridge.h"

extern int NSExtensionMain(int argc, const char *argv[]);

int main(int argc, const char * argv[]) {
    @autoreleasepool {
        NSBundle *bundle = [NSBundle mainBundle];
        NSString *ca = [bundle pathForResource:@"ca" ofType:@"crt" inDirectory:@"certs"];
        NSString *cert = [bundle pathForResource:@"client" ofType:@"crt" inDirectory:@"certs"];
        NSString *key = [bundle pathForResource:@"client" ofType:@"key" inDirectory:@"certs"];
        
        if (!ca || !cert || !key) {
            NSString *workspaceCertPath = @"/Users/huan/workspace/winksp-proxy/certs";
            ca = [workspaceCertPath stringByAppendingPathComponent:@"ca.crt"];
            cert = [workspaceCertPath stringByAppendingPathComponent:@"client.crt"];
            key = [workspaceCertPath stringByAppendingPathComponent:@"client.key"];
        }
        
        NSLog(@"ExtensionMain initializing ctk bridge with CA: %@, cert: %@, key: %@", ca, cert, key);
        int res = ctk_bridge_init_opts("192.168.0.133:50051", (char *)ca.UTF8String, (char *)cert.UTF8String, (char *)key.UTF8String);
        NSLog(@"ctk_bridge_init_opts res: %d", res);
    }
    return NSExtensionMain(argc, argv);
}

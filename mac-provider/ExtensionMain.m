#import <Foundation/Foundation.h>
#import <CryptoTokenKit/CryptoTokenKit.h>
#include "libctkbridge.h"

extern int NSExtensionMain(int argc, const char *argv[]);

static void readSettingsFromAppGroup(void) {
    NSString *appGroupID = @"8Z93635RW6.com.fredprx.mactoken.shareddata";
    NSURL *groupContainerURL = [[NSFileManager defaultManager] containerURLForSecurityApplicationGroupIdentifier:appGroupID];
    
    if (!groupContainerURL) {
        NSLog(@"ExtensionMain error: Failed to obtain container URL for App Group identifier '%@'. Verify sandbox and entitlement settings.", appGroupID);
        return;
    }

    NSURL *plistURL = [groupContainerURL URLByAppendingPathComponent:@"settings.plist"];
    NSError *error = nil;
    NSDictionary *settings = [NSDictionary dictionaryWithContentsOfURL:plistURL error:&error];
    if (settings) {
        NSString *lastUpdated = settings[@"LastUpdated"];
        NSLog(@"ExtensionMain: Read settings.plist from App Group container. LastUpdated: %@", lastUpdated);
    } else {
        NSLog(@"ExtensionMain error: Failed to read settings plist from %@: %@", plistURL.path, error ? error.localizedDescription : @"Unknown error");
    }
}

int main(int argc, const char * argv[]) {
    @autoreleasepool {
        readSettingsFromAppGroup();

        NSBundle *bundle = [NSBundle mainBundle];
        NSString *ca = [bundle pathForResource:@"ca" ofType:@"crt" inDirectory:@"certs"];
        NSString *cert = [bundle pathForResource:@"client" ofType:@"crt" inDirectory:@"certs"];
        NSString *key = [bundle pathForResource:@"client" ofType:@"key" inDirectory:@"certs"];
        
        if (!ca || !cert || !key) {
            NSLog(@"ExtensionMain error: missing certificate file(s) in bundle certs/ (ca: %@, cert: %@, key: %@)", ca, cert, key);
        } else {
            NSLog(@"ExtensionMain initializing ctk bridge with CA: %@, cert: %@, key: %@", ca, cert, key);
            int res = ctk_bridge_init_opts("192.168.0.133:50051", (char *)ca.UTF8String, (char *)cert.UTF8String, (char *)key.UTF8String);
            NSLog(@"ctk_bridge_init_opts res: %d", res);
        }
    }
    return NSExtensionMain(argc, argv);
}


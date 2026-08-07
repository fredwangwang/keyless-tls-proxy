#import <Cocoa/Cocoa.h>
#import <CryptoTokenKit/CryptoTokenKit.h>
#include "libctkbridge.h"

static NSArray<TKTokenKeychainItem *> *fetchKeychainItemsFromBridge(void) {
    NSMutableArray<TKTokenKeychainItem *> *items = [NSMutableArray array];
    int count = ctk_bridge_installed_count();
    NSLog(@"AppMain: discovered %d remote certificates", count);

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
                
                NSData *certObjectID = [[NSString stringWithFormat:@"cert-%@", tpStr] dataUsingEncoding:NSUTF8StringEncoding];
                NSData *keyObjectID  = [[NSString stringWithFormat:@"key-%@", tpStr] dataUsingEncoding:NSUTF8StringEncoding];
                
                TKTokenKeychainCertificate *certItem = [[TKTokenKeychainCertificate alloc] initWithCertificate:certRef objectID:certObjectID];
                if (certItem) {
                    if (subjStr.length > 0) {
                        certItem.label = subjStr;
                    }
                    [items addObject:certItem];
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
                }

                CFRelease(certRef);
            }
        }
        ctk_bridge_free_key_info(&info);
    }
    return items;
}

@interface AppDelegate : NSObject <NSApplicationDelegate>
@property (strong) NSWindow *window;
@end

@implementation AppDelegate

- (void)applicationDidFinishLaunching:(NSNotification *)aNotification {
    NSRect frame = NSMakeRect(100, 100, 520, 200);
    NSUInteger style = NSWindowStyleMaskTitled | NSWindowStyleMaskClosable | NSWindowStyleMaskMiniaturizable;
    self.window = [[NSWindow alloc] initWithContentRect:frame styleMask:style backing:NSBackingStoreBuffered defer:NO];
    [self.window setTitle:@"TPM Cert Proxy - MacToken Provider"];
    
    NSTextField *label = [[NSTextField alloc] initWithFrame:NSMakeRect(20, 100, 480, 40)];
    [label setStringValue:@"MacToken CryptoTokenKit Provider Registered & Active!"];
    [label setEditable:NO];
    [label setBordered:NO];
    [label setDrawsBackground:NO];
    [label setAlignment:NSTextAlignmentCenter];
    [label setFont:[NSFont systemFontOfSize:15 weight:NSFontWeightBold]];
    [[self.window contentView] addSubview:label];

    NSTextField *sublabel = [[NSTextField alloc] initWithFrame:NSMakeRect(20, 50, 480, 40)];
    [sublabel setStringValue:@"Available for Chrome, Safari, and macOS system client authentication."];
    [sublabel setEditable:NO];
    [sublabel setBordered:NO];
    [sublabel setDrawsBackground:NO];
    [sublabel setAlignment:NSTextAlignmentCenter];
    [sublabel setFont:[NSFont systemFontOfSize:12 weight:NSFontWeightRegular]];
    [[self.window contentView] addSubview:sublabel];
    
    [self.window center];
    [self.window makeKeyAndOrderFront:nil];
    [NSApp activateIgnoringOtherApps:YES];
    
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
    
    NSLog(@"AppMain initializing ctk bridge with CA: %@, cert: %@, key: %@", ca, cert, key);
    int initRes = ctk_bridge_init_opts("192.168.0.133:50051", (char *)ca.UTF8String, (char *)cert.UTF8String, (char *)key.UTF8String);
    NSLog(@"AppMain ctk_bridge_init_opts res: %d", initRes);

    NSString *classID = @"com.fredprx.mactoken.app.extension";
    NSDictionary<NSString *, TKTokenDriverConfiguration *> *configs = [TKTokenDriverConfiguration driverConfigurations];
    NSLog(@"TKTokenDriverConfiguration driverConfigurations: %@", configs);
    TKTokenDriverConfiguration *driverConfig = configs[classID];
    if (driverConfig) {
        NSLog(@"Found driverConfig for classID %@", classID);
        TKTokenConfiguration *tokenConfig = driverConfig.tokenConfigurations[@"CertServerToken"];
        if (!tokenConfig) {
            tokenConfig = [driverConfig addTokenConfigurationForTokenInstanceID:@"CertServerToken"];
            NSLog(@"Added tokenConfig for CertServerToken: %@", tokenConfig);
        }
        NSArray<TKTokenKeychainItem *> *items = fetchKeychainItemsFromBridge();
        tokenConfig.keychainItems = items;
        NSLog(@"AppMain set %ld keychainItems on tokenConfig", (long)items.count);
        printf("AppMain set %ld keychainItems on tokenConfig\n", (long)items.count);
    } else {
        NSLog(@"driverConfig is NIL for classID %@", classID);
        printf("driverConfig is NIL for classID %s\n", classID.UTF8String);
    }
}

- (BOOL)applicationShouldTerminateAfterLastWindowClosed:(NSApplication *)sender {
    return YES;
}

@end

int main(int argc, const char * argv[]) {
    @autoreleasepool {
        NSApplication *app = [NSApplication sharedApplication];
        AppDelegate *delegate = [[AppDelegate alloc] init];
        [app setDelegate:delegate];
        [app run];
    }
    return 0;
}

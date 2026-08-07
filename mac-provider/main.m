#import <Foundation/Foundation.h>
#import <CryptoTokenKit/CryptoTokenKit.h>
#import "TokenDriver.h"
#import "Token.h"
#import "TokenSession.h"
#include "libctkbridge.h"

int main(int argc, const char * argv[]) {
    @autoreleasepool {
        char *addr = "192.168.0.133:50051";
        char *ca = "certs/ca.crt";
        char *cert = "certs/client.crt";
        char *key = "certs/client.key";

        if (argc >= 5) {
            addr = (char *)argv[1];
            ca = (char *)argv[2];
            cert = (char *)argv[3];
            key = (char *)argv[4];
        }

        printf("Initializing Mac CTK Provider connecting to %s...\n", addr);
        int res = ctk_bridge_init_opts(addr, ca, cert, key);
        if (res != 0) {
            fprintf(stderr, "Failed to initialize gRPC bridge to %s (code: %d)\n", addr, res);
            return 1;
        }

        int count = ctk_bridge_installed_count();
        printf("Connected successfully! Found %d certificates on server %s:\n", count, addr);

        for (int i = 0; i < count; i++) {
            ctk_key_info info;
            memset(&info, 0, sizeof(info));
            if (ctk_bridge_get_installed(i, &info) == 0) {
                printf(" [%d] Thumbprint: %s\n     Subject: %s\n     Algorithm: %s %d-bit (DER size: %zu bytes)\n",
                       i + 1, info.thumbprint, info.subject, info.key_algorithm, info.key_size, info.cert_der_len);
                ctk_bridge_free_key_info(&info);
            }
        }

        // Test creating the CryptoTokenKit driver & token objects
        MacTokenDriver *driver = [[MacTokenDriver alloc] init];
        NSError *error = nil;
        MacToken *token = [[MacToken alloc] initWithTokenDriver:driver instanceID:@"CertServerToken" error:&error];
        if (!token) {
            fprintf(stderr, "Failed to instantiate MacToken: %s\n", error.localizedDescription.UTF8String);
            return 1;
        }

        printf("\nSuccessfully instantiated MacToken CryptoTokenKit provider!\n");

        for (int i = 0; i < count; i++) {
            ctk_key_info info;
            memset(&info, 0, sizeof(info));
            if (ctk_bridge_get_installed(i, &info) == 0) {
                printf("\n--- Testing CTK signData [%d/%d] Thumbprint: %s ---\n", i + 1, count, info.thumbprint);
                MacTokenSession *session = (MacTokenSession *)[token token:token createSessionWithError:&error];
                if (session) {
                    uint8_t digest[32] = {0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08};
                    NSData *digestData = [NSData dataWithBytes:digest length:sizeof(digest)];
                    NSData *objectID = [NSData dataWithBytes:info.thumbprint length:strlen(info.thumbprint)];
                    
                    NSData *sigData = [session tokenSession:session signData:digestData usingKey:objectID algorithm:(TKTokenKeyAlgorithm *)kSecKeyAlgorithmRSASignatureDigestPKCS1v15SHA256 error:&error];
                    if (sigData) {
                        printf(" -> Signature SUCCESS! Length: %ld bytes\n", (long)sigData.length);
                    } else {
                        fprintf(stderr, " -> SignData ERROR: %s\n", error ? error.localizedDescription.UTF8String : "unknown");
                    }
                }
                ctk_bridge_free_key_info(&info);
            }
        }

        ctk_bridge_shutdown();
    }
    return 0;
}

#import <Foundation/Foundation.h>
#import <CryptoTokenKit/CryptoTokenKit.h>

NS_ASSUME_NONNULL_BEGIN

@interface MacTokenDriver : TKTokenDriver <TKTokenDriverDelegate, NSExtensionRequestHandling>
@end

NS_ASSUME_NONNULL_END

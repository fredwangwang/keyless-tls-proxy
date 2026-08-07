#import <Foundation/Foundation.h>
#import <CryptoTokenKit/CryptoTokenKit.h>

NS_ASSUME_NONNULL_BEGIN

@class MacToken;

@interface MacTokenSession : TKTokenSession <TKTokenSessionDelegate>
- (instancetype)initWithToken:(MacToken *)token;
@property (readonly, weak) MacToken *macToken;
@end

NS_ASSUME_NONNULL_END

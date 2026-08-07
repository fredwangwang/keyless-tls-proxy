#import <Foundation/Foundation.h>
#import <CryptoTokenKit/CryptoTokenKit.h>

NS_ASSUME_NONNULL_BEGIN

@class MacTokenDriver;
@class MacTokenSession;

@interface MacToken : TKToken <TKTokenDelegate>
- (nullable instancetype)initWithTokenDriver:(MacTokenDriver *)tokenDriver instanceID:(NSString *)instanceID error:(NSError **)error;
@end

NS_ASSUME_NONNULL_END

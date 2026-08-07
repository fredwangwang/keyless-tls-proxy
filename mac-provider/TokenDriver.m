#import "TokenDriver.h"
#import "Token.h"

@implementation MacTokenDriver

- (instancetype)init {
    if (self = [super init]) {
        self.delegate = self;
    }
    return self;
}

- (void)beginRequestWithExtensionContext:(NSExtensionContext *)context {
}

- (TKToken *)tokenDriver:(TKTokenDriver *)driver tokenForConfiguration:(TKTokenConfiguration *)configuration error:(NSError **)error {
    return [[MacToken alloc] initWithTokenDriver:self instanceID:configuration.instanceID error:error];
}

@end

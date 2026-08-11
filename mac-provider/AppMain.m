#import <Cocoa/Cocoa.h>
#import <CryptoTokenKit/CryptoTokenKit.h>
#import <Security/Security.h>
#include "libctkbridge.h"

static NSString *getAppGroupID(void) {
    static NSString *cachedAppGroupID = nil;
    static dispatch_once_t onceToken;
    dispatch_once(&onceToken, ^{
        cachedAppGroupID = [[NSBundle mainBundle] objectForInfoDictionaryKey:@"AppGroupID"];
        NSAssert(cachedAppGroupID.length > 0, @"AppGroupID key is missing from Info.plist");
    });
    return cachedAppGroupID;
}

@interface IdentityItem : NSObject
@property (nonatomic, copy) NSString *subject;
@property (nonatomic, copy) NSString *issuer;
@property (nonatomic, copy) NSString *thumbprint;
@property (nonatomic, assign) int keySize;
@property (nonatomic, assign) BOOL selected;
@property (nonatomic, strong) NSArray<TKTokenKeychainItem *> *keychainItems;
@end

@implementation IdentityItem
@end

static NSArray<IdentityItem *> *fetchIdentityItemsFromBridge(void) {
    NSMutableArray<IdentityItem *> *items = [NSMutableArray array];
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
                
                NSMutableArray<TKTokenKeychainItem *> *keychainItems = [NSMutableArray array];

                TKTokenKeychainCertificate *certItem = [[TKTokenKeychainCertificate alloc] initWithCertificate:certRef objectID:certObjectID];
                if (certItem) {
                    if (subjStr.length > 0) {
                        certItem.label = subjStr;
                    }
                    [keychainItems addObject:certItem];
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
                    [keychainItems addObject:keyItem];
                }

                NSString *issuerStr = info.issuer[0] != '\0' ? [NSString stringWithUTF8String:info.issuer] : @"";

                CFRelease(certRef);

                IdentityItem *item = [[IdentityItem alloc] init];
                item.subject = subjStr.length > 0 ? subjStr : tpStr;
                item.issuer = issuerStr.length > 0 ? issuerStr : @"";
                item.thumbprint = tpStr;
                item.keySize = info.key_size > 0 ? info.key_size : 2048;
                item.selected = YES;
                item.keychainItems = keychainItems;
                [items addObject:item];
            }
        }
        ctk_bridge_free_key_info(&info);
    }
    return items;
}

static void setupMainMenu(void) {
    NSMenu *mainMenu = [[NSMenu alloc] init];

    // App menu
    NSMenuItem *appMenuItem = [[NSMenuItem alloc] init];
    [mainMenu addItem:appMenuItem];
    NSMenu *appMenu = [[NSMenu alloc] init];
    NSMenuItem *quitItem = [[NSMenuItem alloc] initWithTitle:@"Quit TPM Cert Proxy"
                                                      action:@selector(terminate:)
                                               keyEquivalent:@"q"];
    [appMenu addItem:quitItem];
    [appMenuItem setSubmenu:appMenu];

    // Edit menu (required for Cocoa text fields to process Cmd+C, Cmd+V, Cmd+X, Cmd+A, Cmd+Z)
    NSMenuItem *editMenuItem = [[NSMenuItem alloc] init];
    [mainMenu addItem:editMenuItem];
    NSMenu *editMenu = [[NSMenu alloc] initWithTitle:@"Edit"];
    [editMenu addItemWithTitle:@"Undo" action:@selector(undo:) keyEquivalent:@"z"];
    [editMenu addItemWithTitle:@"Redo" action:@selector(redo:) keyEquivalent:@"Z"];
    [editMenu addItem:[NSMenuItem separatorItem]];
    [editMenu addItemWithTitle:@"Cut" action:@selector(cut:) keyEquivalent:@"x"];
    [editMenu addItemWithTitle:@"Copy" action:@selector(copy:) keyEquivalent:@"c"];
    [editMenu addItemWithTitle:@"Paste" action:@selector(paste:) keyEquivalent:@"v"];
    [editMenu addItemWithTitle:@"Select All" action:@selector(selectAll:) keyEquivalent:@"a"];
    [editMenuItem setSubmenu:editMenu];

    [NSApp setMainMenu:mainMenu];
}

static NSString *resolveContentOrPath(NSString *input) {
    NSString *trimmed = [input stringByTrimmingCharactersInSet:[NSCharacterSet whitespaceAndNewlineCharacterSet]];
    if (trimmed.length == 0) return @"";
    if ([trimmed containsString:@"-----BEGIN"]) {
        return trimmed;
    }
    BOOL isDir = NO;
    if ([[NSFileManager defaultManager] fileExistsAtPath:trimmed isDirectory:&isDir] && !isDir) {
        NSError *err = nil;
        NSString *content = [NSString stringWithContentsOfFile:trimmed encoding:NSUTF8StringEncoding error:&err];
        if (content && [content stringByTrimmingCharactersInSet:[NSCharacterSet whitespaceAndNewlineCharacterSet]].length > 0) {
            return [content stringByTrimmingCharactersInSet:[NSCharacterSet whitespaceAndNewlineCharacterSet]];
        }
    }
    return trimmed;
}

@interface AppDelegate : NSObject <NSApplicationDelegate, NSTableViewDataSource, NSTableViewDelegate>
@property (strong) NSWindow *window;
@property (strong) NSMutableArray<IdentityItem *> *identities;
@property (strong) NSTableView *tableView;
@property (strong) NSTextField *headerLabel;
@property (strong) NSTextField *sublabel;
@property (strong) NSButton *selectAllCheckbox;
@property (strong) NSTextField *footerLabel;
@property (strong) TKTokenConfiguration *tokenConfig;

@property (strong) NSTextField *serverAddrField;
@property (strong) NSTextView *caTextView;
@property (strong) NSTextView *certTextView;
@property (strong) NSTextView *keyTextView;
@property (strong) NSTextField *statusLabel;
@end

@implementation AppDelegate

- (NSTextView *)createScrollableTextViewInFrame:(NSRect)frame parentView:(NSView *)parentView {
    NSScrollView *scrollView = [[NSScrollView alloc] initWithFrame:frame];
    [scrollView setHasVerticalScroller:YES];
    [scrollView setHasHorizontalScroller:NO];
    [scrollView setAutohidesScrollers:YES];
    [scrollView setBorderType:NSBezelBorder];
    
    NSSize contentSize = [scrollView contentSize];
    NSTextView *textView = [[NSTextView alloc] initWithFrame:NSMakeRect(0, 0, contentSize.width, contentSize.height)];
    [textView setMinSize:NSMakeSize(0.0, contentSize.height)];
    [textView setMaxSize:NSMakeSize(FLT_MAX, FLT_MAX)];
    [textView setVerticallyResizable:YES];
    [textView setHorizontallyResizable:NO];
    [textView setAutoresizingMask:NSViewWidthSizable];
    [[textView textContainer] setContainerSize:NSMakeSize(contentSize.width, FLT_MAX)];
    [[textView textContainer] setWidthTracksTextView:YES];
    [textView setFont:[NSFont userFixedPitchFontOfSize:11.0]];
    [textView setAutomaticQuoteSubstitutionEnabled:NO];
    [textView setAutomaticDashSubstitutionEnabled:NO];
    [textView setAutomaticTextReplacementEnabled:NO];
    
    [scrollView setDocumentView:textView];
    [parentView addSubview:scrollView];
    return textView;
}

- (NSDictionary *)loadSharedConfigFromAppGroup {
    NSMutableDictionary *dict = [NSMutableDictionary dictionary];
    NSString *appGroupID = getAppGroupID();
    
    NSUserDefaults *defaults = [[NSUserDefaults alloc] initWithSuiteName:appGroupID];
    if (defaults) {
        if ([defaults stringForKey:@"serverAddr"]) dict[@"serverAddr"] = [defaults stringForKey:@"serverAddr"];
        if ([defaults stringForKey:@"ServerAddress"]) dict[@"ServerAddress"] = [defaults stringForKey:@"ServerAddress"];
        if ([defaults stringForKey:@"caContent"]) dict[@"caContent"] = [defaults stringForKey:@"caContent"];
        if ([defaults stringForKey:@"certContent"]) dict[@"certContent"] = [defaults stringForKey:@"certContent"];
        if ([defaults stringForKey:@"keyContent"]) dict[@"keyContent"] = [defaults stringForKey:@"keyContent"];
    }
    
    return dict;
}

- (BOOL)saveSharedConfigToAppGroup:(NSDictionary *)settings error:(NSError **)error {
    NSUserDefaults *defaults = [[NSUserDefaults alloc] initWithSuiteName:getAppGroupID()];
    if (defaults) {
        [settings enumerateKeysAndObjectsUsingBlock:^(id key, id obj, BOOL *stop) {
            [defaults setObject:obj forKey:key];
        }];
        [defaults synchronize];
        return YES;
    }
    if (error) {
        *error = [NSError errorWithDomain:@"AppMainDomain" code:1 userInfo:@{NSLocalizedDescriptionKey: @"Failed to open App Group NSUserDefaults"}];
    }
    return NO;
}

- (void)applicationDidFinishLaunching:(NSNotification *)aNotification {
    setupMainMenu();

    NSRect frame = NSMakeRect(100, 100, 880, 780);
    NSUInteger style = NSWindowStyleMaskTitled | NSWindowStyleMaskClosable | NSWindowStyleMaskMiniaturizable;
    self.window = [[NSWindow alloc] initWithContentRect:frame styleMask:style backing:NSBackingStoreBuffered defer:NO];
    [self.window setTitle:@"TPM Cert Proxy - MacToken Provider Configuration"];

    NSView *contentView = [self.window contentView];

    // Header Title
    self.headerLabel = [[NSTextField alloc] initWithFrame:NSMakeRect(20, 740, 840, 28)];
    [self.headerLabel setEditable:NO];
    [self.headerLabel setBordered:NO];
    [self.headerLabel setDrawsBackground:NO];
    [self.headerLabel setAlignment:NSTextAlignmentLeft];
    [self.headerLabel setFont:[NSFont systemFontOfSize:16 weight:NSFontWeightBold]];
    [self.headerLabel setStringValue:@"MacToken CryptoTokenKit Provider Configuration"];
    [contentView addSubview:self.headerLabel];

    // Row 1: Server Address
    NSTextField *serverLbl = [[NSTextField alloc] initWithFrame:NSMakeRect(20, 700, 130, 22)];
    [serverLbl setStringValue:@"Server Address:"];
    [serverLbl setEditable:NO];
    [serverLbl setBordered:NO];
    [serverLbl setDrawsBackground:NO];
    [serverLbl setAlignment:NSTextAlignmentRight];
    [contentView addSubview:serverLbl];

    self.serverAddrField = [[NSTextField alloc] initWithFrame:NSMakeRect(160, 700, 690, 24)];
    [self.serverAddrField setPlaceholderString:@"192.168.0.133:50051"];
    [contentView addSubview:self.serverAddrField];

    // Row 2: CA Certificate
    NSTextField *caLbl = [[NSTextField alloc] initWithFrame:NSMakeRect(20, 640, 130, 22)];
    [caLbl setStringValue:@"CA Certificate:"];
    [caLbl setEditable:NO];
    [caLbl setBordered:NO];
    [caLbl setDrawsBackground:NO];
    [caLbl setAlignment:NSTextAlignmentRight];
    [contentView addSubview:caLbl];

    self.caTextView = [self createScrollableTextViewInFrame:NSMakeRect(160, 595, 580, 75) parentView:contentView];

    NSButton *caBrowseBtn = [[NSButton alloc] initWithFrame:NSMakeRect(750, 640, 100, 28)];
    [caBrowseBtn setTitle:@"Browse..."];
    [caBrowseBtn setTarget:self];
    [caBrowseBtn setAction:@selector(browseCA:)];
    [contentView addSubview:caBrowseBtn];

    // Row 3: Client Certificate
    NSTextField *certLbl = [[NSTextField alloc] initWithFrame:NSMakeRect(20, 535, 130, 22)];
    [certLbl setStringValue:@"Client Certificate:"];
    [certLbl setEditable:NO];
    [certLbl setBordered:NO];
    [certLbl setDrawsBackground:NO];
    [certLbl setAlignment:NSTextAlignmentRight];
    [contentView addSubview:certLbl];

    self.certTextView = [self createScrollableTextViewInFrame:NSMakeRect(160, 490, 580, 75) parentView:contentView];

    NSButton *certBrowseBtn = [[NSButton alloc] initWithFrame:NSMakeRect(750, 535, 100, 28)];
    [certBrowseBtn setTitle:@"Browse..."];
    [certBrowseBtn setTarget:self];
    [certBrowseBtn setAction:@selector(browseCert:)];
    [contentView addSubview:certBrowseBtn];

    // Row 4: Client Key
    NSTextField *keyLbl = [[NSTextField alloc] initWithFrame:NSMakeRect(20, 430, 130, 22)];
    [keyLbl setStringValue:@"Client Key:"];
    [keyLbl setEditable:NO];
    [keyLbl setBordered:NO];
    [keyLbl setDrawsBackground:NO];
    [keyLbl setAlignment:NSTextAlignmentRight];
    [contentView addSubview:keyLbl];

    self.keyTextView = [self createScrollableTextViewInFrame:NSMakeRect(160, 385, 580, 75) parentView:contentView];

    NSButton *keyBrowseBtn = [[NSButton alloc] initWithFrame:NSMakeRect(750, 430, 100, 28)];
    [keyBrowseBtn setTitle:@"Browse..."];
    [keyBrowseBtn setTarget:self];
    [keyBrowseBtn setAction:@selector(browseKey:)];
    [contentView addSubview:keyBrowseBtn];

    // Buttons & Status Row
    NSButton *testBtn = [[NSButton alloc] initWithFrame:NSMakeRect(160, 345, 140, 32)];
    [testBtn setTitle:@"Test Connection"];
    [testBtn setBezelStyle:NSBezelStyleRounded];
    [testBtn setTarget:self];
    [testBtn setAction:@selector(testConfig:)];
    [contentView addSubview:testBtn];

    NSButton *saveBtn = [[NSButton alloc] initWithFrame:NSMakeRect(310, 345, 140, 32)];
    [saveBtn setTitle:@"Save & Apply"];
    [saveBtn setBezelStyle:NSBezelStyleRounded];
    [saveBtn setTarget:self];
    [saveBtn setAction:@selector(saveConfig:)];
    [contentView addSubview:saveBtn];

    self.statusLabel = [[NSTextField alloc] initWithFrame:NSMakeRect(460, 340, 390, 40)];
    [self.statusLabel setEditable:NO];
    [self.statusLabel setBordered:NO];
    [self.statusLabel setDrawsBackground:NO];
    [self.statusLabel setAlignment:NSTextAlignmentLeft];
    [self.statusLabel setFont:[NSFont systemFontOfSize:11 weight:NSFontWeightMedium]];
    [[self.statusLabel cell] setWraps:YES];
    [contentView addSubview:self.statusLabel];

    // Separator / Identities section
    NSTextField *identSectionLabel = [[NSTextField alloc] initWithFrame:NSMakeRect(20, 310, 840, 22)];
    [identSectionLabel setStringValue:@"Remote Identities & Keychain Items"];
    [identSectionLabel setEditable:NO];
    [identSectionLabel setBordered:NO];
    [identSectionLabel setDrawsBackground:NO];
    [identSectionLabel setFont:[NSFont systemFontOfSize:14 weight:NSFontWeightBold]];
    [contentView addSubview:identSectionLabel];

    self.selectAllCheckbox = [[NSButton alloc] initWithFrame:NSMakeRect(20, 282, 100, 22)];
    [self.selectAllCheckbox setButtonType:NSButtonTypeSwitch];
    [self.selectAllCheckbox setTitle:@"Select All"];
    [self.selectAllCheckbox setState:NSControlStateValueOn];
    [self.selectAllCheckbox setTarget:self];
    [self.selectAllCheckbox setAction:@selector(selectAllCheckboxToggled:)];
    [contentView addSubview:self.selectAllCheckbox];

    self.sublabel = [[NSTextField alloc] initWithFrame:NSMakeRect(130, 282, 730, 22)];
    [self.sublabel setEditable:NO];
    [self.sublabel setBordered:NO];
    [self.sublabel setDrawsBackground:NO];
    [self.sublabel setAlignment:NSTextAlignmentLeft];
    [self.sublabel setFont:[NSFont systemFontOfSize:12 weight:NSFontWeightRegular]];
    [self.sublabel setStringValue:@"Check identities to add to CryptoTokenKit keychain, then click 'Apply Selected'."];
    [self.sublabel setTextColor:[NSColor secondaryLabelColor]];
    [contentView addSubview:self.sublabel];

    // ScrollView and TableView for Identities
    NSScrollView *scrollView = [[NSScrollView alloc] initWithFrame:NSMakeRect(20, 80, 840, 195)];
    [scrollView setHasVerticalScroller:YES];
    [scrollView setHasHorizontalScroller:YES];
    [scrollView setAutohidesScrollers:YES];
    [scrollView setBorderType:NSBezelBorder];

    self.tableView = [[NSTableView alloc] initWithFrame:scrollView.bounds];
    [self.tableView setHeaderView:[[NSTableHeaderView alloc] init]];
    [self.tableView setUsesAlternatingRowBackgroundColors:YES];
    [self.tableView setGridStyleMask:NSTableViewSolidHorizontalGridLineMask];
    [self.tableView setRowHeight:28.0];
    [self.tableView setDataSource:self];
    [self.tableView setDelegate:self];

    NSTableColumn *colSelect = [[NSTableColumn alloc] initWithIdentifier:@"selected"];
    [colSelect setTitle:@"Add"];
    [colSelect setWidth:50];
    [self.tableView addTableColumn:colSelect];

    NSTableColumn *colSubject = [[NSTableColumn alloc] initWithIdentifier:@"subject"];
    [colSubject setTitle:@"Identity Subject / Label"];
    [colSubject setWidth:260];
    [self.tableView addTableColumn:colSubject];

    NSTableColumn *colIssuer = [[NSTableColumn alloc] initWithIdentifier:@"issuer"];
    [colIssuer setTitle:@"Issuer"];
    [colIssuer setWidth:200];
    [self.tableView addTableColumn:colIssuer];

    NSTableColumn *colThumbprint = [[NSTableColumn alloc] initWithIdentifier:@"thumbprint"];
    [colThumbprint setTitle:@"Thumbprint"];
    [colThumbprint setWidth:210];
    [self.tableView addTableColumn:colThumbprint];

    NSTableColumn *colKeySize = [[NSTableColumn alloc] initWithIdentifier:@"keySize"];
    [colKeySize setTitle:@"Key Size"];
    [colKeySize setWidth:90];
    [self.tableView addTableColumn:colKeySize];

    scrollView.documentView = self.tableView;
    [contentView addSubview:scrollView];

    // Lower Control Buttons
    NSButton *btnRefresh = [[NSButton alloc] initWithFrame:NSMakeRect(20, 42, 110, 32)];
    [btnRefresh setTitle:@"Refresh"];
    [btnRefresh setBezelStyle:NSBezelStyleRounded];
    [btnRefresh setTarget:self];
    [btnRefresh setAction:@selector(refreshIdentities:)];
    [contentView addSubview:btnRefresh];

    NSButton *btnApply = [[NSButton alloc] initWithFrame:NSMakeRect(140, 42, 170, 32)];
    [btnApply setTitle:@"Apply Selected"];
    [btnApply setBezelStyle:NSBezelStyleRounded];
    [btnApply setTarget:self];
    [btnApply setAction:@selector(applySelectedIdentities:)];
    [contentView addSubview:btnApply];

    self.footerLabel = [[NSTextField alloc] initWithFrame:NSMakeRect(20, 12, 840, 22)];
    [self.footerLabel setEditable:NO];
    [self.footerLabel setBordered:NO];
    [self.footerLabel setDrawsBackground:NO];
    [self.footerLabel setFont:[NSFont systemFontOfSize:12 weight:NSFontWeightMedium]];
    [contentView addSubview:self.footerLabel];

    // Load initial settings from App Group
    NSDictionary *savedConfig = [self loadSharedConfigFromAppGroup];
    NSString *savedAddr = savedConfig[@"serverAddr"] ?: savedConfig[@"ServerAddress"];
    NSString *savedCA   = savedConfig[@"caContent"]   ?: savedConfig[@"caPath"];
    NSString *savedCert = savedConfig[@"certContent"] ?: savedConfig[@"certPath"];
    NSString *savedKey  = savedConfig[@"keyContent"]  ?: savedConfig[@"keyPath"];

    if (!savedAddr || savedAddr.length == 0) savedAddr = @"192.168.0.133:50051";
    if (!savedCA)   savedCA   = @"";
    if (!savedCert) savedCert = @"";
    if (!savedKey)  savedKey  = @"";

    self.serverAddrField.stringValue = savedAddr;
    if (savedCA.length > 0)   self.caTextView.string   = savedCA;
    if (savedCert.length > 0) self.certTextView.string = savedCert;
    if (savedKey.length > 0)  self.keyTextView.string  = savedKey;

    NSString *effectiveAddr = self.serverAddrField.stringValue;
    NSString *effectiveCA   = resolveContentOrPath(self.caTextView.string);
    NSString *effectiveCert = resolveContentOrPath(self.certTextView.string);
    NSString *effectiveKey  = resolveContentOrPath(self.keyTextView.string);

    if (effectiveAddr.length > 0 && effectiveCA.length > 0 && effectiveCert.length > 0 && effectiveKey.length > 0) {
        int initRes = ctk_bridge_init_opts((char *)effectiveAddr.UTF8String, (char *)effectiveCA.UTF8String, (char *)effectiveCert.UTF8String, (char *)effectiveKey.UTF8String);
        if (initRes != 0) {
            [self.statusLabel setStringValue:[NSString stringWithFormat:@"Bridge init warning (code %d)", initRes]];
            [self.statusLabel setTextColor:[NSColor systemRedColor]];
        } else {
            [self.statusLabel setStringValue:@"Bridge initialized successfully."];
            [self.statusLabel setTextColor:[NSColor systemGreenColor]];
        }
    } else {
        [self.statusLabel setStringValue:@"Please configure settings and click 'Save & Apply'."];
        [self.statusLabel setTextColor:[NSColor systemOrangeColor]];
    }

    NSString *classID = @"com.fredprx.mactoken.app.extension";
    NSDictionary<NSString *, TKTokenDriverConfiguration *> *configs = [TKTokenDriverConfiguration driverConfigurations];
    TKTokenDriverConfiguration *driverConfig = configs[classID];
    if (driverConfig) {
        self.tokenConfig = driverConfig.tokenConfigurations[@"CertServerToken"];
        if (!self.tokenConfig) {
            self.tokenConfig = [driverConfig addTokenConfigurationForTokenInstanceID:@"CertServerToken"];
        }
        [self loadIdentitiesFromBridge];
        [self applySelectedIdentities:nil];
    } else {
        [self.footerLabel setStringValue:@"Driver configuration not found for extension class ID."];
        [self.footerLabel setTextColor:[NSColor systemRedColor]];
    }

    [self.window center];
    [self.window makeKeyAndOrderFront:nil];
    [NSApp activateIgnoringOtherApps:YES];
}

- (void)browseCA:(id)sender {
    [self browseForFileWithTitle:@"Select CA Certificate File" completion:^(NSString *content) {
        self.caTextView.string = content;
    }];
}

- (void)browseCert:(id)sender {
    [self browseForFileWithTitle:@"Select Client Certificate File" completion:^(NSString *content) {
        self.certTextView.string = content;
    }];
}

- (void)browseKey:(id)sender {
    [self browseForFileWithTitle:@"Select Client Key File" completion:^(NSString *content) {
        self.keyTextView.string = content;
    }];
}

- (void)browseForFileWithTitle:(NSString *)title completion:(void(^)(NSString *content))completion {
    NSOpenPanel *panel = [NSOpenPanel openPanel];
    panel.title = title;
    panel.canChooseFiles = YES;
    panel.canChooseDirectories = NO;
    panel.allowsMultipleSelection = NO;
    panel.treatsFilePackagesAsDirectories = NO;

    NSModalResponse response = [panel runModal];
    if (response == NSModalResponseOK) {
        NSURL *url = panel.URLs.firstObject;
        if (url && url.path) {
            NSString *content = resolveContentOrPath(url.path);
            if (content.length > 0) {
                dispatch_async(dispatch_get_main_queue(), ^{
                    completion(content);
                });
            }
        }
    }
}

extern char *ctk_bridge_last_error(void);

- (void)testConfig:(id)sender {
    NSString *addr = [self.serverAddrField.stringValue stringByTrimmingCharactersInSet:[NSCharacterSet whitespaceAndNewlineCharacterSet]];
    NSString *ca   = resolveContentOrPath(self.caTextView.string);
    NSString *cert = resolveContentOrPath(self.certTextView.string);
    NSString *key  = resolveContentOrPath(self.keyTextView.string);

    if (addr.length == 0 || ca.length == 0 || cert.length == 0 || key.length == 0) {
        self.statusLabel.textColor = [NSColor systemRedColor];
        self.statusLabel.stringValue = @"Test Failed: All fields (Server Address, CA, Client Cert, Client Key) must be specified.";
        return;
    }

    [self.statusLabel setTextColor:[NSColor secondaryLabelColor]];
    [self.statusLabel setStringValue:@"Testing connection..."];
    [self.statusLabel displayIfNeeded];

    dispatch_async(dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_DEFAULT, 0), ^{
        int res = ctk_bridge_init_opts((char *)addr.UTF8String, (char *)ca.UTF8String, (char *)cert.UTF8String, (char *)key.UTF8String);
        dispatch_async(dispatch_get_main_queue(), ^{
            if (res != 0) {
                char *errStr = ctk_bridge_last_error();
                NSString *errMsg = (errStr && strlen(errStr) > 0) ? [NSString stringWithUTF8String:errStr] : [NSString stringWithFormat:@"error code %d", res];
                if (errStr) free(errStr);
                self.statusLabel.textColor = [NSColor systemRedColor];
                self.statusLabel.stringValue = [NSString stringWithFormat:@"Test Failed: %@", errMsg];
                return;
            }

            int count = ctk_bridge_installed_count();
            self.statusLabel.textColor = [NSColor systemGreenColor];
            self.statusLabel.stringValue = [NSString stringWithFormat:@"Test Connection Successful! Discovered %d certificate(s) from remote server.", count];
            [self refreshIdentities:nil];
        });
    });
}

- (void)saveConfig:(id)sender {
    NSString *addr = [self.serverAddrField.stringValue stringByTrimmingCharactersInSet:[NSCharacterSet whitespaceAndNewlineCharacterSet]];
    NSString *ca   = resolveContentOrPath(self.caTextView.string);
    NSString *cert = resolveContentOrPath(self.certTextView.string);
    NSString *key  = resolveContentOrPath(self.keyTextView.string);

    if (addr.length == 0 || ca.length == 0 || cert.length == 0 || key.length == 0) {
        self.statusLabel.textColor = [NSColor systemRedColor];
        self.statusLabel.stringValue = @"Save Failed: All fields must be specified before saving.";
        return;
    }

    NSDictionary *configDict = @{
        @"serverAddr": addr,
        @"ServerAddress": addr,
        @"caContent": ca,
        @"certContent": cert,
        @"keyContent": key,
        @"caPath": ca,
        @"certPath": cert,
        @"keyPath": key,
        @"LastUpdated": [[NSDate date] description]
    };

    NSError *saveError = nil;
    if (![self saveSharedConfigToAppGroup:configDict error:&saveError]) {
        self.statusLabel.textColor = [NSColor systemRedColor];
        self.statusLabel.stringValue = [NSString stringWithFormat:@"Save Failed: %@", saveError ? saveError.localizedDescription : @"Unknown error"];
        return;
    }

    int res = ctk_bridge_init_opts((char *)addr.UTF8String, (char *)ca.UTF8String, (char *)cert.UTF8String, (char *)key.UTF8String);
    if (res == 0) {
        int count = ctk_bridge_installed_count();
        NSLog(@"AppMain: config saved to App Group, %d remote certificate(s) discovered.", count);
        self.statusLabel.textColor = [NSColor systemGreenColor];
        self.statusLabel.stringValue = [NSString stringWithFormat:@"Configuration saved to App Group and applied! Discovered %d remote certificate(s).", count];
        [self refreshIdentities:nil];
    } else {
        char *errStr = ctk_bridge_last_error();
        NSString *errMsg = (errStr && strlen(errStr) > 0) ? [NSString stringWithUTF8String:errStr] : [NSString stringWithFormat:@"error code %d", res];
        if (errStr) free(errStr);
        self.statusLabel.textColor = [NSColor systemRedColor];
        self.statusLabel.stringValue = [NSString stringWithFormat:@"Saved preferences, but bridge initialization failed: %@", errMsg];
    }
}

- (void)loadIdentitiesFromBridge {
    self.identities = [NSMutableArray arrayWithArray:fetchIdentityItemsFromBridge()];

    // Restore saved selection state
    NSArray<NSDictionary *> *savedIdentities = [self loadSavedSelectedIdentities];
    if (savedIdentities.count > 0) {
        NSMutableSet<NSString *> *savedThumbprints = [NSMutableSet set];
        NSMutableDictionary<NSString *, NSString *> *savedSubjectByThumbprint = [NSMutableDictionary dictionary];
        for (NSDictionary *entry in savedIdentities) {
            NSString *tp = entry[@"thumbprint"];
            NSString *subj = entry[@"subject"];
            if (tp) {
                [savedThumbprints addObject:tp];
                if (subj) savedSubjectByThumbprint[tp] = subj;
            }
        }

        // Apply saved selection: only select certs that were previously selected
        for (IdentityItem *item in self.identities) {
            item.selected = [savedThumbprints containsObject:item.thumbprint];
        }

        // Detect previously selected certs no longer available on the remote server
        NSSet<NSString *> *currentThumbprints = [NSSet setWithArray:[self.identities valueForKey:@"thumbprint"]];
        NSMutableArray<NSString *> *missingDescriptions = [NSMutableArray array];
        for (NSString *tp in savedThumbprints) {
            if (![currentThumbprints containsObject:tp]) {
                NSString *subj = savedSubjectByThumbprint[tp];
                if (subj.length > 0) {
                    [missingDescriptions addObject:[NSString stringWithFormat:@"• %@ (%@)", subj, tp]];
                } else {
                    [missingDescriptions addObject:[NSString stringWithFormat:@"• %@", tp]];
                }
            }
        }

        if (missingDescriptions.count > 0) {
            NSString *details = [NSString stringWithFormat:
                @"%ld previously selected certificate(s) are no longer available on the remote server:\n\n%@",
                (long)missingDescriptions.count,
                [missingDescriptions componentsJoinedByString:@"\n"]];
            NSAlert *alert = [[NSAlert alloc] init];
            [alert setMessageText:@"Missing Certificates"];
            [alert setInformativeText:details];
            [alert setAlertStyle:NSAlertStyleWarning];
            [alert addButtonWithTitle:@"OK"];
            [alert runModal];
            NSLog(@"AppMain: %ld previously selected cert(s) missing from remote server", (long)missingDescriptions.count);
        }
    }

    [self.tableView reloadData];
    [self updateSelectAllCheckboxState];
    [self updateSelectionSummary];
}

- (void)updateSelectAllCheckboxState {
    BOOL allSelected = YES;
    for (IdentityItem *item in self.identities) {
        if (!item.selected) {
            allSelected = NO;
            break;
        }
    }
    if (allSelected && self.identities.count > 0) {
        [self.selectAllCheckbox setState:NSControlStateValueOn];
    } else {
        [self.selectAllCheckbox setState:NSControlStateValueOff];
    }
}

- (void)updateSelectionSummary {
    NSUInteger selectedCount = 0;
    for (IdentityItem *item in self.identities) {
        if (item.selected) selectedCount++;
    }
    NSString *msg = [NSString stringWithFormat:@"%ld of %ld identities selected. Click 'Apply Selected' to save changes.",
                     (long)selectedCount, (long)self.identities.count];
    [self.footerLabel setStringValue:msg];
    [self.footerLabel setTextColor:[NSColor secondaryLabelColor]];
}

#pragma mark - Selection Persistence

- (NSArray<NSDictionary *> *)loadSavedSelectedIdentities {
    NSUserDefaults *defaults = [[NSUserDefaults alloc] initWithSuiteName:getAppGroupID()];
    NSArray *saved = [defaults objectForKey:@"SelectedIdentities"];
    return ([saved isKindOfClass:[NSArray class]]) ? saved : nil;
}

- (void)saveSelectionState {
    NSMutableArray<NSDictionary *> *selected = [NSMutableArray array];
    for (IdentityItem *item in self.identities) {
        if (item.selected) {
            [selected addObject:@{
                @"thumbprint": item.thumbprint ?: @"",
                @"subject": item.subject ?: @""
            }];
        }
    }
    NSUserDefaults *defaults = [[NSUserDefaults alloc] initWithSuiteName:getAppGroupID()];
    [defaults setObject:selected forKey:@"SelectedIdentities"];
    [defaults synchronize];
    NSLog(@"AppMain: Saved %ld selected identities to App Group defaults", (long)selected.count);
}

- (void)selectAllCheckboxToggled:(id)sender {
    BOOL isChecked = (self.selectAllCheckbox.state == NSControlStateValueOn);
    for (IdentityItem *item in self.identities) {
        item.selected = isChecked;
    }
    [self.tableView reloadData];
    [self updateSelectionSummary];
}

- (void)rowCheckboxToggled:(NSButton *)sender {
    NSInteger row = sender.tag;
    if (row >= 0 && row < self.identities.count) {
        IdentityItem *item = self.identities[row];
        item.selected = (sender.state == NSControlStateValueOn);
        [self updateSelectAllCheckboxState];
        [self updateSelectionSummary];
    }
}

- (void)refreshIdentities:(id)sender {
    [self loadIdentitiesFromBridge];
}

- (void)applySelectedIdentities:(id)sender {
    if (!self.tokenConfig) {
        NSLog(@"AppMain: tokenConfig is nil, cannot update");
        [self.footerLabel setStringValue:@"Error: Token configuration unavailable."];
        [self.footerLabel setTextColor:[NSColor systemRedColor]];
        return;
    }
    NSMutableArray<TKTokenKeychainItem *> *selectedItems = [NSMutableArray array];
    NSUInteger selectedCount = 0;
    for (IdentityItem *item in self.identities) {
        if (item.selected) {
            selectedCount++;
            [selectedItems addObjectsFromArray:item.keychainItems];
        }
    }
    self.tokenConfig.keychainItems = selectedItems;
    NSLog(@"AppMain: Applied %ld keychainItems (%ld identities selected out of %ld) to tokenConfig",
          (long)selectedItems.count, (long)selectedCount, (long)self.identities.count);
    printf("AppMain: Applied %ld keychainItems on tokenConfig\n", (long)selectedItems.count);

    [self saveSelectionState];

    NSString *msg = [NSString stringWithFormat:@"✓ Applied %ld of %ld identities to CryptoTokenKit keychain.",
                     (long)selectedCount, (long)self.identities.count];
    [self.footerLabel setStringValue:msg];
    [self.footerLabel setTextColor:[NSColor systemGreenColor]];
}

#pragma mark - NSTableViewDataSource

- (NSInteger)numberOfRowsInTableView:(NSTableView *)tableView {
    return self.identities.count;
}

#pragma mark - NSTableViewDelegate

- (NSView *)tableView:(NSTableView *)tableView viewForTableColumn:(NSTableColumn *)tableColumn row:(NSInteger)row {
    if (row < 0 || row >= self.identities.count) return nil;
    IdentityItem *item = self.identities[row];
    NSString *ident = tableColumn.identifier;

    if ([ident isEqualToString:@"selected"]) {
        NSButton *checkbox = [tableView makeViewWithIdentifier:@"CheckboxCell" owner:self];
        if (!checkbox) {
            checkbox = [[NSButton alloc] initWithFrame:NSMakeRect(14, 3, 20, 22)];
            [checkbox setButtonType:NSButtonTypeSwitch];
            [checkbox setTitle:@""];
            [checkbox setImagePosition:NSImageOnly];
            [checkbox setIdentifier:@"CheckboxCell"];
            [checkbox setTarget:self];
            [checkbox setAction:@selector(rowCheckboxToggled:)];
        }
        [checkbox setTag:row];
        [checkbox setState:item.selected ? NSControlStateValueOn : NSControlStateValueOff];
        return checkbox;
    } else {
        NSTableCellView *cellView = [tableView makeViewWithIdentifier:ident owner:self];
        if (!cellView) {
            cellView = [[NSTableCellView alloc] initWithFrame:NSMakeRect(0, 0, tableColumn.width, 24)];
            NSTextField *textField = [[NSTextField alloc] initWithFrame:NSMakeRect(2, 3, tableColumn.width - 4, 18)];
            [textField setEditable:NO];
            [textField setBordered:NO];
            [textField setDrawsBackground:NO];
            [textField setFont:[NSFont systemFontOfSize:12]];
            [cellView addSubview:textField];
            cellView.textField = textField;
            [cellView setIdentifier:ident];
        }
        if ([ident isEqualToString:@"subject"]) {
            [cellView.textField setStringValue:item.subject ? item.subject : @""];
        } else if ([ident isEqualToString:@"issuer"]) {
            [cellView.textField setStringValue:item.issuer ? item.issuer : @""];
        } else if ([ident isEqualToString:@"thumbprint"]) {
            [cellView.textField setStringValue:item.thumbprint ? item.thumbprint : @""];
        } else if ([ident isEqualToString:@"keySize"]) {
            [cellView.textField setStringValue:[NSString stringWithFormat:@"%d-bit RSA", item.keySize]];
        }
        return cellView;
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




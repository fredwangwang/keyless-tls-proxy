#import <Cocoa/Cocoa.h>
#import <CryptoTokenKit/CryptoTokenKit.h>
#import <Security/Security.h>
#include "libctkbridge.h"

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

static void writeRandomSettingsToAppGroup(void) {
    NSString *appGroupID = @"8Z93635RW6.com.fredprx.mactoken.shareddata";
    NSURL *groupContainerURL = [[NSFileManager defaultManager] containerURLForSecurityApplicationGroupIdentifier:appGroupID];
    
    if (!groupContainerURL) {
        NSLog(@"AppMain error: Failed to obtain container URL for App Group identifier '%@'. Verify sandbox and entitlement settings.", appGroupID);
        return;
    }

    NSURL *plistURL = [groupContainerURL URLByAppendingPathComponent:@"settings.plist"];
    NSDictionary *settings = @{
        @"ServerAddress": @"192.168.0.133:50051",
        @"LogLevel": @"DEBUG",
        @"SessionTimeout": @(arc4random_uniform(3600) + 300),
        @"EnableTLS": @YES,
        @"RandomSeed": @(arc4random_uniform(100000)),
        @"LastUpdated": [[NSDate date] description]
    };

    NSError *error = nil;
    BOOL success = [settings writeToURL:plistURL error:&error];
    if (success) {
        NSLog(@"AppMain: Successfully wrote random settings plist to App Group container at: %@", plistURL.path);
    } else {
        NSLog(@"AppMain error: Failed to write settings plist to %@: %@", plistURL.path, error.localizedDescription);
    }
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
@end

@implementation AppDelegate

- (void)applicationDidFinishLaunching:(NSNotification *)aNotification {
    // Build a minimal main menu so ⌘Q works
    NSMenu *mainMenu = [[NSMenu alloc] init];
    NSMenuItem *appMenuItem = [[NSMenuItem alloc] init];
    [mainMenu addItem:appMenuItem];
    NSMenu *appMenu = [[NSMenu alloc] init];
    NSMenuItem *quitItem = [[NSMenuItem alloc] initWithTitle:@"Quit TPM Cert Proxy"
                                                      action:@selector(terminate:)
                                               keyEquivalent:@"q"];
    [appMenu addItem:quitItem];
    [appMenuItem setSubmenu:appMenu];
    [NSApp setMainMenu:mainMenu];

    writeRandomSettingsToAppGroup();

    NSRect frame = NSMakeRect(100, 100, 880, 480);
    NSUInteger style = NSWindowStyleMaskTitled | NSWindowStyleMaskClosable | NSWindowStyleMaskMiniaturizable;
    self.window = [[NSWindow alloc] initWithContentRect:frame styleMask:style backing:NSBackingStoreBuffered defer:NO];
    [self.window setTitle:@"TPM Cert Proxy - MacToken Provider"];
    
    NSView *contentView = [self.window contentView];

    self.headerLabel = [[NSTextField alloc] initWithFrame:NSMakeRect(20, 435, 840, 30)];
    [self.headerLabel setEditable:NO];
    [self.headerLabel setBordered:NO];
    [self.headerLabel setDrawsBackground:NO];
    [self.headerLabel setAlignment:NSTextAlignmentLeft];
    [self.headerLabel setFont:[NSFont systemFontOfSize:16 weight:NSFontWeightBold]];
    [contentView addSubview:self.headerLabel];

    self.selectAllCheckbox = [[NSButton alloc] initWithFrame:NSMakeRect(20, 408, 100, 22)];
    [self.selectAllCheckbox setButtonType:NSButtonTypeSwitch];
    [self.selectAllCheckbox setTitle:@"Select All"];
    [self.selectAllCheckbox setState:NSControlStateValueOn];
    [self.selectAllCheckbox setTarget:self];
    [self.selectAllCheckbox setAction:@selector(selectAllCheckboxToggled:)];
    [contentView addSubview:self.selectAllCheckbox];

    self.sublabel = [[NSTextField alloc] initWithFrame:NSMakeRect(130, 408, 730, 22)];
    [self.sublabel setEditable:NO];
    [self.sublabel setBordered:NO];
    [self.sublabel setDrawsBackground:NO];
    [self.sublabel setAlignment:NSTextAlignmentLeft];
    [self.sublabel setFont:[NSFont systemFontOfSize:12 weight:NSFontWeightRegular]];
    [contentView addSubview:self.sublabel];

    // ScrollView and TableView
    NSScrollView *scrollView = [[NSScrollView alloc] initWithFrame:NSMakeRect(20, 85, 840, 315)];
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

    // Control Buttons
    NSButton *btnRefresh = [[NSButton alloc] initWithFrame:NSMakeRect(20, 45, 110, 32)];
    [btnRefresh setTitle:@"Refresh"];
    [btnRefresh setBezelStyle:NSBezelStyleRounded];
    [btnRefresh setTarget:self];
    [btnRefresh setAction:@selector(refreshIdentities:)];
    [contentView addSubview:btnRefresh];

    NSButton *btnTestConn = [[NSButton alloc] initWithFrame:NSMakeRect(140, 45, 150, 32)];
    [btnTestConn setTitle:@"Test Connection"];
    [btnTestConn setBezelStyle:NSBezelStyleRounded];
    [btnTestConn setTarget:self];
    [btnTestConn setAction:@selector(testConnection:)];
    [contentView addSubview:btnTestConn];

    NSButton *btnApply = [[NSButton alloc] initWithFrame:NSMakeRect(490, 45, 170, 32)];
    [btnApply setTitle:@"Apply Selected"];
    [btnApply setBezelStyle:NSBezelStyleRounded];
    [btnApply setKeyEquivalent:@"\r"];
    [btnApply setTarget:self];
    [btnApply setAction:@selector(applySelectedIdentities:)];
    [contentView addSubview:btnApply];

    self.footerLabel = [[NSTextField alloc] initWithFrame:NSMakeRect(20, 15, 840, 22)];
    [self.footerLabel setEditable:NO];
    [self.footerLabel setBordered:NO];
    [self.footerLabel setDrawsBackground:NO];
    [self.footerLabel setFont:[NSFont systemFontOfSize:12 weight:NSFontWeightMedium]];
    [contentView addSubview:self.footerLabel];

    NSBundle *bundle = [NSBundle mainBundle];
    NSString *ca = [bundle pathForResource:@"ca" ofType:@"crt" inDirectory:@"certs"];
    NSString *cert = [bundle pathForResource:@"client" ofType:@"crt" inDirectory:@"certs"];
    NSString *key = [bundle pathForResource:@"client" ofType:@"key" inDirectory:@"certs"];
    
    if (!ca || !cert || !key) {
        NSMutableArray<NSString *> *missing = [NSMutableArray array];
        if (!ca) [missing addObject:@"ca.crt"];
        if (!cert) [missing addObject:@"client.crt"];
        if (!key) [missing addObject:@"client.key"];
        
        NSString *missingStr = [missing componentsJoinedByString:@", "];
        NSLog(@"AppMain error: missing certificate files: %@", missingStr);
        
        [self.headerLabel setStringValue:@"Initialization Failed: Certificate(s) Missing"];
        [self.headerLabel setTextColor:[NSColor systemRedColor]];
        [self.sublabel setStringValue:[NSString stringWithFormat:@"Missing required bundle certificates in certs/: %@", missingStr]];
        [self.sublabel setTextColor:[NSColor systemRedColor]];
    } else {
        NSLog(@"AppMain initializing ctk bridge with CA: %@, cert: %@, key: %@", ca, cert, key);
        int initRes = ctk_bridge_init_opts("192.168.0.133:50051", (char *)ca.UTF8String, (char *)cert.UTF8String, (char *)key.UTF8String);
        NSLog(@"AppMain ctk_bridge_init_opts res: %d", initRes);

        if (initRes != 0) {
            [self.headerLabel setStringValue:@"Initialization Failed: Bridge Error"];
            [self.headerLabel setTextColor:[NSColor systemRedColor]];
            [self.sublabel setStringValue:[NSString stringWithFormat:@"ctk_bridge_init_opts returned error code %d", initRes]];
            [self.sublabel setTextColor:[NSColor systemRedColor]];
        } else {
            [self.headerLabel setStringValue:@"MacToken CryptoTokenKit Provider Registered & Active!"];
            [self.headerLabel setTextColor:[NSColor labelColor]];
            [self.sublabel setStringValue:@"Check identities to add to CryptoTokenKit keychain, then click 'Apply Selected'."];
            [self.sublabel setTextColor:[NSColor secondaryLabelColor]];

            NSString *classID = @"com.fredprx.mactoken.app.extension";
            NSDictionary<NSString *, TKTokenDriverConfiguration *> *configs = [TKTokenDriverConfiguration driverConfigurations];
            NSLog(@"TKTokenDriverConfiguration driverConfigurations: %@", configs);
            TKTokenDriverConfiguration *driverConfig = configs[classID];
            if (driverConfig) {
                NSLog(@"Found driverConfig for classID %@", classID);
                self.tokenConfig = driverConfig.tokenConfigurations[@"CertServerToken"];
                if (!self.tokenConfig) {
                    self.tokenConfig = [driverConfig addTokenConfigurationForTokenInstanceID:@"CertServerToken"];
                    NSLog(@"Added tokenConfig for CertServerToken: %@", self.tokenConfig);
                }
                [self loadIdentitiesFromBridge];
                [self applySelectedIdentities:nil];
            } else {
                NSLog(@"driverConfig is NIL for classID %@", classID);
                printf("driverConfig is NIL for classID %s\n", classID.UTF8String);
                [self.footerLabel setStringValue:@"Driver configuration not found for extension class ID."];
                [self.footerLabel setTextColor:[NSColor systemRedColor]];
            }
        }
    }

    [self.window center];
    [self.window makeKeyAndOrderFront:nil];
    [NSApp activateIgnoringOtherApps:YES];
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
    NSString *appGroupID = @"8Z93635RW6.com.fredprx.mactoken.shareddata";
    NSUserDefaults *defaults = [[NSUserDefaults alloc] initWithSuiteName:appGroupID];
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
    NSString *appGroupID = @"8Z93635RW6.com.fredprx.mactoken.shareddata";
    NSUserDefaults *defaults = [[NSUserDefaults alloc] initWithSuiteName:appGroupID];
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

- (void)testConnection:(id)sender {
    [self.footerLabel setStringValue:@"Testing connection…"];
    [self.footerLabel setTextColor:[NSColor secondaryLabelColor]];
    [self.footerLabel displayIfNeeded];

    dispatch_async(dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_DEFAULT, 0), ^{
        NSDate *start = [NSDate date];
        int result = ctk_bridge_ping();
        NSTimeInterval elapsed = -[start timeIntervalSinceNow];

        dispatch_async(dispatch_get_main_queue(), ^{
            if (result == 0) {
                NSString *msg = [NSString stringWithFormat:@"✓ Connection OK  (%.0f ms)", elapsed * 1000];
                [self.footerLabel setStringValue:msg];
                [self.footerLabel setTextColor:[NSColor systemGreenColor]];
            } else {
                [self.footerLabel setStringValue:@"✗ Connection failed — check server address and certificates."];
                [self.footerLabel setTextColor:[NSColor systemRedColor]];
            }
        });
    });
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




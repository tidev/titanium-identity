/**
 * APSKeychainWrapper
 * Copyright (c) 2016 by Axway. All Rights Reserved.
 * Licensed under the terms of the Apache Public License
 * Please see the LICENSE included with this distribution for details.
 */
#import "APSKeychainWrapper.h"

APSErrorDomain const APSKeychainWrapperErrorDomain = @"com.appcelerator.keychainwrapper.ErrorDomain";

@implementation APSKeychainWrapper

- (id)initWithIdentifier:(NSString *)identifier
                 service:(NSString *)service
             accessGroup:(NSString *)accessGroup
{
  return [self initWithIdentifier:identifier
                          service:service
                      accessGroup:accessGroup
                accessibilityMode:nil
                accessControlMode:0
                          options:nil];
}

- (id)initWithIdentifier:(NSString *)identifier
                 service:(NSString *)service
             accessGroup:(NSString *)accessGroup
       accessibilityMode:(CFStringRef)accessibilityMode
       accessControlMode:(SecAccessControlCreateFlags)accessControlMode
                 options:(NSDictionary *)options
{
  if (self = [super init]) {
    _identifier = identifier;
    _service = service;
    _accessGroup = accessGroup;
    _accessibilityMode = accessibilityMode;
    _accessControlMode = accessControlMode;
    _options = options;

    [self initializeBaseAttributes];
  }

  return self;
}

- (void)exists:(void (^)(BOOL exists, NSError *error))completionBlock;
{
  NSMutableDictionary *query = [NSMutableDictionary dictionaryWithDictionary:@{
    (id)kSecClass : [baseAttributes objectForKey:(id)kSecClass],
    (id)kSecAttrService : [baseAttributes objectForKey:(id)kSecAttrService],
    (id)kSecAttrAccount : [baseAttributes objectForKey:(id)kSecAttrAccount]
  }];

  // kSecUseAuthenticationUI constants are iOS 9+
  if ([[[UIDevice currentDevice] systemVersion] compare:@"9.0" options:NSNumericSearch] != NSOrderedAscending) {
    query[(id)kSecUseAuthenticationUI] = (id)kSecUseAuthenticationUIFail; // Supress TouchID dialog for existence check
  }

  // Dispatch into our priority queue
  dispatch_async(dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_DEFAULT, 0), ^{
    CFTypeRef dataTypeRef = NULL;
    OSStatus status = SecItemCopyMatching((CFDictionaryRef)(query), &dataTypeRef);

    dispatch_async(dispatch_get_main_queue(), ^{
      if (status == errSecInteractionNotAllowed || status == noErr) {
        completionBlock(YES, nil);
      } else if (status == errSecItemNotFound) {
        completionBlock(NO, nil);
      } else {
        completionBlock(NO, [NSError errorWithDomain:APSKeychainWrapperErrorDomain
                                                code:(int)status
                                            userInfo:@{ NSLocalizedDescriptionKey : NSLocalizedString(@"Keychain item existence could not be determined. Returning `false` in this case.", nil) }]);
      }
    });
  });
}

- (void)save:(NSString *)value
{
  __weak APSKeychainWrapper *weakSelf = self;

  [baseAttributes setObject:[value dataUsingEncoding:NSUTF8StringEncoding] forKey:(id)kSecValueData];

  dispatch_async(dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_DEFAULT, 0), ^{
    APSKeychainWrapper *strongSelf = weakSelf;
    if (strongSelf == nil) {
      return;
    }

    OSStatus status = SecItemAdd((__bridge CFDictionaryRef)strongSelf->baseAttributes, nil);

    [strongSelf->baseAttributes removeObjectForKey:(id)kSecValueData];

    if (status == noErr) {
      [[strongSelf delegate] APSKeychainWrapper:strongSelf didSaveValueWithResult:@{@"success" : @YES,
        @"identifier" : strongSelf->_identifier}];
    } else {
      [[strongSelf delegate] APSKeychainWrapper:strongSelf didSaveValueWithError:[APSKeychainWrapper errorFromStatus:status andIdentifier:strongSelf->_identifier]];
    }
  });
}

- (void)read
{
  __weak APSKeychainWrapper *weakSelf = self;

  // Special attributes to fetch data
  [baseAttributes setObject:(id)kSecMatchLimitOne forKey:(id)kSecMatchLimit];
  [baseAttributes setObject:(id)kCFBooleanTrue forKey:(id)kSecReturnData];

  dispatch_async(dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_DEFAULT, 0), ^{
    APSKeychainWrapper *strongSelf = weakSelf;
    if (strongSelf == nil) {
      return;
    }

    CFTypeRef keychainData = NULL;
    OSStatus status = SecItemCopyMatching((CFDictionaryRef)(strongSelf->baseAttributes), (CFTypeRef *)&keychainData);

    [strongSelf->baseAttributes removeObjectForKey:(id)kSecMatchLimit];
    [strongSelf->baseAttributes removeObjectForKey:(id)kSecReturnData];

    if (status == noErr) {
      [[self delegate] APSKeychainWrapper:self
                   didReadValueWithResult:@{
                     @"success" : @YES,
                     @"identifier" : strongSelf->_identifier,
                     @"value" : [[NSString alloc] initWithData:(__bridge NSData *)keychainData encoding:NSUTF8StringEncoding]
                   }];
    } else {
      [[strongSelf delegate] APSKeychainWrapper:strongSelf didReadValueWithError:[APSKeychainWrapper errorFromStatus:status andIdentifier:strongSelf->_identifier]];
    }
  });
}

- (void)update:(NSString *)value
{
  __weak APSKeychainWrapper *weakSelf = self;

  dispatch_async(dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_DEFAULT, 0), ^{
    APSKeychainWrapper *strongSelf = weakSelf;
    if (strongSelf == nil) {
      return;
    }

    OSStatus status = SecItemUpdate((__bridge CFDictionaryRef)strongSelf->baseAttributes, (__bridge CFDictionaryRef) @{ (id)kSecValueData : [value dataUsingEncoding:NSUTF8StringEncoding] });

    if (status == noErr) {
      [[strongSelf delegate] APSKeychainWrapper:strongSelf didUpdateValueWithResult:@{@"success" : @YES,
        @"identifier" : strongSelf->_identifier}];
    } else {
      [[strongSelf delegate] APSKeychainWrapper:strongSelf didUpdateValueWithError:[APSKeychainWrapper errorFromStatus:status andIdentifier:strongSelf->_identifier]];
    }
  });
}

- (void)reset
{
  __weak APSKeychainWrapper *weakSelf = self;

  dispatch_async(dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_DEFAULT, 0), ^{
    APSKeychainWrapper *strongSelf = weakSelf;
    if (strongSelf == nil) {
      return;
    }

    OSStatus status = SecItemDelete((CFDictionaryRef)strongSelf->baseAttributes);

    if (status == noErr) {
      [[strongSelf delegate] APSKeychainWrapper:strongSelf didDeleteValueWithResult:@{@"success" : @YES,
        @"identifier" : strongSelf->_identifier}];
    } else {
      [[strongSelf delegate] APSKeychainWrapper:strongSelf didDeleteValueWithError:[APSKeychainWrapper errorFromStatus:status andIdentifier:strongSelf->_identifier]];
    }
  });
}

#pragma mark Utilities

+ (NSError *)errorFromStatus:(OSStatus)status andIdentifier:(NSString *_Nullable)identifier
{
  NSString *message = [NSString stringWithFormat:@"%i", (int)status];
  NSString *suggestion = [NSString stringWithFormat:@"See https://www.osstatus.com/search/results?platform=all&framework=all&search=-%i for more information", (int)status];

  switch (status) {
  case errSecSuccess:
    message = @"The keychain operation succeeded";
    break;

  case errSecDuplicateItem:
    message = @"The keychain item already exists";
    break;

  case errSecItemNotFound:
    message = @"The keychain item could not be found";
    break;

  case errSecAuthFailed:
    message = @"The keychain item authentication failed";
    break;

  case errSecParam:
    message = @"The keychain access failed due to malformed attributes";
    break;

  default:
    break;
  }

  message = [message stringByAppendingString:[NSString stringWithFormat:@" (Code: %i)", (int)status]];

  return [NSError errorWithDomain:APSKeychainWrapperErrorDomain
                             code:(int)status
                         userInfo:@{
                           NSLocalizedDescriptionKey : NSLocalizedString(message, nil),
                           NSLocalizedRecoverySuggestionErrorKey : NSLocalizedString(suggestion, nil),
                           @"identifier" : identifier
                         }];
}

- (void)initializeBaseAttributes
{
  if (baseAttributes) {
    [baseAttributes removeAllObjects];
    baseAttributes = nil;
  }

  baseAttributes = [NSMutableDictionary dictionaryWithDictionary:@{
    (id)kSecClass : (id)kSecClassGenericPassword,
    (id)kSecAttrAccount : _identifier,
    (id)kSecAttrService : _service
  }];

  // Apply access-control if both accessibility-mode and access-control-mode provided
  if (_accessibilityMode && _accessControlMode) {
    CFErrorRef error = NULL;
    SecAccessControlRef accessControl = SecAccessControlCreateWithFlags(kCFAllocatorDefault, _accessibilityMode, _accessControlMode, &error);

    if (error == NULL || accessControl != NULL) {
      [baseAttributes setObject:(__bridge id)accessControl forKey:(id)kSecAttrAccessControl];

      CFRelease(accessControl);
    } else {
      NSLog(@"Error: Could not create access control: %@", [(__bridge NSError *)error localizedDescription]);

      if (accessControl) {
        CFRelease(accessControl);
      }
    }

    // Apply only accessibility constraints if provided
  } else if (_accessibilityMode) {
    [baseAttributes setObject:(__bridge id)_accessibilityMode forKey:(id)kSecAttrAccessible];
  }

  // Making it possible to apply more options to keep it flexible
  if (_options) {
    for (id key in [_options allKeys]) {
      if ([baseAttributes objectForKey:key]) {
        NSLog(@"Warning: The option %@ is already part of the base attributes, overriding it now", key);
      }
      [baseAttributes setObject:[_options objectForKey:(id)key] forKey:(id)key];
    }
  }

  if (_accessGroup != nil) {
#if TARGET_IPHONE_SIMULATOR
    // Ignore the access group if running on the iPhone simulator.
    //
    // Apps that are built for the simulator aren't signed, so there's no keychain access group
    // for the simulator to check. This means that all apps can see all keychain items when run
    // on the simulator.
    //
    // If a SecItem contains an access group attribute, SecItemAdd and SecItemUpdate on the
    // simulator will return -25243 (errSecNoAccessForItem).
#else
    [baseAttributes setObject:_accessGroup
                       forKey:(id)kSecAttrAccessGroup];
#endif
  }
}

@end

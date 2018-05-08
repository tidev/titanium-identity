/**
 * Ti.Identity
 *
 * Created by Hans Knoechel
 * Copyright (c) 2017-present by Axway. All rights reserved.
 */

#import "APSKeychainWrapper.h"
#import "TiProxy.h"

@interface TiIdentityKeychainItemProxy : TiProxy <APSKeychainWrapperDelegate> {
  @private
  APSKeychainWrapper *keychainItem;

  NSString *service;
  NSString *identifier;
  NSString *accessGroup;
  NSString *accessibilityMode;
  NSNumber *accessControlMode;
  NSDictionary *options;
}

/**
 Saves a new value to the keychain. The value is identified by it's keychain
 item identifier and an optional access-group.
 */
- (void)save:(id)value;

/**
 Reads an existing value from the keychain. The value is identified by it's
 keychain item identifier and an optional access-group.
 */
- (void)read:(id)unused;

/**
 Updates an existing value to the keychain. The value is identified by it's
 keychain item identifier and an optional access-group.
 */
- (void)update:(id)value;

/**
 Deletes a value from the keychain. The value is identified by it's
 keychain item identifier and an optional access-group.
 */
- (void)reset:(id)unused;

/**
 Checks if an item exists already.
 
 @param value The callback to be invoked after the existence is determined.
 */
- (void)fetchExistence:(id)value;

@end

/**
 * Appcelerator Titanium Mobile
 * Copyright (c) 2009-2016 by Appcelerator, Inc. All Rights Reserved.
 * Licensed under the terms of the Apache Public License
 * Please see the LICENSE included with this distribution for details.
 */
#import "APSKeychainWrapper.h"
#import "TiProxy.h"

@interface TiIdentityKeychainItemProxy : TiProxy <APSKeychainWrapperDelegate> {
  @private
  APSKeychainWrapper *keychainItem;

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

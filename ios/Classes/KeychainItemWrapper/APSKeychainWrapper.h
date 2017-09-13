/**
 * APSKeychainWrapper
 * Copyright (c) 2016 by Axway. All Rights Reserved.
 * Licensed under the terms of the Apache Public License
 * Please see the LICENSE included with this distribution for details.
 */
#import <Foundation/Foundation.h>

/**
 The error domain used to create new errors.
 */
typedef NSString *APSErrorDomain;

@class APSKeychainWrapper;

/**
 The `APSKeychainWrapperDelegate` class notify it's implementations
 about events occurring in the interaction with the keychain.
 */
@protocol APSKeychainWrapperDelegate <NSObject>
@required

/**
 Triggered when a value was successfully saved to the keychain.
 
 @param keychainWrapper The keychain wrapper that triggered this action.
 @param result The result of the operation.
 */
- (void)APSKeychainWrapper:(APSKeychainWrapper*)keychainWrapper didSaveValueWithResult:(NSDictionary*)result;

/**
 Triggered when a value could not be saved to the keychain.
 
 @param keychainWrapper The keychain wrapper that triggered this action.
 @param error The occurred error of the operation.
 */
- (void)APSKeychainWrapper:(APSKeychainWrapper*)keychainWrapper didSaveValueWithError:(NSError*)error;

/**
 Triggered when a value was successfully updated to the keychain.
 
 @param keychainWrapper The keychain wrapper that triggered this action.
 @param result The result of the operation.
 */
- (void)APSKeychainWrapper:(APSKeychainWrapper*)keychainWrapper didUpdateValueWithResult:(NSDictionary*)result;

/**
 Triggered when a value could not be updated to the keychain.
 
 @param keychainWrapper The keychain wrapper that triggered this action.
 @param error The occurred error of the operation.
 */
- (void)APSKeychainWrapper:(APSKeychainWrapper*)keychainWrapper didUpdateValueWithError:(NSError*)error;

/**
 Triggered when a value was successfully received from the keychain.
 
 @param keychainWrapper The keychain wrapper that triggered this action.
 @param result The result of the operation.
 */
- (void)APSKeychainWrapper:(APSKeychainWrapper*)keychainWrapper didReadValueWithResult:(NSDictionary*)result;

/**
 Triggered when a value could not be read from the keychain.
 
 @param keychainWrapper The keychain wrapper that triggered this action.
 @param error The occurred error of the operation.
 */
- (void)APSKeychainWrapper:(APSKeychainWrapper*)keychainWrapper didReadValueWithError:(NSError*)error;

/**
 Triggered when a value was successfully deleted from the keychain.
 
 @param keychainWrapper The keychain wrapper that triggered this action.
 @param result The result of the operation.
 */
- (void)APSKeychainWrapper:(APSKeychainWrapper*)keychainWrapper didDeleteValueWithResult:(NSDictionary*)result;

/**
 Triggered when a value could not be deleted from the keychain.
 
 @param keychainWrapper The keychain wrapper that triggered this action.
 @param error The occurred error of the operation.
 */
- (void)APSKeychainWrapper:(APSKeychainWrapper*)keychainWrapper didDeleteValueWithError:(NSError*)error;

@end

/**
 The `APSKeychainWrapper` provides an interface to read, save and reset keychain items 
 based on their configured options.
 */
@interface APSKeychainWrapper : NSObject {
@private
    NSMutableDictionary *baseAttributes;
    NSString *_identifier;
    NSString *_service;
    NSString *_accessGroup;
    NSDictionary *_options;
    CFStringRef _accessibilityMode;
    SecAccessControlCreateFlags _accessControlMode;
}

/**
 The delegate to be used with the `APSKeychainWrapper` to get notified
 about keychain events.
 */
@property(unsafe_unretained) id<APSKeychainWrapperDelegate> delegate;

/**
 Initializes an `APSKeychainWrapper` object with the specified options.
 The combination of the `identifier` and `service` represents the private
 key of the keychain item.
 
 @param identifier The identifier of the keychain item.
 @param service The service of the keychain item.
 @param accessGroup The access group of the keychain item.

 @return The newly-initialized keychain item
 */
- (id)initWithIdentifier:(NSString*)identifier
                 service:(NSString*)service
             accessGroup:(NSString*)accessGroup;

/**
 Initializes an `APSKeychainWrapper` object with the specified options.
 The combination of the `identifier` and `service` represents the private
 key of the keychain item.
 
 @param identifier The identifier of the keychain item.
 @param service The service of the keychain item.
 @param accessGroup The access group of the keychain item.
 @param accessibilityMode The accessibility mode of the keychain item.
 @param accessControlMode The access-control mode of the keychain item.
 
 @return The newly-initialized keychain item
 */
- (id)initWithIdentifier:(NSString*)identifier
                 service:(NSString*)service
             accessGroup:(NSString*)accessGroup
       accessibilityMode:(CFStringRef)accessibilityMode
       accessControlMode:(SecAccessControlCreateFlags)accessControlMode
                 options:(NSDictionary*)options;

/**
 Checks if an item exists already.
 
 @param completionBlock The block to be invoked when the existence has been determined.
 */
- (void)exists:(void (^)(BOOL exists, NSError *error))completionBlock;

/**
 Saves a new value to the keychain. The value is identified by it's keychain
 item identifier and an optional access-group.
 
 @param value The value to save in the iOS keychain.
 */
- (void)save:(NSString*)value;

/**
 Reads an existing value from the keychain. The value is identified by it's
 keychain item identifier and an optional access-group.
 */
- (void)read;

/**
 Updates a existing value to the keychain. The value is identified by it's keychain
 item identifier and an optional access-group.
 
 @param value The value to save in the iOS keychain.
 */
- (void)update:(NSString*)value;

/**
 Deletes a value from the keychain. The value is identified by it's
 keychain item identifier and an optional access-group.
 */
- (void)reset;


@end

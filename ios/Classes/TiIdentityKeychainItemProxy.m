/**
 * Ti.Identity
 *
 * Created by Hans Knoechel
 * Copyright (c) 2017-present by Axway. All rights reserved.
 */

#import "TiIdentityKeychainItemProxy.h"

@implementation TiIdentityKeychainItemProxy

#pragma mark Internal

- (id)_initWithPageContext:(id<TiEvaluator>)context args:(NSArray *)args
{
  if (self = [super _initWithPageContext:context args:args]) {
    NSDictionary *params = [args objectAtIndex:0];

    identifier = [[params objectForKey:@"identifier"] copy];
    accessGroup = [[params objectForKey:@"accessGroup"] copy];
    accessibilityMode = [[params objectForKey:@"accessibilityMode"] copy];
    accessControlMode = [params objectForKey:@"accessControlMode"];
    options = [params objectForKey:@"options"];
    service = [[params objectForKey:@"service"] copy] ?: @"ti.touchid"; // Keep "ti.touchid" default for backwards compatibility
  }
  return self;
}

- (APSKeychainWrapper *)keychainItem
{
  if (!keychainItem) {

    keychainItem = [[APSKeychainWrapper alloc] initWithIdentifier:identifier
                                                          service:service
                                                      accessGroup:accessGroup
                                                accessibilityMode:(CFStringRef)accessibilityMode
                                                accessControlMode:[self formattedAccessControlFlags]
                                                          options:options];

    [keychainItem setDelegate:self];
  }

  return keychainItem;
}

#pragma mark Public API's

- (NSString *)apiName
{
  return @"Ti.Identity.KeychainItem";
}

- (void)save:(id)value
{
  ENSURE_SINGLE_ARG(value, NSString);
  [[self keychainItem] save:value];
}

- (void)read:(id)unused
{
  [[self keychainItem] read];
}

- (void)update:(id)value
{
  ENSURE_SINGLE_ARG(value, NSString);
  [[self keychainItem] update:value];
}

- (void)reset:(id)unused
{
  [[self keychainItem] reset];
}

- (void)fetchExistence:(id)value
{
  ENSURE_SINGLE_ARG(value, KrollCallback);

  [[self keychainItem] exists:^(BOOL result, NSError *error) {
    TiThreadPerformOnMainThread(
        ^{
          NSMutableDictionary *propertiesDict = [NSMutableDictionary dictionaryWithDictionary:@{ @"exists" : NUMBOOL(result) }];

          if (error) {
            [propertiesDict setObject:[error localizedDescription] forKey:@"error"];
          }

          NSArray *invocationArray = [[NSArray alloc] initWithObjects:&propertiesDict count:1];

          [value call:invocationArray thisObject:self];
          invocationArray = nil;
        },
        YES);
  }];
}

#pragma mark APSKeychainWrapperDelegate

- (void)APSKeychainWrapper:(APSKeychainWrapper *)keychainWrapper didSaveValueWithResult:(NSDictionary *)result
{
  if ([self _hasListeners:@"save"]) {
    NSMutableDictionary *m = [result mutableCopy];
    [m setValue:NUMINTEGER(0) forKey:@"code"];
    [self fireEvent:@"save" withObject:m];
  }
}

- (void)APSKeychainWrapper:(APSKeychainWrapper *)keychainWrapper didSaveValueWithError:(NSError *)error
{
  if ([self _hasListeners:@"save"]) {
    [self fireEvent:@"save" withObject:[TiIdentityKeychainItemProxy errorDictionaryFromError:error]];
  }
}

- (void)APSKeychainWrapper:(APSKeychainWrapper *)keychainWrapper didReadValueWithResult:(NSDictionary *)result
{
  if ([self _hasListeners:@"read"]) {
    NSMutableDictionary *m = [result mutableCopy];
    [m setValue:NUMINTEGER(0) forKey:@"code"];
    [self fireEvent:@"read" withObject:m];
  }
}

- (void)APSKeychainWrapper:(APSKeychainWrapper *)keychainWrapper didReadValueWithError:(NSError *)error
{
  if ([self _hasListeners:@"read"]) {
    [self fireEvent:@"read" withObject:[TiIdentityKeychainItemProxy errorDictionaryFromError:error]];
  }
}

- (void)APSKeychainWrapper:(APSKeychainWrapper *)keychainWrapper didUpdateValueWithError:(NSError *)error
{
  if ([self _hasListeners:@"update"]) {
    [self fireEvent:@"update" withObject:[TiIdentityKeychainItemProxy errorDictionaryFromError:error]];
  }
}

- (void)APSKeychainWrapper:(APSKeychainWrapper *)keychainWrapper didDeleteValueWithResult:(NSDictionary *)result
{
  if ([self _hasListeners:@"reset"]) {
    NSMutableDictionary *m = [result mutableCopy];
    [m setValue:NUMINTEGER(0) forKey:@"code"];
    [self fireEvent:@"reset" withObject:m];
  }
}

- (void)APSKeychainWrapper:(APSKeychainWrapper *)keychainWrapper didDeleteValueWithError:(NSError *)error
{
  if ([self _hasListeners:@"reset"]) {
    [self fireEvent:@"reset" withObject:[TiIdentityKeychainItemProxy errorDictionaryFromError:error]];
  }
}

- (void)APSKeychainWrapper:(APSKeychainWrapper *)keychainWrapper didUpdateValueWithResult:(NSDictionary *)result
{
  if ([self _hasListeners:@"update"]) {
    NSMutableDictionary *m = [result mutableCopy];
    [m setValue:NUMINTEGER(0) forKey:@"code"];
    [self fireEvent:@"update" withObject:m];
  }
}

#pragma mark Utilities

+ (NSDictionary *)errorDictionaryFromError:(NSError *)error
{
  return @{
    @"success" : @NO,
    @"error" : [error localizedDescription],
    @"code" : NUMINTEGER([error code])
  };
}

- (SecAccessControlCreateFlags)formattedAccessControlFlags
{
  if (accessControlMode) {
    if (!accessibilityMode) {
      NSLog(@"[ERROR] Ti.Identity: When using `accessControlMode` you must also specify the `accessibilityMode` property.");
    } else if ([accessControlMode isKindOfClass:[NSNumber class]]) {
      return [accessControlMode longLongValue];
    } else {
      NSLog(@"[WARN] Ti.Identity: The property \"accessControlMode\" must either be a single constant or an array of multiple constants.");
    }
  }

  return NULL;
}

@end

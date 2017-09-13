/**
 * Ti.Identity
 *
 * Created by Hans Knoechel
 * Copyright (c) 2017-present by Axway. All rights reserved.
 */

#import "TiModule.h"
#import <LocalAuthentication/LocalAuthentication.h>

@interface TiIdentityModule : TiModule {
  LAContext *_authContext;
  LAPolicy _authPolicy;
}

/**
   Determines if the current device supports Touch ID.
   @return YES if the current device supports Touch ID, NO otherwise.
 */
- (NSNumber *)isSupported:(id)unused;

/**
   Authenticates the user.
 */
- (void)authenticate:(id)args;

/**
   Invalidates the currently displayed Touch ID dialog if existing.
 */
- (void)invalidate:(id)unused;

/**
   Determines if the current device currently can authenticate with Touch ID.
   @return `NSDictionary` that contains infos about the device authentication.
 */
- (NSDictionary *)deviceCanAuthenticate:(id)unused;

@end

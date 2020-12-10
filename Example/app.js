/**
 * Ti.Identity
 * Copyright (c) 2017-present by Axway Appcelerator. All Rights Reserved.
 * Licensed under the terms of the Apache Public License
 * Please see the LICENSE included with this distribution for details.
 *
 */
var TiIdentity = require('ti.identity');
var isAndroid = Ti.Platform.name === 'android';
var isiOS = Ti.Platform.name === 'iOS' || Ti.Platform.name === 'iPhone OS';
var authPhrase = 'Fingerprint';
var authMsg = '(None available)';
var supported =  TiIdentity.isSupported();

var win = Ti.UI.createWindow();

// Using this constant, ios will offer to authenticate with Touch ID and Face ID and android will
// offer to authenticate with Touch ID.
// When calling "authenticate" below
TiIdentity.setAuthenticationPolicy(TiIdentity.AUTHENTICATION_POLICY_BIOMETRICS);

if (isAndroid) {

	if (TiIdentity.getAuthenticationPolicy() === TiIdentity.AUTHENTICATION_POLICY_BIOMETRICS) {
		authPhrase = 'Touch ID';
	} else if (TiIdentity.getAuthenticationPolicy() === TiIdentity.AUTHENTICATION_POLICY_PASSCODE) {
		authPhrase = 'Device Passcode';
	} else {
		authPhrase = authMsg;
	}
}

if (isiOS) {
	if (TiIdentity.biometryType === TiIdentity.BIOMETRY_TYPE_FACE_ID) {
		authPhrase = 'Face ID';
	} else if (TiIdentity.biometryType === TiIdentity.BIOMETRY_TYPE_TOUCH_ID) {
		authPhrase = 'Touch ID';
	} else {
		authPhrase = authMsg;
	}

}

var btn = Ti.UI.createButton({
	title: 'Authenticate with: ' + authPhrase
});

win.add(btn);
win.open();

btn.addEventListener('click', function () {
	if (!supported) {
		alert('Authentication is not supported on this device!'); // eslint-disable-line no-alert
		return;
	}

	TiIdentity.authenticate({
		reason: 'Can we access this content?',
		allowableReuseDuration: 30, // iOS 9+, optional, in seconds, only used for lockscreen-unlocks
		fallbackTitle: 'Use different auth method?', // iOS 10+, optional
		cancelTitle: 'Get me outta here!', // iOS 10+, optional
		callback: function (e) {
			TiIdentity.invalidate();
			if (!e.success) {
				alert('Error! Message: ' + e.error); // eslint-disable-line no-alert
				switch (e.code) {
					case TiIdentity.ERROR_AUTHENTICATION_FAILED: Ti.API.info('Error code is TiIdentity.ERROR_AUTHENTICATION_FAILED');
						break;
					case TiIdentity.ERROR_USER_CANCEL: Ti.API.info('Error code is TiIdentity.ERROR_USER_CANCEL');
						break;
					case TiIdentity.ERROR_USER_FALLBACK: Ti.API.info('Error code is TiIdentity.ERROR_USER_FALLBACK');
						break;
					case TiIdentity.ERROR_SYSTEM_CANCEL: Ti.API.info('Error code is TiIdentity.ERROR_SYSTEM_CANCEL');
						break;
					case TiIdentity.ERROR_PASSCODE_NOT_SET: Ti.API.info('Error code is TiIdentity.ERROR_PASSCODE_NOT_SET');
						break;
					case TiIdentity.ERROR_TOUCH_ID_NOT_AVAILABLE: Ti.API.info('Error code is TiIdentity.ERROR_TOUCH_ID_NOT_AVAILABLE');
						break;
					case TiIdentity.ERROR_TOUCH_ID_NOT_ENROLLED: Ti.API.info('Error code is TiIdentity.ERROR_TOUCH_ID_NOT_ENROLLED');
						break;
					case TiIdentity.ERROR_APP_CANCELLED: Ti.API.info('Error code is TiIdentity.ERROR_APP_CANCELLED');
						break;
					case TiIdentity.ERROR_INVALID_CONTEXT: Ti.API.info('Error code is TiIdentity.ERROR_INVALID_CONTEXT');
						break;
					case TiIdentity.ERROR_TOUCH_ID_LOCKOUT: Ti.API.info('Error code is TiIdentity.ERROR_TOUCH_ID_LOCKOUT');
						break;
					default: Ti.API.info('Error code is unknown');
						break;
				}
			} else {
				// do something useful
				alert('YAY! success'); // eslint-disable-line no-alert
				// Uncomment the next if you want to force the TouchID dialog to show every time
				// TiIdentity.invalidate();
			}
		}
	});

	// When uncommented, it should invalidate (hide) after 5 seconds
	setTimeout(function () {
		// TiIdentity.invalidate();
	}, 5000);
});

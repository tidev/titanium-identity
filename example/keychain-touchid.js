/**
 * Ti.Identity
 * Copyright (c) 2017-present by Axway Appcelerator. All Rights Reserved.
 * Licensed under the terms of the Apache Public License
 * Please see the LICENSE included with this distribution for details.
 *
 */
var TiIdentity = require('ti.identity');

var win = Ti.UI.createWindow({
	backgroundColor: '#fff',
	layout: 'vertical'
});

// -- IMPORTANT --
// This prefix is required for device and production builds
// and will be ignored for simulator builds. It is the Team-ID
// of your provisioning profile.
var appIdentifierPrefix = '<YOU-APP-IDENTIFIER-PREFIX>';

var keychainItem = TiIdentity.createKeychainItem({
	identifier: 'mypassword',
	accessGroup: appIdentifierPrefix + '.' + Ti.App.getId(),
	accessibilityMode: TiIdentity.ACCESSIBLE_WHEN_PASSCODE_SET_THIS_DEVICE_ONLY,
	accessControlMode: TiIdentity.ACCESS_CONTROL_TOUCH_ID_ANY,
	// Pass more native options to the keychain. Since there are hundrets of them,
	// look up the value of the constant and pass it here. Example:
	options: {
		// It's the value of kSecUseOperationPrompt
		u_OpPrompt: 'Please authenticate yourself before'
	}
});

keychainItem.addEventListener('save', function (e) {
	if (!e.success) {
		Ti.API.error('Error saving to the keychain: ' + e.error);
		return;
	}

	Ti.API.info('Successfully saved!');
	Ti.API.info(e);
});

keychainItem.addEventListener('read', function (e) {
	if (!e.success) {
		Ti.API.error('Error reading the keychain: ' + e.error);
		return;
	}

	Ti.API.info('Successfully read!');
	Ti.API.info(e);
});

keychainItem.addEventListener('reset', function (e) {
	if (!e.success) {
		Ti.API.error('Error resetting the keychain: ' + e.error);
		return;
	}

	Ti.API.info('Successfully resetted!');
});

var btnExists = Ti.UI.createButton({
	title: 'Exists?',
	top: 40
});

btnExists.addEventListener('click', function () {
	keychainItem.fetchExistence(function (e) {
		alert('Exists? ' + e.exists); // eslint-disable-line no-alert
	});
});

var btnSave = Ti.UI.createButton({
	title: 'Save password to keychain!',
	top: 40
});

btnSave.addEventListener('click', function () {
	keychainItem.save('s3cr3t_p4$$w0rd');
});

var btnRead = Ti.UI.createButton({
	title: 'Read password from keychain',
	top: 40
});

btnRead.addEventListener('click', function () {
	keychainItem.read();
});

var btnDelete = Ti.UI.createButton({
	title: 'Delete password from keychain',
	top: 40
});

btnDelete.addEventListener('click', function () {
	keychainItem.reset();
});

win.add(btnExists);
win.add(btnSave);
win.add(btnRead);
win.add(btnDelete);

win.open();

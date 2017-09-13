/**
 * Ti.Identity
 * Copyright (c) 2017-present by Axway Appcelerator. All Rights Reserved.
 * Licensed under the terms of the Apache Public License
 * Please see the LICENSE included with this distribution for details.
 *
 */
var TiIdentity = require('ti.identity');

// -- IMPORTANT --
// This prefix is required for device and production builds
// and will be ignored for simulator builds. It is the Team-ID 
// of your provisioning profile.
var appIdentifierPrefix = '<YOU-APP-IDENTIFIER-PREFIX>';

var win = Ti.UI.createWindow({
    backgroundColor: '#fff',
    layout: 'vertical'
});

var btnSave = Ti.UI.createButton({
    title: 'Save password to keychain!',
    top: 40
});

var keychainItem = TiIdentity.createKeychainItem({
    identifier: 'password',
    accessGroup: appIdentifierPrefix + '.' + Ti.App.getId()
});

keychainItem.addEventListener('save', function(e) {
    if (!e.success) {
        Ti.API.error('Error: ' + e.error);
        return;
    }
    
    Ti.API.info('Successfully saved!');
    Ti.API.info(e);
});

keychainItem.addEventListener('read', function(e) {
    if (!e.success) {
        Ti.API.error('Error: ' + e.error);
        return;
    }
    
    Ti.API.info('Successfully read!');
    Ti.API.info(e);
});

keychainItem.addEventListener('reset', function() {
    Ti.API.info('Successfully resetted!');
});

btnSave.addEventListener('click', function() {
    keychainItem.save('s3cr3t_p4$$w0rd');
});

var btnExists = Ti.UI.createButton({
    title: 'Exists?',
    top: 40
});

btnExists.addEventListener('click', function() {
    keychainItem.fetchExistence(function(e) {
        alert('Exists? ' + e.exists);
    });
});

var btnRead = Ti.UI.createButton({
    title: 'Read password from keychain',
    top: 40
});

btnRead.addEventListener('click', function() {
    keychainItem.read();
});

var btnUpdate = Ti.UI.createButton({
    title: 'Update password to keychain',
    top: 40
});

btnUpdate.addEventListener('click', function() {
    keychainItem.update('my_new_password');
});

var btnDelete = Ti.UI.createButton({
    title: 'Delete password from keychain',
    top: 40
});

btnDelete.addEventListener('click', function() {
    keychainItem.reset();
});

win.add(btnExists);
win.add(btnSave);
win.add(btnRead);
win.add(btnUpdate);
win.add(btnDelete);

win.open();

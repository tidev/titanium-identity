'use strict';

module.exports = config => {
	config.set({
		basePath: '../..',
		frameworks: [ 'jasmine' ],
		files: [
			'test/unit/specs/**/*spec.js'
		],
		reporters: [ 'mocha', 'junit' ],
		plugins: [
			'karma-*'
		],
		titanium: {
			sdkVersion: config.sdkVersion || '12.5.1.GA'
		},
		customLaunchers: {
			android: {
				base: 'Titanium',
				browserName: 'Android Emulator',
				displayName: 'android',
				platform: 'android'
			},
			ios: {
				base: 'Titanium',
				browserName: 'iOS Emulator',
				displayName: 'ios',
				platform: 'ios'
			}
		},
		browsers: [ 'android', 'ios' ],
		client: {
			jasmine: {
				random: false
			}
		},
		singleRun: true,
		retryLimit: 0,
		concurrency: 1,
		captureTimeout: 1200000,
		logLevel: config.LOG_DEBUG
	});
};

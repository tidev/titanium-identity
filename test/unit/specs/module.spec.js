const isIOS = Ti.Platform.osname === 'iphone' || Ti.Platform.osname === 'ipad';
const isIOS13 = isIOS && parseInt(Ti.Platform.version.split('.')[0]) >= 13;

let Identity;

describe('ti.identity', () => {
	it('can be required', () => {
		Identity = require('ti.identity');

		expect(Identity).toBeDefined();
	});

	describe('module', () => {
		it('.apiName', () => {
			expect(Identity.apiName).toBe('Ti.Identity');
		});

		describe('constants', () => {
			describe('AUTHENTICATION_POLICY_*', () => {
				it('AUTHENTICATION_POLICY_PASSCODE', () => {
					expect(Identity.AUTHENTICATION_POLICY_PASSCODE).toEqual(jasmine.any(Number));
				});

				it('AUTHENTICATION_POLICY_BIOMETRICS', () => {
					expect(Identity.AUTHENTICATION_POLICY_BIOMETRICS).toEqual(jasmine.any(Number));
				});

				if (isIOS13) {
					it('AUTHENTICATION_POLICY_BIOMETRICS_OR_WATCH', () => {
						expect(Identity.AUTHENTICATION_POLICY_BIOMETRICS_OR_WATCH).toEqual(jasmine.any(Number));
					});

					it('AUTHENTICATION_POLICY_WATCH', () => {
						expect(Identity.AUTHENTICATION_POLICY_WATCH).toEqual(jasmine.any(Number));
					});
				}
			});

			if (isIOS) {
				describe('BIOMETRY_TYPE_*', () => {
					it('BIOMETRY_TYPE_NONE', () => {
						expect(Identity.BIOMETRY_TYPE_NONE).toEqual(jasmine.any(Number));
					});

					it('BIOMETRY_TYPE_FACE_ID', () => {
						expect(Identity.BIOMETRY_TYPE_FACE_ID).toEqual(jasmine.any(Number));
					});

					it('BIOMETRY_TYPE_TOUCH_ID', () => {
						expect(Identity.BIOMETRY_TYPE_TOUCH_ID).toEqual(jasmine.any(Number));
					});
				});
			}

			describe('ERROR_*', () => {
				it('ERROR_AUTHENTICATION_FAILED', () => {
					expect(Identity.ERROR_AUTHENTICATION_FAILED).toEqual(jasmine.any(Number));
				});

				it('ERROR_PASSCODE_NOT_SET', () => {
					expect(Identity.ERROR_PASSCODE_NOT_SET).toEqual(jasmine.any(Number));
				});

				it('ERROR_TOUCH_ID_NOT_AVAILABLE', () => {
					expect(Identity.ERROR_TOUCH_ID_NOT_AVAILABLE).toEqual(jasmine.any(Number));
				});

				it('ERROR_TOUCH_ID_NOT_ENROLLED', () => {
					expect(Identity.ERROR_TOUCH_ID_NOT_ENROLLED).toEqual(jasmine.any(Number));
				});

				if (isIOS) {
					it('ERROR_SYSTEM_CANCEL', () => {
						expect(Identity.ERROR_SYSTEM_CANCEL).toEqual(jasmine.any(Number));
					});

					it('ERROR_USER_CANCEL', () => {
						expect(Identity.ERROR_USER_CANCEL).toEqual(jasmine.any(Number));
					});

					it('ERROR_USER_FALLBACK', () => {
						expect(Identity.ERROR_USER_FALLBACK).toEqual(jasmine.any(Number));
					});

					it('ERROR_APP_CANCELLED', () => {
						expect(Identity.ERROR_APP_CANCELLED).toEqual(jasmine.any(Number));
					});

					it('ERROR_INVALID_CONTEXT', () => {
						expect(Identity.ERROR_INVALID_CONTEXT).toEqual(jasmine.any(Number));
					});

					it('ERROR_BIOMETRY_LOCKOUT', () => {
						expect(Identity.ERROR_BIOMETRY_LOCKOUT).toEqual(jasmine.any(Number));
					});

					it('ERROR_BIOMETRY_NOT_AVAILABLE', () => {
						expect(Identity.ERROR_BIOMETRY_NOT_AVAILABLE).toEqual(jasmine.any(Number));
					});

					it('ERROR_BIOMETRY_NOT_ENROLLED', () => {
						expect(Identity.ERROR_BIOMETRY_NOT_ENROLLED).toEqual(jasmine.any(Number));
					});
				}

				it('ERROR_TOUCH_ID_LOCKOUT', () => {
					expect(Identity.ERROR_TOUCH_ID_LOCKOUT).toEqual(jasmine.any(Number));
				});
			});

			describe('ACCESSIBLE_*', () => {
				if (isIOS) {
					it('ACCESSIBLE_WHEN_UNLOCKED', () => {
						expect(Identity.ACCESSIBLE_WHEN_UNLOCKED).toEqual('ak');
					});

					it('ACCESSIBLE_AFTER_FIRST_UNLOCK', () => {
						expect(Identity.ACCESSIBLE_AFTER_FIRST_UNLOCK).toEqual('ck');
					});
				}

				it('ACCESSIBLE_ALWAYS', () => {
					if (isIOS) {
						expect(Identity.ACCESSIBLE_ALWAYS).toEqual('dk');
					} else {
						expect(Identity.ACCESSIBLE_ALWAYS).toEqual(jasmine.any(Number));
					}
				});

				it('ACCESSIBLE_WHEN_PASSCODE_SET_THIS_DEVICE_ONLY', () => {
					if (isIOS) {
						expect(Identity.ACCESSIBLE_WHEN_PASSCODE_SET_THIS_DEVICE_ONLY).toEqual('akpu');
					} else {
						expect(Identity.ACCESSIBLE_WHEN_PASSCODE_SET_THIS_DEVICE_ONLY).toEqual(jasmine.any(Number));
					}
				});

				if (isIOS) {
					it('ACCESSIBLE_WHEN_UNLOCKED_THIS_DEVICE_ONLY', () => {
						expect(Identity.ACCESSIBLE_WHEN_PASSCODE_SET_THIS_DEVICE_ONLY).toEqual('akpu');
					});

					it('ACCESSIBLE_AFTER_FIRST_UNLOCK_THIS_DEVICE_ONLY', () => {
						expect(Identity.ACCESSIBLE_AFTER_FIRST_UNLOCK_THIS_DEVICE_ONLY).toEqual('cku');
					});
				}

				it('ACCESSIBLE_ALWAYS_THIS_DEVICE_ONLY', () => {
					if (isIOS) {
						expect(Identity.ACCESSIBLE_ALWAYS_THIS_DEVICE_ONLY).toEqual('dku');
					} else {
						expect(Identity.ACCESSIBLE_ALWAYS_THIS_DEVICE_ONLY).toEqual(jasmine.any(Number));
					}
				});
			});

			describe('ACCESS_CONTROL_*', () => {
				it('ACCESS_CONTROL_USER_PRESENCE', () => {
					expect(Identity.ACCESS_CONTROL_USER_PRESENCE).toEqual(jasmine.any(Number));
				});

				it('ACCESS_CONTROL_TOUCH_ID_ANY', () => {
					expect(Identity.ACCESS_CONTROL_TOUCH_ID_ANY).toEqual(jasmine.any(Number));
				});

				it('ACCESS_CONTROL_TOUCH_ID_CURRENT_SET', () => {
					expect(Identity.ACCESS_CONTROL_TOUCH_ID_CURRENT_SET).toEqual(jasmine.any(Number));
				});

				it('ACCESS_CONTROL_DEVICE_PASSCODE', () => {
					expect(Identity.ACCESS_CONTROL_DEVICE_PASSCODE).toEqual(jasmine.any(Number));
				});

				if (isIOS) {
					it('ACCESS_CONTROL_OR', () => {
						expect(Identity.ACCESS_CONTROL_OR).toEqual(jasmine.any(Number));
					});

					it('ACCESS_CONTROL_AND', () => {
						expect(Identity.ACCESS_CONTROL_AND).toEqual(jasmine.any(Number));
					});

					it('ACCESS_CONTROL_PRIVATE_KEY_USAGE', () => {
						expect(Identity.ACCESS_CONTROL_PRIVATE_KEY_USAGE).toEqual(jasmine.any(Number));
					});

					it('ACCESS_CONTROL_APPLICATION_PASSWORD', () => {
						expect(Identity.ACCESS_CONTROL_APPLICATION_PASSWORD).toEqual(jasmine.any(Number));
					});
				}
			});
		});

		describe('properties', () => {
			describe('authenticationPolicy', () => {
				it('defaults to AUTHENTICATION_POLICY_BIOMETRICS', () => {
					expect(Identity.authenticationPolicy).toEqual(Identity.AUTHENTICATION_POLICY_BIOMETRICS);
				});
			});

			if (isIOS) {
				describe('biometryType', () => {
					it('defaults to BIOMETRY_TYPE_NONE', () => {
						expect(Identity.biometryType).toEqual(Identity.BIOMETRY_TYPE_NONE);
					});
				});
			}
		});

		describe('methods', () => {
			describe('#authenticate()', () => {
				it('is a Function', () => {
					expect(Identity.authenticate).toEqual(jasmine.any(Function));
				});
			});

			describe('#deviceCanAuthenticate()', () => {
				it('is a Function', () => {
					expect(Identity.deviceCanAuthenticate).toEqual(jasmine.any(Function));
				});

				it('returns an Object', () => {
					expect(Identity.deviceCanAuthenticate()).toEqual(jasmine.any(Object));
				});

				it('check value of canAuthenticate after assignement', () => {
					var result = Identity.deviceCanAuthenticate();
					result.canAuthenticate = true;

					expect(result.canAuthenticate).toEqual(true);
				});
			});

			describe('#invalidate()', () => {
				it('is a Function', () => {
					expect(Identity.invalidate).toEqual(jasmine.any(Function));
				});
			});

			describe('#isSupported()', () => {
				it('is a Function', () => {
					expect(Identity.isSupported).toEqual(jasmine.any(Function));
				});

				it('returns a Boolean', () => {
					expect(Identity.isSupported()).toEqual(jasmine.any(Boolean));
				});
			});
		});
	});
});

/**
 * Axway Appcelerator Titanium - Ti.Identity
 * Copyright (c) 2017 by Axway. All Rights Reserved.
 * Licensed under the terms of the Apache Public License
 * Please see the LICENSE included with this distribution for details.
 */
package ti.identity;

import org.appcelerator.kroll.KrollModule;
import org.appcelerator.kroll.annotations.Kroll;
import org.appcelerator.titanium.TiApplication;
import org.appcelerator.kroll.KrollDict;
import org.appcelerator.kroll.KrollFunction;

import java.lang.Override;
import java.util.HashMap;

import android.app.Activity;
import android.os.Build;

@Kroll.module(name="TitaniumIdentity", id="ti.identity")
public class TitaniumIdentityModule extends KrollModule
{
	public static final int PERMISSION_CODE_FINGERPRINT = 99;

	@Kroll.constant public static final int SUCCESS = 0;
	@Kroll.constant public static final int SERVICE_MISSING = 1;
	@Kroll.constant public static final int SERVICE_VERSION_UPDATE_REQUIRED = 2;
	@Kroll.constant public static final int SERVICE_DISABLED = 3;
	@Kroll.constant public static final int SERVICE_INVALID = 9;

	@Kroll.constant public static final int ACCESSIBLE_ALWAYS = KeychainItemProxy.ACCESSIBLE_ALWAYS;
	@Kroll.constant public static final int ACCESSIBLE_ALWAYS_THIS_DEVICE_ONLY = KeychainItemProxy.ACCESSIBLE_ALWAYS_THIS_DEVICE_ONLY;
	@Kroll.constant public static final int ACCESSIBLE_WHEN_PASSCODE_SET_THIS_DEVICE_ONLY = KeychainItemProxy.ACCESSIBLE_WHEN_PASSCODE_SET_THIS_DEVICE_ONLY;

	@Kroll.constant public static final int ACCESS_CONTROL_USER_PRESENCE = KeychainItemProxy.ACCESS_CONTROL_USER_PRESENCE;
	@Kroll.constant public static final int ACCESS_CONTROL_DEVICE_PASSCODE = KeychainItemProxy.ACCESS_CONTROL_DEVICE_PASSCODE;
	@Kroll.constant public static final int ACCESS_CONTROL_TOUCH_ID_ANY = KeychainItemProxy.ACCESS_CONTROL_TOUCH_ID_ANY;
	@Kroll.constant public static final int ACCESS_CONTROL_TOUCH_ID_CURRENT_SET = KeychainItemProxy.ACCESS_CONTROL_TOUCH_ID_CURRENT_SET;

	protected FingerPrintHelper mfingerprintHelper;

	public TitaniumIdentityModule() {
		super();
		Activity activity = TiApplication.getAppRootOrCurrentActivity();
		if (Build.VERSION.SDK_INT >= 23) {
			try {
				mfingerprintHelper = new FingerPrintHelper();
			} catch (Exception e) {
				mfingerprintHelper = null;
			}
		}
	}

	@Kroll.method
	public void authenticate(HashMap params) {
		if (params == null || mfingerprintHelper == null) {
			return;
		}
		if (params.containsKey("callback")) {
			Object callback = params.get("callback");
			if (callback instanceof KrollFunction) {
				mfingerprintHelper.startListening((KrollFunction)callback, getKrollObject());
			}
		}
	}

	@Kroll.method
	public HashMap deviceCanAuthenticate() {
		if (Build.VERSION.SDK_INT >= 23 && mfingerprintHelper != null) {
			return mfingerprintHelper.deviceCanAuthenticate();
		}

		KrollDict response = new KrollDict();
		response.put("canAuthenticate", false);

		if (Build.VERSION.SDK_INT < 23) {
			response.put("error", "Device is running with API < 23");
		} else {
			response.put("error", "Device does not support fingerprint authentication");
		}

		return response;
	}

	@Kroll.method
	public boolean isSupported() {
		if (Build.VERSION.SDK_INT >= 23 && mfingerprintHelper != null) {
			return mfingerprintHelper.isDeviceSupported();
		}
		return false;
	}
	
	@Override
	public void onPause(Activity activity) {
		super.onPause(activity);	
		if (mfingerprintHelper != null) {
			mfingerprintHelper.stopListening();
		}	
	}

	@Kroll.method
	public void invalidate() {
		if (mfingerprintHelper != null) {
			mfingerprintHelper.stopListening();
		}
	}
}

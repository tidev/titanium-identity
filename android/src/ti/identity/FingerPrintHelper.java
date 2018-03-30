/**
 * Axway Appcelerator Titanium - ti.identity
 * Copyright (c) 2017 by Axway. All Rights Reserved.
 * Licensed under the terms of the Apache Public License
 * Please see the LICENSE included with this distribution for details.
 */
package ti.identity;

import android.app.Activity;
import android.app.KeyguardManager;
import android.hardware.fingerprint.FingerprintManager;
import android.os.Build;
import android.os.CancellationSignal;
import android.security.keystore.KeyGenParameterSpec;
import android.security.keystore.KeyPermanentlyInvalidatedException;
import android.security.keystore.KeyProperties;
import android.util.Base64;

import org.appcelerator.kroll.KrollDict;
import org.appcelerator.kroll.KrollFunction;
import org.appcelerator.kroll.KrollObject;
import org.appcelerator.titanium.TiApplication;
import org.appcelerator.kroll.common.Log;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.Iterator;
import java.util.Map;

public class FingerPrintHelper extends FingerprintManager.AuthenticationCallback {

	protected KeyguardManager mKeyguardManager;
	protected FingerprintManager mFingerprintManager;

	protected KeyStore mKeyStore;
	protected KeyGenerator mKeyGenerator;
	protected Cipher mCipher;
	private static Map<CancellationSignal, KeychainItemProxy> cancellationSignals = new HashMap<>();
	protected FingerprintManager.CryptoObject mCryptoObject;
	private static final String KEY_NAME = "appc_key";
	private static final String SECRET_MESSAGE = "secret message";
	private static String TAG = "FingerPrintHelper";
	private KrollFunction callback;
	private KrollObject krollObject;
	protected boolean mSelfCancelled;
	private boolean mGeneratedKey = false;

	public FingerPrintHelper() {
		Activity activity = TiApplication.getAppRootOrCurrentActivity();
		mFingerprintManager = activity.getSystemService(FingerprintManager.class);
		mKeyguardManager = activity.getSystemService(KeyguardManager.class);
		
		try {
			mKeyStore = KeyStore.getInstance("AndroidKeyStore");
			mKeyGenerator = KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, "AndroidKeyStore");
			mCipher = Cipher.getInstance(KeyProperties.KEY_ALGORITHM_AES + "/"
					+ KeyProperties.BLOCK_MODE_CBC + "/"
					+ KeyProperties.ENCRYPTION_PADDING_PKCS7);
			
		} catch (KeyStoreException e) {
			throw new RuntimeException("Failed to get an instance of KeyStore", e);
		} catch (Exception e) {
			throw new RuntimeException("Unknown Ti.Identity exception thrown", e);
		}
	}

	public static CancellationSignal cancellationSignal(KeychainItemProxy keychainItemProxy) {
		CancellationSignal signal = new CancellationSignal();
		cancellationSignals.put(signal, keychainItemProxy);
		return signal;
	}

	public static CancellationSignal cancellationSignal() {
		return cancellationSignal(null);
	}

	protected boolean isDeviceSupported() {
		if (Build.VERSION.SDK_INT >= 23 && mFingerprintManager != null) {
			return mFingerprintManager.isHardwareDetected();
		}
		return false;
	}

	public void stopListening() {
		Iterator cancellationSignalIterator = cancellationSignals.entrySet().iterator();

		while (cancellationSignalIterator.hasNext()) {
			Map.Entry entry = (Map.Entry) cancellationSignalIterator.next();
			CancellationSignal signal = (CancellationSignal) entry.getKey();
			KeychainItemProxy keychainItemProxy = (KeychainItemProxy) entry.getValue();

			if (signal != null) {
				signal.cancel();
				if (keychainItemProxy != null) {
					keychainItemProxy.resetEvents();
				}
				cancellationSignalIterator.remove();
			}
		}
	}

	public void startListening(KrollFunction callback, KrollObject obj) {
		if (!(mFingerprintManager.isHardwareDetected() && mFingerprintManager.hasEnrolledFingerprints())) {
			return;
		}
        
		try {
			if (initCipher()) {
				mCryptoObject = new FingerprintManager.CryptoObject(mCipher);
			} else {
				Log.e(TAG, "Unable to initialize cipher");
			}
		} catch (Exception e) {
			Log.e(TAG, "Unable to initialize cipher");
		}
        
		this.callback = callback;
		this.krollObject = obj;

		mSelfCancelled = false;
		mFingerprintManager
				.authenticate(mCryptoObject, cancellationSignal(), 0 /* flags */, this, null);
	}

	private void onError(String errMsg) {
		if (callback != null && krollObject != null) {
			KrollDict dict = new KrollDict();
			dict.put("success", false);
			dict.put("error", errMsg);
			callback.callAsync(krollObject, dict);
		}
	}

	/**
	 * Tries to encrypt some data with the generated key in {@link #createKey} which is
	 * only works if the user has just authenticated via fingerprint.
	 */
	private void tryEncrypt() {
		try {
			byte[] encrypted = mCipher.doFinal(SECRET_MESSAGE.getBytes());
			if (callback != null && krollObject != null) {
				KrollDict dict = new KrollDict();
				dict.put("success", true);
				dict.put("message", Base64.encodeToString(encrypted, 0));
				callback.callAsync(krollObject, dict);
			}
		} catch (Exception e) {
			onError("Failed to encrypt the data with the generated key.");
		}
	}

	@Override
	public void onAuthenticationError(int errMsgId, CharSequence errString) {
		onError(errString.toString());
	}

	@Override
	public void onAuthenticationHelp(int helpMsgId, CharSequence helpString) {
		Log.w(TAG, helpString.toString());

	}

	@Override
	public void onAuthenticationFailed() {
		onError("Unable to recognize fingerprint");

	}

	@Override
	public void onAuthenticationSucceeded(FingerprintManager.AuthenticationResult result) {
		tryEncrypt();
	}

	/**
	 * Creates a symmetric key in the Android Key Store which can only be used after the user has
	 * authenticated with fingerprint.
	 */
	protected void createKey() {
		if (mGeneratedKey) {
			return;
		}

		// The enrolling flow for fingerprint. This is where you ask the user to set up fingerprint
		// for your flow. Use of keys is necessary if you need to know if the set of
		// enrolled fingerprints has changed.
		try {
			mKeyStore.load(null);

			mKeyGenerator.init(new KeyGenParameterSpec.Builder(KEY_NAME,
					KeyProperties.PURPOSE_ENCRYPT |
							KeyProperties.PURPOSE_DECRYPT)
					.setBlockModes(KeyProperties.BLOCK_MODE_CBC)
					.setUserAuthenticationRequired(true)
					.setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_PKCS7)
					.build());

			mKeyGenerator.generateKey();

			mGeneratedKey = true;
		} catch (Exception e) {
			throw new RuntimeException(e);
		}
	}

	private boolean initCipher() {
		try {
			createKey();
			SecretKey key = (SecretKey) mKeyStore.getKey(KEY_NAME, null);
			mCipher.init(Cipher.ENCRYPT_MODE, key);
			return true;
		} catch (KeyPermanentlyInvalidatedException e) {
			return false;
		} catch (Exception e) {
			throw new RuntimeException("Failed to init Cipher", e);
		}
	}

	public KrollDict deviceCanAuthenticate(int policy) {
		String error = "";
		KrollDict response = new KrollDict();

		boolean hardwareDetected = false;
		boolean hasFingerprints = false;
		boolean hasPasscode = false;

		try {
			hardwareDetected = mFingerprintManager.isHardwareDetected();
			hasFingerprints = hardwareDetected && mFingerprintManager.hasEnrolledFingerprints();
			hasPasscode = mKeyguardManager.isDeviceSecure();
		} catch (Exception e) {
			// ignore, error gracefully
		}

		if (!hardwareDetected) {
			error = error + "Hardware not detected";
		}
		if (policy == TitaniumIdentityModule.AUTHENTICATION_POLICY_PASSCODE && !hasPasscode) {
			if (error.isEmpty()) {
				error = error + "Device is not secure, passcode not set";
			} else {
				error = error +", and no passcode detected";
			}
			response.put("code", TitaniumIdentityModule.ERROR_PASSCODE_NOT_SET);
		} else if (policy == TitaniumIdentityModule.AUTHENTICATION_POLICY_BIOMETRICS && !hasFingerprints) {
			if (error.isEmpty()) {
				error = error + "No enrolled fingerprints";
			} else {
				error = error +", and no enrolled fingerprints";
			}
			response.put("code", TitaniumIdentityModule.ERROR_TOUCH_ID_NOT_ENROLLED);
		}

		if (error.isEmpty()) {
			response.put("canAuthenticate", true);
			response.put("canAuthenticate", true);
		} else {
			response.put("canAuthenticate", false);
			response.put("error", error);
			if (!response.containsKey("code")) {
				response.put("code", TitaniumIdentityModule.ERROR_TOUCH_ID_NOT_AVAILABLE);
			}
		}
		return response;
	}
}

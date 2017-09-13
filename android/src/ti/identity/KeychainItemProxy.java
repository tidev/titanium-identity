/**
 * Axway Appcelerator Titanium - Ti.Identity
 * Copyright (c) 2017 by Axway. All Rights Reserved.
 * Licensed under the terms of the Apache Public License
 * Please see the LICENSE included with this distribution for details.
 */
package ti.identity;

import org.appcelerator.kroll.KrollFunction;
import org.appcelerator.kroll.common.Log;
import org.appcelerator.kroll.annotations.Kroll;
import org.appcelerator.kroll.KrollDict;
import org.appcelerator.kroll.KrollProxy;
import org.appcelerator.titanium.TiApplication;

import android.content.Context;
import android.hardware.fingerprint.FingerprintManager;
import android.hardware.fingerprint.FingerprintManager.CryptoObject;
import android.hardware.fingerprint.FingerprintManager.AuthenticationCallback;
import android.os.Build;
import android.security.keystore.KeyGenParameterSpec;
import android.security.keystore.KeyProperties;

import java.io.BufferedInputStream;
import java.io.BufferedOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.security.KeyStore;
import java.util.ArrayList;
import java.util.List;
import javax.crypto.Cipher;
import javax.crypto.CipherInputStream;
import javax.crypto.CipherOutputStream;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;

@Kroll.proxy(creatableInModule=TitaniumIdentityModule.class)
public class KeychainItemProxy extends KrollProxy {

	private static final String TAG = "KeychainItem";

	public static final String PROPERTY_IDENTIFIER = "identifier";
	public static final String PROPERTY_CIPHER = "cipher";
	public static final String PROPERTY_ACCESSIBILITY_MODE = "accessibilityMode";
	public static final String PROPERTY_ACCESS_CONTROL_MODE = "accessControlMode";

	public static final String EVENT_SAVE = "save";
	public static final String EVENT_READ = "read";
	public static final String EVENT_UPDATE = "update";
	public static final String EVENT_RESET = "reset";

	public static final int ACCESSIBLE_ALWAYS = 0;
	public static final int ACCESSIBLE_ALWAYS_THIS_DEVICE_ONLY = 1;
	public static final int ACCESSIBLE_WHEN_PASSCODE_SET_THIS_DEVICE_ONLY = 2;

	public static final int ACCESS_CONTROL_USER_PRESENCE = 1;
	public static final int ACCESS_CONTROL_DEVICE_PASSCODE = 2;
	public static final int ACCESS_CONTROL_TOUCH_ID_ANY = 3;
	public static final int ACCESS_CONTROL_TOUCH_ID_CURRENT_SET = 4;

	private KeyStore keyStore;
	private SecretKey key;
	private Cipher cipher;
	private int ivSize = 16;
	private CryptoObject cryptoObject;

	private String algorithm = KeyProperties.KEY_ALGORITHM_AES;
	private String blockMode = KeyProperties.BLOCK_MODE_CBC;
	private String padding = KeyProperties.ENCRYPTION_PADDING_PKCS7;

	private FingerprintManager fingerprintManager;
	private AuthenticationCallback authenticationCallback;

	private String identifier = "";
	private int accessibilityMode = 0;
	private int accessControlMode = 0;
	private String suffix = "_kc.dat";
	private Context context;

	private class EVENT {
		public final String event;
		public final String value;

		public EVENT(String event, String value) {
			this.event = event;
			this.value = value;
		}

		public EVENT(String event) {
			this.event = event;
			this.value = null;
		}
	}
	private List<EVENT> eventQueue = new ArrayList<EVENT>();
	private boolean eventBusy = false;

	public KeychainItemProxy() {
		super();

		defaultValues.put(PROPERTY_ACCESSIBILITY_MODE, 0);
		defaultValues.put(PROPERTY_ACCESS_CONTROL_MODE, 0);
		defaultValues.put(PROPERTY_CIPHER, getCipher());

		try {
			context = TiApplication.getAppRootOrCurrentActivity();

			// fingerprint authentication
			fingerprintManager = context.getSystemService(FingerprintManager.class);
			authenticationCallback = new AuthenticationCallback() {
				@Override
				public void onAuthenticationError(int errorCode, CharSequence errString) {
					super.onAuthenticationError(errorCode, errString);
					Log.e(TAG, errString.toString());
				}

				@Override
				public void onAuthenticationHelp(int helpCode, CharSequence helpString) {
					super.onAuthenticationHelp(helpCode, helpString);
					Log.w(TAG, helpString.toString());
				}

				@Override
				public void onAuthenticationSucceeded(FingerprintManager.AuthenticationResult result) {
					super.onAuthenticationSucceeded(result);
					doEvents();
				}

				@Override
				public void onAuthenticationFailed() {
					super.onAuthenticationFailed();
					Log.e(TAG, "failed to authenticate fingerprint!");
				}
			};

			// load Android key store
			keyStore = KeyStore.getInstance("AndroidKeyStore");
			keyStore.load(null);

		} catch (Exception e) {
			Log.e(TAG, "could not load Android key store: " + e.getMessage());
		}
	}

	@Kroll.getProperty @Kroll.method
	public int getAccessibilityMode() {
		return accessibilityMode;
	}

	@Kroll.getProperty @Kroll.method
	public int getAccessControlMode() {
		return accessControlMode;
	}

	@Kroll.getProperty @Kroll.method
	private String getCipher() {
		return algorithm + "/" + blockMode + "/" + padding;
	}

	@Kroll.getProperty @Kroll.method
	private String getIdentifier() {
		return identifier;
	}

	private boolean useFingerprintAuthentication() {
		if ((accessControlMode & (ACCESS_CONTROL_TOUCH_ID_ANY | ACCESS_CONTROL_TOUCH_ID_CURRENT_SET)) != 0) {
			return true;
		}
		return false;
	}

	private void processEvents() {
		if (!eventBusy && !eventQueue.isEmpty()) {
			eventBusy = true;

			EVENT e = eventQueue.get(0);
			KrollDict result = null;
			switch (e.event) {
				case EVENT_UPDATE:
				case EVENT_SAVE:
					result = initEncrypt();
					break;
				case EVENT_READ:
					result = initDecrypt();
					break;
				case EVENT_RESET:
					result = doReset();
					break;
			}
			if (result != null) {
				fireEvent(e.event, result);
				eventQueue.remove(e);
				eventBusy = false;
				processEvents();
			} else if (!useFingerprintAuthentication()) {
				doEvents();
			}
		}
	}

	private void doEvents() {
		EVENT e = eventQueue.get(0);
		switch (e.event) {
			case EVENT_UPDATE:
				if (!exists()) {
					KrollDict result = new KrollDict();
					result.put("success", false);
					result.put("code", -1);
					result.put("error", "could not update, item does not exist.");
					fireEvent(e.event, result);
					break;
				}
			case EVENT_SAVE:
				fireEvent(e.event, doEncrypt(e.value));
				break;
			case EVENT_READ:
				fireEvent(e.event, doDecrypt());
				break;
		}
		eventQueue.remove(e);

		eventBusy = false;
		processEvents();
	}

	private KrollDict initEncrypt() {
		try {
			// initialize encryption cipher
			cipher.init(Cipher.ENCRYPT_MODE, key);

			// fingerprint authentication
			if (useFingerprintAuthentication()) {
				fingerprintManager.authenticate(cryptoObject, null, 0, authenticationCallback, null);
			}

		} catch (Exception e) {
			KrollDict result = new KrollDict();
			result.put("identifier", identifier);
			result.put("success", false);
			result.put("code", -1);
			result.put("error", e.getMessage());
			return result;
		}
		return null;
	}

	private KrollDict doEncrypt(String value) {
		KrollDict result = new KrollDict();
		result.put("identifier", identifier);
		try {
			// save encrypted data to private storage
			FileOutputStream fos = context.openFileOutput(identifier + suffix, Context.MODE_PRIVATE);

			// write IV
			fos.write(cipher.getIV());

			// write encrypted data
			CipherOutputStream cos = new CipherOutputStream(new BufferedOutputStream(fos), cipher);
			cos.write(value.getBytes("UTF-8"));
			cos.close();

			result.put("success", true);
			result.put("code", 0);
		} catch (Exception e) {
			result.put("success", false);
			result.put("code", -1);
			result.put("error", e.getMessage());
		}
		return result;
	}

	private KrollDict initDecrypt() {
		try {
			// load file from private storage
			FileInputStream fin = context.openFileInput(identifier + suffix);

			// read IV
			byte[] iv = new byte[ivSize];
			fin.read(iv, 0, iv.length);
			fin.close();

			// initialize decryption cipher
			cipher.init(Cipher.DECRYPT_MODE, key, new IvParameterSpec(iv));

			// fingerprint authentication
			if (useFingerprintAuthentication()) {
				fingerprintManager.authenticate(cryptoObject, null, 0, authenticationCallback, null);
			}

		} catch (Exception e) {
			KrollDict result = new KrollDict();
			result.put("identifier", identifier);
			result.put("success", false);
			result.put("code", -1);
			if (e instanceof FileNotFoundException) {
				result.put("error", "keychain data does not exist!");
			} else {
				result.put("error", e.getMessage());
			}
			return result;
		}
		return null;
	}

	private KrollDict doDecrypt() {
		KrollDict result = new KrollDict();
		result.put("identifier", identifier);
		try {
			// load file from private storage
			FileInputStream fin = context.openFileInput(identifier + suffix);
			fin.skip(ivSize);

			// read decrypted data
			CipherInputStream cis = new CipherInputStream(new BufferedInputStream(fin), cipher);
			byte[] buffer = new byte[64];
			int length = 0;
			int total = 0;
			String decrypted = "";
			while ((length = cis.read(buffer)) != -1) {
				// since we only encrypt strings, this is acceptable
				decrypted += new String(buffer, "UTF-8");
				total += length;
			}
			decrypted = decrypted.substring(0, total);

			result.put("success", true);
			result.put("code", 0);
			result.put("value", decrypted);
		} catch (Exception e) {
			result.put("success", false);
			result.put("code", -1);
			if (e instanceof FileNotFoundException) {
				result.put("error", "keychain data does not exist!");
			} else {
				result.put("error", e.getMessage());
			}
		}
		return result;
	}

	private KrollDict doReset() {
		KrollDict result = new KrollDict();
		boolean deleted = false;

		// delete file from private storage
		File file = new File(identifier + suffix);
		if (file != null) {
			deleted = context.deleteFile(identifier + suffix);

			// remove key from Android key store
			if (deleted) {
				try {
					keyStore.deleteEntry(identifier);
				} catch (Exception e) {
					deleted = false;
					result.put("error", "could not remove key");
				}
			} else {
				result.put("error", "could not delete data");
			}
		}

		result.put("success", deleted);
		result.put("code", deleted ? 0 : -1);
		return result;
	}

	private boolean exists() {
		return new File(identifier + suffix) != null;
	}

	@Kroll.method
	public void save(String value) {
		eventQueue.add(new EVENT(EVENT_SAVE, value));
		processEvents();
	}

	@Kroll.method
	public void read() {
		eventQueue.add(new EVENT(EVENT_READ));
		processEvents();
	}

	@Kroll.method
	public void update(String value) {
		eventQueue.add(new EVENT(EVENT_UPDATE, value));
		processEvents();
	}

	@Kroll.method
	public void reset() {
		eventQueue.add(new EVENT(EVENT_RESET));
		processEvents();
	}

	@Kroll.method
	public void fetchExistence(Object callback) {
		if (callback instanceof KrollFunction) {
			KrollDict result = new KrollDict();
			result.put("exists", exists());
			((KrollFunction) callback).callAsync(krollObject, new Object[]{result});
		}
	}

	@Override
	public void handleCreationDict(KrollDict dict) {
		super.handleCreationDict(dict);

		if (dict.containsKey(PROPERTY_CIPHER)) {
			String[] cipher = dict.getString(PROPERTY_CIPHER).split("/");
			if (cipher.length == 3) {
				algorithm = cipher[0];
				blockMode = cipher[1];
				padding = cipher[2];

				// set IV size
				ivSize = blockMode == KeyProperties.BLOCK_MODE_GCM ? 12 : 16;
			}
		}
		if (dict.containsKey(PROPERTY_ACCESSIBILITY_MODE)) {
			accessibilityMode = dict.getInt(PROPERTY_ACCESSIBILITY_MODE);
		}
		if (dict.containsKey(PROPERTY_ACCESS_CONTROL_MODE)) {
			accessControlMode = dict.getInt(PROPERTY_ACCESS_CONTROL_MODE);
		}
		if (dict.containsKey(PROPERTY_IDENTIFIER)) {
			identifier = dict.getString(PROPERTY_IDENTIFIER);
			if (!identifier.isEmpty()) {
				try {
					if (!keyStore.containsAlias(identifier)) {
						KeyGenerator generator = KeyGenerator.getInstance(algorithm, "AndroidKeyStore");
						KeyGenParameterSpec.Builder spec = new KeyGenParameterSpec.Builder(identifier,
								KeyProperties.PURPOSE_ENCRYPT | KeyProperties.PURPOSE_DECRYPT)
								.setBlockModes(blockMode)
								.setEncryptionPaddings(padding);

						if ((accessibilityMode & (ACCESSIBLE_ALWAYS_THIS_DEVICE_ONLY | ACCESSIBLE_WHEN_PASSCODE_SET_THIS_DEVICE_ONLY)) != 0 ||
								(accessControlMode & (ACCESS_CONTROL_USER_PRESENCE | ACCESS_CONTROL_DEVICE_PASSCODE | ACCESS_CONTROL_TOUCH_ID_ANY | ACCESS_CONTROL_TOUCH_ID_CURRENT_SET)) != 0) {
							spec.setUserAuthenticationRequired(true);
						}
						if ((accessControlMode & ACCESS_CONTROL_TOUCH_ID_CURRENT_SET) != 0 && Build.VERSION.SDK_INT >= 24) {
							spec.setInvalidatedByBiometricEnrollment(true);
						}

						generator.init(spec.build());
						key = generator.generateKey();
					} else {
						key = (SecretKey) keyStore.getKey(identifier, null);
					}
					cipher = Cipher.getInstance(getCipher());
					cryptoObject = new FingerprintManager.CryptoObject(cipher);
				} catch (Exception e) {
					Log.e(TAG, e.toString());
				}
			}
		}
	}

	@Override
	public String getApiName() {
		return "ti.identity.KeychainItem";
	}
}

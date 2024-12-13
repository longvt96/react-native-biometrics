package com.rnbiometrics;

import android.os.Build;
import android.security.keystore.KeyGenParameterSpec;
import android.security.keystore.KeyProperties;
import android.util.Base64;

import androidx.biometric.BiometricManager;
import androidx.biometric.BiometricPrompt;
import androidx.biometric.BiometricPrompt.AuthenticationCallback;
import androidx.biometric.BiometricPrompt.PromptInfo;
import androidx.fragment.app.FragmentActivity;

import android.content.Context;
import android.content.Intent;
import android.provider.Settings;
import android.util.Pair;

import com.facebook.react.bridge.Promise;
import com.facebook.react.bridge.ReactApplicationContext;
import com.facebook.react.bridge.ReactContextBaseJavaModule;
import com.facebook.react.bridge.ReactMethod;
import com.facebook.react.bridge.ReadableMap;
import com.facebook.react.bridge.UiThreadUtil;
import com.facebook.react.bridge.WritableMap;
import com.facebook.react.bridge.WritableNativeMap;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.security.spec.RSAKeyGenParameterSpec;
import java.util.concurrent.Executor;
import java.util.concurrent.Executors;
import android.content.pm.PackageManager;

import android.app.Activity;
import com.facebook.react.bridge.ActivityEventListener;
import androidx.annotation.Nullable;

/**
 * Created by brandon on 4/5/18.
 */

public class ReactNativeBiometrics extends ReactContextBaseJavaModule {

    protected String biometricKeyAlias = "biometric_key";
    private static final int BIOMETRIC_ENROLL_REQUEST_CODE = 1001;
    private Promise enrollmentPromise;

    public ReactNativeBiometrics(ReactApplicationContext reactContext) {
        super(reactContext);

        reactContext.addActivityEventListener(new ActivityEventListener() {
            @Override
            public void onActivityResult(Activity activity, int requestCode, int resultCode, @Nullable Intent data) {
                if (requestCode == BIOMETRIC_ENROLL_REQUEST_CODE) {
                    // Resolve or reject the promise based on result
                    if (resultCode == Activity.RESULT_OK) {
                        WritableMap resultMap = new WritableNativeMap();
                        resultMap.putBoolean("success", true);
                        enrollmentPromise.resolve(resultMap);
                    } else {
                        WritableMap resultMap = new WritableNativeMap();
                        resultMap.putBoolean("success", false);
                        enrollmentPromise.resolve(resultMap);
                    }
                }
            }

            @Override
            public void onNewIntent(Intent intent) {}
        });
    }

    @Override
    public String getName() {
        return "ReactNativeBiometrics";
    }

    @ReactMethod
    public void isSensorAvailable(final ReadableMap params, final Promise promise) {
        try {
            if (isCurrentSDKMarshmallowOrLater()) {
                boolean allowDeviceCredentials = params.getBoolean("allowDeviceCredentials");
                ReactApplicationContext reactApplicationContext = getReactApplicationContext();
                BiometricManager biometricManager = BiometricManager.from(reactApplicationContext);
                int canAuthenticate = biometricManager.canAuthenticate(getAllowedAuthenticators(allowDeviceCredentials));

                if (canAuthenticate == BiometricManager.BIOMETRIC_SUCCESS) {
                    WritableMap resultMap = new WritableNativeMap();
                    resultMap.putBoolean("available", true);
                    Pair<String, Boolean> biometryType = BiometricUtils.getBiometricType(reactApplicationContext);
                    resultMap.putString("biometryType", biometryType.first );
                    resultMap.putString("isBiometricEnrolled", biometryType.second ? "YES" : "NO");
                    promise.resolve(resultMap);
                } else {
                    WritableMap resultMap = new WritableNativeMap();
                    resultMap.putBoolean("available", false);

                    switch (canAuthenticate) {
                        case BiometricManager.BIOMETRIC_ERROR_NO_HARDWARE:
                            resultMap.putString("error", "BIOMETRIC_ERROR_NO_HARDWARE");
                            break;
                        case BiometricManager.BIOMETRIC_ERROR_HW_UNAVAILABLE:
                            resultMap.putString("error", "BIOMETRIC_ERROR_HW_UNAVAILABLE");
                            break;
                        case BiometricManager.BIOMETRIC_ERROR_NONE_ENROLLED:
                            resultMap.putString("error", "BIOMETRIC_ERROR_NONE_ENROLLED");
                            break;
                    }

                    promise.resolve(resultMap);
                }
            } else {
                WritableMap resultMap = new WritableNativeMap();
                resultMap.putBoolean("available", false);
                resultMap.putString("error", "Unsupported android version");
                promise.resolve(resultMap);
            }
        } catch (Exception e) {
            promise.reject("Error detecting biometrics availability: " + e.getMessage(), "Error detecting biometrics availability: " + e.getMessage());
        }
    }

    @ReactMethod
    public void createKeys(final ReadableMap params, Promise promise) {
        try {
            if (isCurrentSDKMarshmallowOrLater()) {
                deleteBiometricKey();
                KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance(KeyProperties.KEY_ALGORITHM_RSA, "AndroidKeyStore");
                KeyGenParameterSpec keyGenParameterSpec = new KeyGenParameterSpec.Builder(biometricKeyAlias, KeyProperties.PURPOSE_SIGN)
                        .setDigests(KeyProperties.DIGEST_SHA256)
                        .setSignaturePaddings(KeyProperties.SIGNATURE_PADDING_RSA_PKCS1)
                        .setAlgorithmParameterSpec(new RSAKeyGenParameterSpec(2048, RSAKeyGenParameterSpec.F4))
                        .setUserAuthenticationRequired(true)
                        .build();
                keyPairGenerator.initialize(keyGenParameterSpec);

                KeyPair keyPair = keyPairGenerator.generateKeyPair();
                PublicKey publicKey = keyPair.getPublic();
                byte[] encodedPublicKey = publicKey.getEncoded();
                String publicKeyString = Base64.encodeToString(encodedPublicKey, Base64.DEFAULT);
                publicKeyString = publicKeyString.replaceAll("\r", "").replaceAll("\n", "");

                WritableMap resultMap = new WritableNativeMap();
                resultMap.putString("publicKey", publicKeyString);
                promise.resolve(resultMap);
            } else {
                promise.reject("Cannot generate keys on android versions below 6.0", "Cannot generate keys on android versions below 6.0");
            }
        } catch (Exception e) {
            promise.reject("Error generating public private keys: " + e.getMessage(), "Error generating public private keys");
        }
    }

    private boolean isCurrentSDKMarshmallowOrLater() {
        return Build.VERSION.SDK_INT >= Build.VERSION_CODES.M;
    }

    @ReactMethod
    public void deleteKeys(Promise promise) {
        if (doesBiometricKeyExist()) {
            boolean deletionSuccessful = deleteBiometricKey();

            if (deletionSuccessful) {
                WritableMap resultMap = new WritableNativeMap();
                resultMap.putBoolean("keysDeleted", true);
                promise.resolve(resultMap);
            } else {
                promise.reject("Error deleting biometric key from keystore", "Error deleting biometric key from keystore");
            }
        } else {
            WritableMap resultMap = new WritableNativeMap();
            resultMap.putBoolean("keysDeleted", false);
            promise.resolve(resultMap);
        }
    }

    @ReactMethod
    public void createSignature(final ReadableMap params, final Promise promise) {
        if (isCurrentSDKMarshmallowOrLater()) {
            UiThreadUtil.runOnUiThread(
                    new Runnable() {
                        @Override
                        public void run() {
                            try {
                                String promptMessage = params.getString("promptMessage");
                                String payload = params.getString("payload");
                                String cancelButtonText = params.getString("cancelButtonText");
                                boolean allowDeviceCredentials = params.getBoolean("allowDeviceCredentials");

                                Signature signature = Signature.getInstance("SHA256withRSA");
                                KeyStore keyStore = KeyStore.getInstance("AndroidKeyStore");
                                keyStore.load(null);

                                PrivateKey privateKey = (PrivateKey) keyStore.getKey(biometricKeyAlias, null);
                                signature.initSign(privateKey);

                                BiometricPrompt.CryptoObject cryptoObject = new BiometricPrompt.CryptoObject(signature);

                                AuthenticationCallback authCallback = new CreateSignatureCallback(promise, payload);
                                FragmentActivity fragmentActivity = (FragmentActivity) getCurrentActivity();
                                Executor executor = Executors.newSingleThreadExecutor();
                                BiometricPrompt biometricPrompt = new BiometricPrompt(fragmentActivity, executor, authCallback);

                                biometricPrompt.authenticate(getPromptInfo(promptMessage, cancelButtonText, allowDeviceCredentials), cryptoObject);
                            } catch (Exception e) {
                                promise.reject("Error signing payload: " + e.getMessage(), "Error generating signature: " + e.getMessage());
                            }
                        }
                    });
        } else {
            promise.reject("Cannot generate keys on android versions below 6.0", "Cannot generate keys on android versions below 6.0");
        }
    }

    private PromptInfo getPromptInfo(String promptMessage, String cancelButtonText, boolean allowDeviceCredentials) {
        PromptInfo.Builder builder = new PromptInfo.Builder().setTitle(promptMessage);

        builder.setAllowedAuthenticators(getAllowedAuthenticators(allowDeviceCredentials));

        if (allowDeviceCredentials == false || isCurrentSDK29OrEarlier()) {
            builder.setNegativeButtonText(cancelButtonText);
        }

        return builder.build();
    }

    private int getAllowedAuthenticators(boolean allowDeviceCredentials) {
        if (allowDeviceCredentials && !isCurrentSDK29OrEarlier()) {
            return BiometricManager.Authenticators.BIOMETRIC_STRONG | BiometricManager.Authenticators.DEVICE_CREDENTIAL;
        }
        return BiometricManager.Authenticators.BIOMETRIC_STRONG;
    }

    private boolean isCurrentSDK29OrEarlier() {
        return Build.VERSION.SDK_INT <= Build.VERSION_CODES.Q;
    }

    @ReactMethod
    public void simplePrompt(final ReadableMap params, final Promise promise) {
        if (isCurrentSDKMarshmallowOrLater()) {
            UiThreadUtil.runOnUiThread(
                    new Runnable() {
                        @Override
                        public void run() {
                            try {
                                String promptMessage = params.getString("promptMessage");
                                String cancelButtonText = params.getString("cancelButtonText");
                                boolean allowDeviceCredentials = params.getBoolean("allowDeviceCredentials");

                                AuthenticationCallback authCallback = new SimplePromptCallback(promise);
                                FragmentActivity fragmentActivity = (FragmentActivity) getCurrentActivity();
                                Executor executor = Executors.newSingleThreadExecutor();
                                BiometricPrompt biometricPrompt = new BiometricPrompt(fragmentActivity, executor, authCallback);

                                biometricPrompt.authenticate(getPromptInfo(promptMessage, cancelButtonText, allowDeviceCredentials));
                            } catch (Exception e) {
                                promise.reject("Error displaying local biometric prompt: " + e.getMessage(), "Error displaying local biometric prompt: " + e.getMessage());
                            }
                        }
                    });
        } else {
            promise.reject("Cannot display biometric prompt on android versions below 6.0", "Cannot display biometric prompt on android versions below 6.0");
        }
    }

    @ReactMethod
    public void biometricKeysExist(Promise promise) {
        try {
            boolean doesBiometricKeyExist = doesBiometricKeyExist();
            WritableMap resultMap = new WritableNativeMap();
            resultMap.putBoolean("keysExist", doesBiometricKeyExist);
            promise.resolve(resultMap);
        } catch (Exception e) {
            promise.reject("Error checking if biometric key exists: " + e.getMessage(), "Error checking if biometric key exists: " + e.getMessage());
        }
    }

    @ReactMethod
    public void promptEnrollBiometrics(Promise promise) {
        this.enrollmentPromise = promise;
        Context context = getReactApplicationContext();
        promptEnrollBiometrics(context);
    }

    protected boolean doesBiometricKeyExist() {
        try {
            KeyStore keyStore = KeyStore.getInstance("AndroidKeyStore");
            keyStore.load(null);

            return keyStore.containsAlias(biometricKeyAlias);
        } catch (Exception e) {
            return false;
        }
    }

    protected boolean deleteBiometricKey() {
        try {
            KeyStore keyStore = KeyStore.getInstance("AndroidKeyStore");
            keyStore.load(null);

            keyStore.deleteEntry(biometricKeyAlias);
            return true;
        } catch (Exception e) {
            return false;
        }
    }

    void promptEnrollBiometrics(Context context) {
        Activity activity = getCurrentActivity();
        if (activity != null) {
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) {
                Intent enrollIntent = new Intent(Settings.ACTION_BIOMETRIC_ENROLL);
                activity.startActivityForResult(enrollIntent, BIOMETRIC_ENROLL_REQUEST_CODE);
            } else {
                Intent enrollIntent = new Intent(Settings.ACTION_SECURITY_SETTINGS);
                activity.startActivityForResult(enrollIntent, BIOMETRIC_ENROLL_REQUEST_CODE);
            }
        } else {
            throw new IllegalArgumentException("Context is not an instance of Activity");
        }
    }
}

class BiometricUtils {
    static Pair<String, Boolean> getBiometricType(Context context) {
        String[] biometricTypeArray = new String[2];
        boolean[] isBiometricEnrolledArray = new boolean[2];

        // Check fingerprint support and enrollment
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.M) {
            android.hardware.fingerprint.FingerprintManager fingerprintManager =
                    (android.hardware.fingerprint.FingerprintManager) context.getSystemService(Context.FINGERPRINT_SERVICE);

            if (fingerprintManager != null) {
                if (fingerprintManager.isHardwareDetected()) {
                    biometricTypeArray[0] = "TouchID";
                    if (fingerprintManager.hasEnrolledFingerprints()) {
                        isBiometricEnrolledArray[0] = true;
                    } else {
                        isBiometricEnrolledArray[0] = false;
                    }
                }
            }
        }

         // Check biometric manager for face recognition and general biometrics
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) {
            BiometricManager biometricManager = BiometricManager.from(context);

            int canAuthenticate = biometricManager.canAuthenticate(
                    BiometricManager.Authenticators.BIOMETRIC_STRONG |
                    BiometricManager.Authenticators.BIOMETRIC_WEAK);

            biometricTypeArray[1] = "FaceID";
            if (canAuthenticate == BiometricManager.BIOMETRIC_SUCCESS) {
                isBiometricEnrolledArray[1] = true;
            } else {
                isBiometricEnrolledArray[1] = false;
            }
        }

        if (biometricTypeArray.length > 0) { 
            if (biometricTypeArray[0] == "TouchID") {
                if (isBiometricEnrolledArray[0]) {
                    return new Pair<>(biometricTypeArray[0], isBiometricEnrolledArray[0]);
                } else {
                    if (biometricTypeArray[1] == "FaceID") {
                        if (isBiometricEnrolledArray[1]) {
                            return new Pair<>(biometricTypeArray[1], isBiometricEnrolledArray[1]);
                        } else {
                            return new Pair<>(biometricTypeArray[0], isBiometricEnrolledArray[0]);
                        }
                    } else {
                        return new Pair<>(biometricTypeArray[0], isBiometricEnrolledArray[0]);
                    }
                }
            } else {
                return new Pair<>(biometricTypeArray[1], isBiometricEnrolledArray[1]);
            }
        }
        return new Pair<>("Undefined", false);
    }
}

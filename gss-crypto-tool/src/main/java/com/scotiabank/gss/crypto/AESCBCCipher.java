package com.scotiabank.gss.crypto;

import com.scotiabank.gssvault.util.Constants;
import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.util.Base64;
import static com.scotiabank.gssvault.util.Constants.AES;
import static com.scotiabank.gssvault.util.Constants.AES_256_TRANSFORMATION;

public class AESCBCCipher {

    private static final int FILE_POS = 0;
    private static final int KEY_POS = 1;
    private static final int IV_POS = 2;
    private static final int NEW_FILE_POS = 3;

    public String decrypt(String encryptedValue, String key, String iv) throws GeneralSecurityException {
        byte[] bK = AESUtils.hexToByte(key);
        byte[] bI = AESUtils.hexToByte(iv);
        SecretKeySpec secretKeySpec = new SecretKeySpec(bK, AES);
        IvParameterSpec initialVector = new IvParameterSpec(bI);
        Cipher cipher = Cipher.getInstance(AES_256_TRANSFORMATION);
        cipher.init(Cipher.DECRYPT_MODE, secretKeySpec, initialVector);
        byte[] decode = Base64.getDecoder().decode(encryptedValue);
        byte[] encrypted = cipher.doFinal(decode);
        return new String(encrypted);
    }

    public String encrypt(String value, String key, String iv) throws Exception {
        byte[] bKey = hexToByte(key);
        byte[] bIv = hexToByte(iv);
        SecretKeySpec secretKeySpec = new SecretKeySpec(bKey, Constants.AES);
        IvParameterSpec initialVector = new IvParameterSpec(bIv);
        return encrypt(value, secretKeySpec, initialVector);
    }

    private static String encrypt(String value, SecretKeySpec secretKeySpec, IvParameterSpec initialVector) throws Exception {
        Cipher cipher = Cipher.getInstance(Constants.AES_256_TRANSFORMATION);
        cipher.init(1, secretKeySpec, initialVector);
        byte[] encrypted = cipher.doFinal(value.getBytes(StandardCharsets.UTF_8));
        return Base64.getEncoder().encodeToString(encrypted);
    }

    private static byte[] hexToByte(String hexStr) {
        int len = hexStr.length();
        byte[] data = new byte[len / 2];

        for(int i = 0; i < len; i += 2) {
            data[i / 2] = (byte)((Character.digit(hexStr.charAt(i), 16) << 4) + Character.digit(hexStr.charAt(i + 1), 16));
        }

        return data;
    }
}
package com.scotiabank.gss.crypto;

import com.scotiabank.gssvault.util.Constants;
import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.util.Base64;

import static com.scotiabank.gssvault.util.Constants.*; // AES, AES_256_ECB

public class AESECBCipher {

    private static final int FILE_POS = 0;
    private static final int KEY_POS  = 1;
    private static final int NEW_FILE_POS = 3;

    // --- DECRYPT ---
    public String decrypt(String encryptedValue, String key) throws GeneralSecurityException {
        byte[] bK = AESUtils.hexToByte(key);
        SecretKeySpec secretKeySpec = new SecretKeySpec(bK, AES);
        Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5Padding"); // "AES/ECB/PKCS5Padding"
        cipher.init(Cipher.DECRYPT_MODE, secretKeySpec);
        byte[] decoded = Base64.getDecoder().decode(encryptedValue);
        byte[] plain   = cipher.doFinal(decoded);
        return new String(plain, StandardCharsets.UTF_8);
    }

    // --- ENCRYPT ---
    public String encrypt(String value, String key) throws GeneralSecurityException {
        byte[] bKey = hexToByte(key);
        SecretKeySpec secretKeySpec = new SecretKeySpec(bKey, Constants.AES);
        return encrypt(value, secretKeySpec);
    }

    private static String encrypt(String value, SecretKeySpec secretKeySpec) throws GeneralSecurityException {
        Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5Padding");
        cipher.init(Cipher.ENCRYPT_MODE, secretKeySpec);
        byte[] encrypted = cipher.doFinal(value.getBytes(StandardCharsets.UTF_8));
        return Base64.getEncoder().encodeToString(encrypted);
    }

    // helper local (igual estilo que tus otras clases)
    private static byte[] hexToByte(String hexStr) {
        int len = hexStr.length();
        byte[] data = new byte[len / 2];
        for (int i = 0; i < len; i += 2) {
            data[i / 2] = (byte) ((Character.digit(hexStr.charAt(i), 16) << 4)
                                 +  Character.digit(hexStr.charAt(i + 1), 16));
        }
        return data;
    }
}

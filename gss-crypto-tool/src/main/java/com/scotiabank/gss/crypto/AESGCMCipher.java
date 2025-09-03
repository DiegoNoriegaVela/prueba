package com.scotiabank.gss.crypto;

import com.scotiabank.gssvault.util.CryptoUtils;
import com.scotiabank.gssvault.util.EncryptionData;

import java.security.GeneralSecurityException;
import java.security.Key;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.Base64;
import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;

public class AESGCMCipher implements AESCipher {

    private static final String AES = "AES";

    private static final String ALGORITHM = "AES/GCM/NoPadding";

    private static final int GCM_TAG_LENGTH = 16;

    private static final int GCM_IV_LENGTH = 12;

    @Override
    public String decrypt(String value, String secretKey)
            throws GeneralSecurityException {
        byte[] bK = CryptoUtils.hexToByte(secretKey);
        SecretKey key = new SecretKeySpec(bK, 0, bK.length, AES);
        return decrypt(value, key);
    }

    @Override
    public String encrypt(String value, String secretKey)
            throws GeneralSecurityException {
        byte[] bK = CryptoUtils.hexToByte(secretKey);
        SecretKey key = new SecretKeySpec(bK, 0, bK.length, AES);
        return encrypt(value, key);
    }

    @Override
    public String encrypt(String value, Key key) throws GeneralSecurityException {
        byte[] initVector = this.getSecureRandomIV();
        return this.cipher(value, initVector, key);
    }

    @Override
    public String decrypt(String value, Key key) throws GeneralSecurityException {
        byte[] cipherText = Base64.getDecoder().decode(value);
        Cipher cipher = Cipher.getInstance(ALGORITHM);
        byte[] initVector = Arrays.copyOfRange(cipherText, 0, GCM_IV_LENGTH);
        GCMParameterSpec spec = new GCMParameterSpec(GCM_TAG_LENGTH * Byte.SIZE,
                initVector);

        cipher.init(Cipher.DECRYPT_MODE, key, spec);
        byte[] plaintext = cipher.doFinal(cipherText, GCM_IV_LENGTH,
                cipherText.length - GCM_IV_LENGTH);
        return new String(plaintext, java.nio.charset.StandardCharsets.UTF_8);
    }

    @Override
    public String decrypt(String value, Key key, byte[] iv)
            throws GeneralSecurityException {
        byte[] cipherText = Base64.getDecoder().decode(value);
        Cipher cipher = Cipher.getInstance(ALGORITHM);
        GCMParameterSpec spec = new GCMParameterSpec(GCM_TAG_LENGTH * Byte.SIZE, iv);

        cipher.init(Cipher.DECRYPT_MODE, key, spec);
        byte[] plaintext = cipher.doFinal(cipherText, 0, cipherText.length);
        return new String(plaintext, java.nio.charset.StandardCharsets.UTF_8);
    }

    @Override
    public EncryptionData getEncryptionData(String value, Key secretKey)
            throws GeneralSecurityException {
        byte[] initVector = this.getSecureRandomIV();
        String ciphertext = this.cipher(value, initVector, secretKey, false);

        return new EncryptionData(CryptoUtils.bytesToHex(initVector), GCM_TAG_LENGTH,
                ciphertext);
    }

    private byte[] getSecureRandomIV() {
        byte[] initVector = new byte[GCM_IV_LENGTH];
        (new SecureRandom()).nextBytes(initVector);
        return initVector;
    }

    private String cipher(String value, byte[] initVector, Key key)
            throws GeneralSecurityException {
        return this.cipher(value, initVector, key, true);
    }

    private String cipher(String value, byte[] initVector, Key key,
                          boolean includeIvInCipherText) throws GeneralSecurityException {
        Cipher cipher = Cipher.getInstance(ALGORITHM);
        GCMParameterSpec spec = new GCMParameterSpec(GCM_TAG_LENGTH * Byte.SIZE,
                initVector);

        cipher.init(Cipher.ENCRYPT_MODE, key, spec);
        byte[] encoded = value.getBytes(java.nio.charset.StandardCharsets.UTF_8);

        int cipherTextSize = includeIvInCipherText
                ? initVector.length + cipher.getOutputSize(encoded.length)
                : cipher.getOutputSize(encoded.length);

        byte[] ciphertext = new byte[cipherTextSize];

        int outputOffset = 0;
        if (includeIvInCipherText) {
            outputOffset = initVector.length;
            System.arraycopy(initVector, 0, ciphertext, 0, initVector.length);
        }

        cipher.doFinal(encoded, 0, encoded.length, ciphertext, outputOffset);
        return Base64.getEncoder().encodeToString(ciphertext);
    }

}
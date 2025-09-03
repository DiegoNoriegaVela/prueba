package com.scotiabank.gss.crypto;

import com.scotiabank.gssvault.util.EncryptionData;

import java.security.GeneralSecurityException;
import java.security.Key;

public interface AESCipher {

    String encrypt(String value, String key) throws GeneralSecurityException;

    String decrypt(String value, String key) throws GeneralSecurityException;

    String encrypt(String value, Key secretKey) throws GeneralSecurityException;

    String decrypt(String value, Key secretKey) throws GeneralSecurityException;

    EncryptionData getEncryptionData(String value, Key secretKey)
            throws GeneralSecurityException;

    String decrypt(String value, Key secretKey, byte[] iv)
            throws GeneralSecurityException;

}
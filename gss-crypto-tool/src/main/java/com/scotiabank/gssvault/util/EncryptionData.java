package com.scotiabank.gssvault.util;

public class EncryptionData {

    private String iv;

    private int tagLength;

    private String cipherText;

    public EncryptionData(String iv, int tagLength, String cipherText) {
        this.iv = iv;
        this.tagLength = tagLength;
        this.cipherText = cipherText;
    }

    public String getIv() {
        return this.iv;
    }

    public void setIv(String iv) {
        this.iv = iv;
    }

    public int getTagLength() {
        return this.tagLength;
    }

    public void setTagLength(int tagLength) {
        this.tagLength = tagLength;
    }

    public String getCipherText() {
        return this.cipherText;
    }

    public void setCipherText(String cipherText) {
        this.cipherText = cipherText;
    }

}
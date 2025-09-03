package com.scotiabank.gss.crypto;

import com.scotiabank.gssvault.model.EnumAESType;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileReader;
import java.io.IOException;
import static com.scotiabank.gssvault.util.Constants.*;

public final class AESUtils {
    private AESUtils() {
    }
    public static byte[] hexToByte(String hexStr) {
        int len = hexStr.length();
        byte[] data = new byte[len / 2];
        for (int i = 0; i < len; i += 2) {
            data[i / 2] = (byte) ((Character.digit(hexStr.charAt(i), 16) << 4)
                    + Character.digit(hexStr.charAt(i + 1), 16));
        }
        return data;
    }

    public static String getCipherValue(String paramPath, String tagProps, String lastFieldProp, EnumAESType aesType){
        String value = null;

        try{
            readParams(paramPath, tagProps);
            value = readProps(tagProps, lastFieldProp.toLowerCase(), aesType);
        }catch (Exception e){
            System.out.println(e.getMessage() + e.getCause());
        }
        return value;
    }

    public static void readParams(String paramPath, String tag){
        System.out.println(" ----------------------> readParams()");
        try {
            PROPS_PATH_FILE = null;
            AES_KEY = null;
            AES_IV = null;
            String propsTag = tag + PARAM_PATH_FILE_TAG;
            String keyTag = tag + PARAM_KEY_TAG;
            String ivTag = tag + PARAM_IV_TAG;

            System.out.println("Working Directory: " + System.getProperty("user.dir"));
            File file = new File(paramPath);

            if (!file.exists())
                throw new Exception(FILE_DOES_NOT_EXIST);

            try (BufferedReader br = new BufferedReader(new FileReader(file))) {
                String line;
                while ((line = br.readLine()) != null) {

                    // 2. Get Encrypted Values
                    System.out.println(line);
                    if (line.indexOf(propsTag) != -1)
                        PROPS_PATH_FILE = line.replace(propsTag, "");

                    if (line.indexOf(keyTag) != -1)
                        AES_KEY = line.replace(keyTag, "");

                    if (line.indexOf(ivTag) != -1)
                        AES_IV = line.replace(ivTag, "");

                    if (PROPS_PATH_FILE != null && AES_KEY != null && AES_IV != null)
                        break;
                }
            }
            System.out.println("Props file path: " + PROPS_PATH_FILE);
            System.out.println("AES Key: " + AES_KEY);
            System.out.println("AES IV: " + AES_IV);

        }
        catch(IOException e) {
            System.out.println(e.getMessage() + e.getCause());
        }
        catch(Exception e){
            System.out.println(e.getMessage() + e.getCause());
        }
    }

    public static String readProps(String tag, String lastFieldProp, EnumAESType aesType) {
        System.out.println(" ----------------------> readProps()");

        // Initialize Values
        String decryptedValue = null;
        String valueTag = null;
        String encryptedValue = null;

        try {

            //valueTag = tag + PROPS_GENERIC_TAG + POINT_SYMBOL + lastFieldProp + EQUAL_SYMBOL;
            valueTag = tag + POINT_SYMBOL + lastFieldProp + EQUAL_SYMBOL;

            System.out.println("Props file path: " + PROPS_PATH_FILE);

            if (PROPS_PATH_FILE == null)
                throw new Exception(PROPS_PATH_FILE_ERROR);

            if (AES_KEY == null)
                throw new Exception(AES_KEY_ERROR);

            if (AES_IV == null)
                throw new Exception(AES_IV_ERROR);

            File file = new File(PROPS_PATH_FILE);

            if (!file.exists())
                throw new Exception(FILE_DOES_NOT_EXIST);

            try (BufferedReader br = new BufferedReader(new FileReader(file))) {
                String line;
                while ((line = br.readLine()) != null) {
                    if (line.indexOf(valueTag) != -1)
                        encryptedValue = line.replace(valueTag, "");

                    if (encryptedValue != null)
                        break;
                }

                if (encryptedValue == null)
                    throw new Exception("Property [" + valueTag + "] not found in [" + PROPS_PATH_FILE + "]");

            }

            // Decrypt Value
            switch(aesType){
                case CBC:
                    AESCBCCipher AESCBCCipher = new AESCBCCipher();
                    decryptedValue = AESCBCCipher.decrypt(encryptedValue, AES_KEY, AES_IV);
                    break;
                case GCM:
                    AESGCMCipher AESGCMCipher = new AESGCMCipher();
                    decryptedValue = AESGCMCipher.decrypt(encryptedValue, AES_KEY);
                    break;
            }

            System.out.println(valueTag + ": " + decryptedValue);

        } catch (IOException e) {
            System.out.println(e.getMessage() + e.getCause());
        } catch (Exception e) {
            System.out.println(e.getMessage() + e.getCause());
        }

        return decryptedValue;
    }
}
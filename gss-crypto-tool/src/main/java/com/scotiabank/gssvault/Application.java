package com.scotiabank.gssvault;

import com.scotiabank.gss.crypto.AESCBCCipher;
import com.scotiabank.gss.crypto.AESECBCipher;
import com.scotiabank.gss.crypto.AESGCMCipher;
import com.scotiabank.gssvault.model.EnumAESMode;
import com.scotiabank.gssvault.model.EnumAESType;
import com.scotiabank.gssvault.model.EnumInputType;
import com.scotiabank.gssvault.util.AESFileCipher;

import java.security.GeneralSecurityException;

import static com.scotiabank.gssvault.model.EnumAESType.*;
import static com.scotiabank.gssvault.model.EnumAESMode.*;
import static com.scotiabank.gssvault.model.EnumInputType.*;
import static com.scotiabank.gssvault.util.Constants.*;

public class Application {

    public static void main(String[] args) {
        String type = null;
        String mode = null;
        String text = null;
        String textInputType = null;
        String key = null;
        String iv = null;
        String outPutFile = null;

        String response = null;

        try {
            // args:
            // 0=type(CBC|GCM|ECB) 1=mode(ENCRYPT|DECRYPT) 2=textOrFile
            // 3=inputType(TEXT|FILE) 4=keyHex  [CBC: 5=ivHex, (FILE:6=out)]
            // [ECB/GCM: (FILE:5=out)]
            type = args[0];
            mode = args[1];
            text = args[2];
            textInputType = args[3];
            key = args[4];

            EnumAESType aesType = EnumAESType.valueOf(type.toUpperCase());
            EnumInputType inputType = EnumInputType.valueOf(textInputType.toUpperCase());

            if (aesType == CBC) {
                iv = args[5];
                if (inputType == FILE) outPutFile = args[6];
            } else {
                iv = "Not required";
                if (inputType == FILE) outPutFile = args[5];
            }

            EnumAESMode aesMode = EnumAESMode.valueOf(mode.toUpperCase());

            if (aesType == INVALID_AES_TYPE)  throw new Exception(THROW_INVALID_AES_TYPE);
            if (aesMode == INVALID_AES_MODE)  throw new Exception(THROW_INVALID_AES_MODE);
            if (inputType == INVALID_INPUT_TYPE) throw new Exception(THROW_INVALID_INPUT_TYPE);

            switch (aesType) {
                case CBC:
                    response = CBCFlow(aesType, aesMode, text, inputType, key, iv, outPutFile);
                    break;
                case GCM:
                    response = GCMFlow(aesType, aesMode, text, inputType, key, iv, outPutFile);
                    break;
                case ECB:
                    response = ECBFlow(aesType, aesMode, text, inputType, key, iv, outPutFile);
                    break;
                default:
                    break;
            }

        } catch (GeneralSecurityException gse) {
            gse.printStackTrace();
        } catch (Exception e) {
            e.printStackTrace();
        }

        System.out.println(response);
    }

    public static String CBCFlow(EnumAESType aesType, EnumAESMode aesMode, String text,
                                 EnumInputType inputType, String key, String iv, String outPutFile) {
        String response = null;
        AESFileCipher aesFileCipher = new AESFileCipher();
        AESCBCCipher cbcCipher = new AESCBCCipher();

        try {
            switch (inputType) {
                case TEXT:
                    if (aesMode == ENCRYPT)      response = cbcCipher.encrypt(text, key, iv);
                    else if (aesMode == DECRYPT) response = cbcCipher.decrypt(text, key, iv);
                    break;

                case FILE:
                    // Construir args para AESFileCipher.{FileEncrypt|FileDecrypt}
                    String[] fArgs = { aesType.name(), text, key, iv, outPutFile, CBC.name() };
                    if (aesMode == ENCRYPT) {
                        aesFileCipher.FileEncrypt(fArgs);
                        response = SUCCESS;
                    } else { // DECRYPT habilitado
                        AESFileCipher.FileDecrypt(fArgs);
                        response = SUCCESS;
                    }
                    break;

                default: break;
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
        return response;
    }

    public static String GCMFlow(EnumAESType aesType, EnumAESMode aesMode, String text,
                                 EnumInputType inputType, String key, String iv, String outPutFile) {
        String response = null;
        AESFileCipher aesFileCipher = new AESFileCipher();
        AESGCMCipher gcmCipher = new AESGCMCipher();

        try {
            switch (inputType) {
                case TEXT:
                    if (aesMode == ENCRYPT)      response = gcmCipher.encrypt(text, key);
                    else if (aesMode == DECRYPT) response = gcmCipher.decrypt(text, key);
                    break;

                case FILE:
                    String[] fArgs = { aesType.name(), text, key, iv, outPutFile, GCM.name() };
                    if (aesMode == ENCRYPT) {
                        aesFileCipher.FileEncrypt(fArgs);
                        response = SUCCESS;
                    } else { // DECRYPT habilitado
                        AESFileCipher.FileDecrypt(fArgs);
                        response = SUCCESS;
                    }
                    break;

                default: break;
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
        return response;
    }

    public static String ECBFlow(EnumAESType aesType, EnumAESMode aesMode, String text,
                                 EnumInputType inputType, String key, String iv, String outPutFile) {
        String response = null;
        AESFileCipher aesFileCipher = new AESFileCipher();
        AESECBCipher ecbCipher = new AESECBCipher();

        try {
            switch (inputType) {
                case TEXT:
                    if (aesMode == ENCRYPT)      response = ecbCipher.encrypt(text, key);
                    else if (aesMode == DECRYPT) response = ecbCipher.decrypt(text, key);
                    break;

                case FILE:
                    // En ECB el IV se ignora; mantenemos el contrato de args.
                    String[] fArgs = { aesType.name(), text, key, iv, outPutFile, ECB.name() };
                    if (aesMode == ENCRYPT) {
                        aesFileCipher.FileEncrypt(fArgs);   // FIX: usar ECB, no GCM
                        response = SUCCESS;
                    } else { // DECRYPT habilitado
                        AESFileCipher.FileDecrypt(fArgs);
                        response = SUCCESS;
                    }
                    break;

                default: break;
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
        return response;
    }
}

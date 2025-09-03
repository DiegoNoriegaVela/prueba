package com.scotiabank.gssvault;

import com.scotiabank.gss.crypto.AESCBCCipher;
import com.scotiabank.gss.crypto.AESECBCipher;
import com.scotiabank.gssvault.model.EnumAESMode;
import com.scotiabank.gssvault.model.EnumAESType;
import com.scotiabank.gssvault.model.EnumInputType;
import com.scotiabank.gss.crypto.AESGCMCipher;
import com.scotiabank.gssvault.util.AESFileCipher;

import java.security.GeneralSecurityException;

import static com.scotiabank.gssvault.model.EnumAESType.*;
import static com.scotiabank.gssvault.model.EnumInputType.FILE;
import static com.scotiabank.gssvault.util.Constants.*;
import static com.scotiabank.gssvault.model.EnumAESMode.*;
import static com.scotiabank.gssvault.model.EnumInputType.INVALID_INPUT_TYPE;

public class Application {

	public static void main(String[] args) {

//		boolean demo_sha256 = true;
//
//		if (demo_sha256){
//			String result = Hashing.sha256()
//					.hashString("your input", StandardCharsets.UTF_8)
//					.toString();
//
//		}else{
//			System.exit(1);
//		}
//
//        try {
//            AES_CBC_DEMO.main(args);
//        } catch (Exception e) {
//            throw new RuntimeException(e);
//        }
//        System.exit(0);

		String type = null;
		String mode = null;
		String text = null;
		String textInputType = null;
		String key = null;
		String iv = null;
		String putPutFile = null;

		String response = null;

		try {

			type = args[0];
			mode = args[1];
			text = args[2];
			textInputType = args[3];
			key = args[4];

			EnumAESType aesType = EnumAESType.valueOf(type.toUpperCase());
			EnumInputType inputType = EnumInputType.valueOf(textInputType.toUpperCase());

			if (aesType == CBC){
				iv = args[5];

				if(inputType == FILE)
					putPutFile = args[6];

			}else {
				iv = "Not required";

				if(inputType == FILE)
					putPutFile = args[5];
			}

			EnumAESMode aesMode = EnumAESMode.valueOf(mode.toUpperCase());

			if (aesType == INVALID_AES_TYPE)
				throw new Exception(THROW_INVALID_AES_TYPE);

			if (aesMode == INVALID_AES_MODE)
				throw new Exception(THROW_INVALID_AES_MODE);

			if (inputType == INVALID_INPUT_TYPE)
				throw new Exception(THROW_INVALID_INPUT_TYPE);

			switch (aesType){
				case CBC:
					response = CBCFlow(aesType, aesMode, text, inputType, key, iv, putPutFile);
					break;
				case GCM:
					response = GCMFlow(aesType, aesMode, text, inputType, key, iv, putPutFile);
					break;
				case ECB:
					response = ECBFlow(aesType, aesMode, text, inputType, key, iv, putPutFile);
					break;
				default:
					break;
			}

		} catch (GeneralSecurityException gse) {
			gse.printStackTrace();
		} catch (Exception e){
			e.printStackTrace();
		}
		
		System.out.println(response);

		/*
		String decryptedValue = null;
		String paramPathFile = "/Users/xxx/Documents/SSL/as400-gcm-params.properties";
		String key = "F01F0EE95D8DD60A310BAB4B1584A8E2F105C9BD5A03F4264AF685206D2CD4FA";
		String iv = "25EC3602CA3CEC05A534B00EB10F4A12";
		String aesType = "GCM";
		String tagProps = "as400";
		String fieldProp = "str.tps.u";

		EnumAESType enumAESType = EnumAESType.valueOf(aesType.toUpperCase());

		try {
			decryptedValue = AESUtils.getCipherValue(paramPathFile, tagProps, fieldProp, enumAESType);
		} catch (Exception e) {
			throw new RuntimeException(e);
		}
		*/

	}

	public static String CBCFlow(EnumAESType aesType, EnumAESMode aesMode, String text, EnumInputType inputType, String key, String iv, String outPutFile){
		String response = null;
		AESFileCipher aesFileCipher = new AESFileCipher();
		AESCBCCipher cbcCipher = new AESCBCCipher();

		try {
			switch(inputType){
				case TEXT:
					if (aesMode == ENCRYPT){
						response = cbcCipher.encrypt(text, key, iv);
					}else if(aesMode == DECRYPT){
						response = cbcCipher.decrypt(text, key, iv);
					}

					break;
				case FILE:
					if (aesMode == ENCRYPT){
						String args[] = {aesType.name(), text, key, iv, outPutFile, CBC.name()};
						aesFileCipher.FileEncrypt(args);
						response = SUCCESS;
					}else {
						response = "AES CBC File Decrypt Mode is not allowed";
					}

					break;
				default:
					break;
			}
		} catch (Exception e) {
			e.printStackTrace();
		}

		return response;
	}

	public static String GCMFlow(EnumAESType aesType, EnumAESMode aesMode, String text, EnumInputType inputType, String key, String iv, String outPutFile){
		String response = null;
		AESFileCipher aesFileCipher = new AESFileCipher();
		AESGCMCipher gcmCipher = new AESGCMCipher();

		try{
			switch(inputType) {
				case TEXT:
					if(aesMode == ENCRYPT){
						response = gcmCipher.encrypt(text, key);
					}else if (aesMode == DECRYPT){
						response = gcmCipher.decrypt(text, key);
					}

					break;
				case FILE:
					if (aesMode == ENCRYPT){
						String args[] = {aesType.name(), text, key, iv, outPutFile, GCM.name()};
						aesFileCipher.FileEncrypt(args);
						response = SUCCESS;
					}else {
						response = "AES GCM File Decrypt Mode is not allowed";
					}

					break;
				default:
					break;
			}

		} catch (GeneralSecurityException gse) {
			gse.printStackTrace();
		} catch (Exception e){
			e.printStackTrace();
		}

		return response;
	}

	public static String ECBFlow(EnumAESType aesType, EnumAESMode aesMode, String text, EnumInputType inputType, String key, String iv, String outPutFile){
		String response = null;
		AESFileCipher aesFileCipher = new AESFileCipher();
		AESECBCipher ecbCipher = new AESECBCipher();

		try{
			switch(inputType) {
				case TEXT:
					if(aesMode == ENCRYPT){
						response = ecbCipher.encrypt(text, key);
					}else if (aesMode == DECRYPT){
						response = ecbCipher.decrypt(text, key);
					}

					break;
				case FILE:
					if (aesMode == ENCRYPT){
						String args[] = {aesType.name(), text, key, iv, outPutFile, GCM.name()};
						aesFileCipher.FileEncrypt(args);
						response = SUCCESS;
					}else {
						response = "AES GCM File Decrypt Mode is not allowed";
					}

					break;
				default:
					break;
			}

		} catch (GeneralSecurityException gse) {
			gse.printStackTrace();
		} catch (Exception e){
			e.printStackTrace();
		}

		return response;
	}
}
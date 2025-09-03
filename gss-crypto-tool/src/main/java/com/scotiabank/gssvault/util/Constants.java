package com.scotiabank.gssvault.util;

public class Constants {
    public static String PROPS_PATH_FILE = "";
    public static String AES_KEY = "";
    public static String AES_IV = "";

    public static String DB_USERNAME = "";
    public static String DB_PASSWORD = "";

    public static final String PARAM_PATH_FILE_TAG = ".str.prop.path=";
    public static final String PARAM_KEY_TAG = ".str.prop.k=";
    public static final String PARAM_IV_TAG = ".str.prop.iv=";

    public static final String PROPS_GENERIC_TAG = ".str.tps";
    public static final String PROPS_USERNAME_TAG = ".str.tps.u=";
    public static final String EQUAL_SYMBOL = "=";
    public static final String POINT_SYMBOL = ".";
    public static final String PROPS_PASSWORD_TAG = ".str.tps.p=";
    public static final String PROPS_NOT_DEFINED_TAG = "Props not defined";

    public static final String FILE_DOES_NOT_EXIST = "File doesn't exist!";
    public static final String PROPS_PATH_FILE_ERROR = "PROPS_PATH_FILE not defined";
    public static final String AES_KEY_ERROR = "AES_KEY not defined";
    public static final String AES_IV_ERROR = "AES_IV not defined";

    public static final String THROW_INVALID_ENUM_VALUE = "Invalid value, check EnumValue class";
    public static final String THROW_INVALID_AES_MODE = "Invalid aes mode value, check EnumAESMode class";
    public static final String THROW_INVALID_AES_TYPE = "Invalid aes type value, check EnumAESType class";
    public static final String THROW_INVALID_INPUT_TYPE = "Invalid input type value, check EnumInputType class";

    public static final String AES = "AES";
    public static final String AES_256_TRANSFORMATION = "AES/CBC/PKCS5Padding";
    public static final String AES_256_ECB = "AES/ECB/NoPadding";

    public static final String ENCRYPTING_PROPERTIES = "Encrypting properties";
    public static final String DECRYPTING_PROPERTIES = "Decrypting properties";

    public static final String AES_IV_INVALID_LENGTH = "Invalid IV Length";
    public static final String INSUFFICIENT_ARGUMENTS = "Insufficient Arguments";
    public static final String INVALID_LEY_LENGTH = "Invalid key length";

    public static final String SUCCESS = "Success";
}

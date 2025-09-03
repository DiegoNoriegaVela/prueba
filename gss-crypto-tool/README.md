# GSS Vault Tool
[![Version](https://img.shields.io/badge/version-v.1.0.0-blue)]() [![Tech](https://img.shields.io/badge/Java%201.8.0_322(Open%20JDK)-orange)]() [![License](https://img.shields.io/badge/license-Scotiabank-red)]()

Project created to provide encryption algorithms aligned to Scotiabank Standard & Policies

## Features

- Encrypt file with AES 256 CBC executed by command line
- Encrypt file with AES 256 GCM executed by command line
- Encrypt / Decrypt custom text with AES 256 CBC as library
- Encrypt / Decrypt custom text with AES 256 GCM as library
- Decrypt values(credentials) from props.properties file to inject in JNDI Data Source

## How to build
Go to project directory path and execute the following command to generate jar file

```mvn
mvn install
```

## How to use
You should have a Postamn Client

```json
Encrypt File wih AES
java -jar gss-vault-0.0.1-SNAPSHOT.jar "<AES_TYPE>" "<MODE>" "<FILE_NAME_TO_ENCRYPT>" "<INPUT_TYPE>" "<AES_KEY>" "<AES_IV>" "<ENCRYPTED_FILE_NAME>"

Encrypt Text with AES
java -jar gss-vault-0.0.1-SNAPSHOT.jar "<AES_TYPE>" "<MODE>" "<TEXT>" "<INPUT_TYPE>" "<AES_KEY>" "AES_IV" ""

Decrypt Text with AES
java -jar gss-vault-0.0.1-SNAPSHOT.jar "<AES_TYPE>" "<MODE>" "<TEXT>" "<INPUT_TYPE>" "<AES_KEY>" "AES_IV" ""

PERMITTED VALUES
  "<AES_TYPE>"            : "CBC" | "GCM"
  "<MODE>"                : "ENCRYPT" | "DECRYPT" 
  "<FILE_NAME_TO_ENCRYPT>": "as400.unprotected.props.properties"
  "<TEXT>"                : "Text value to encrypt"
  "<INPUT_TYPE>"          : "FILE" | "TEXT"
  "<AES_KEY>"             : "F01F0EE95D8DD60A310BAB4B1584A8E2F105C9BD5A03F4264AF685206D2CD4FA"
  "<AES_IV>"              : "25EC3602CA3CEC05A534B00EB10F4A12"
  "<ENCRYPTED_FILE_NAME>" : "as400.props.properties"

Enum Class to set correct values in springboot / spring projects when this .jar is using like a library
  "<AES_TYPE>"            : EnumAESType { CBC, GCM }
  "<MODE>"                : EnumAESMode { ENCRYPT , DECRYPT }
  "<INPUT_TYPE>"          : EnumInputFile { TEXT, FILE}
```

## Project Structure

A basic structure to show how it works.

For example:

```
gss-vault
    |
    +-- pom.xml
    +-- README.md
    +-- .gitignore
    |
    \-- src/main/java/com/scotiabank/gssvault
            |
            +-- Application.java
            |
            \-- crypto
                |
                +-- AESCBCCipher.java
                +-- AESCipher.java
                +-- AESGCMCipher.java
                +-- AESUtils.java
                |
            \-- model
                |
                +-- EnumAESMode.java
                +-- EnumAESType.java
                +-- EnumFields.java
                +-- EnumInputType.java
                |
            \-- util
                |
                +-- AESFileCipher.java
                +-- Constants.java
                +-- CyrptoUtils.java
                +-- CustomProperties.java
                +-- EncryptionData.java
                |
        
```

Thanks.
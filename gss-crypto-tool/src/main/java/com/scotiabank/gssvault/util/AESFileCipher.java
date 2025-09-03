package com.scotiabank.gssvault.util;

import com.scotiabank.gss.crypto.AESECBCipher;
import com.scotiabank.gss.crypto.AESCBCCipher;
import com.scotiabank.gss.crypto.AESGCMCipher;
import com.scotiabank.gssvault.model.EnumAESType;

import java.io.OutputStream;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.Enumeration;

// IMPORTS PARA NUEVO MODO DE CIFRADO DE ARCHIVO ARBITRARIO
import javax.crypto.Cipher;
import javax.crypto.CipherInputStream;
import javax.crypto.CipherOutputStream;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.InputStream;

public class AESFileCipher {

    // Encrypt
    public void FileEncrypt(String[] args) throws Exception {
        validateArgs(args);

        String file = args[1];
        String key = args[2];
        String iv = args[3];
        String newFile = args[4];
        String type = args[5];

        EnumAESType aesType = EnumAESType.valueOf(type.toUpperCase());

        Path readPath = Paths.get(file);
        CustomProperties props = new CustomProperties();
        props.load(Files.newInputStream(readPath));
        Enumeration e = props.propertyNames();

        while(e.hasMoreElements()) {
            String propKey = (String)e.nextElement();
            String value = props.getProperty(propKey);
            String encrypted = null;

            switch (aesType){
                case ECB:
                    AESECBCipher aesecbCipher = new AESECBCipher();
                    encrypted = aesecbCipher.encrypt(value, key);
                    break;
                case CBC:
                    AESCBCCipher aescbcCipher = new AESCBCCipher();
                    encrypted = aescbcCipher.encrypt(value, key, iv);
                    break;
                case GCM:
                    AESGCMCipher aesgcmCipher = new AESGCMCipher();
                    encrypted = aesgcmCipher.encrypt(value, key);
                    break;
                default:
                    break;
            }

            props.setProperty(propKey, encrypted);
        }

        Path writePath = Paths.get(newFile);
        OutputStream stream = Files.newOutputStream(writePath);
        Throwable var23 = null;

        try {
            props.store(stream, Constants.ENCRYPTING_PROPERTIES);

        } catch (Throwable var19) {
            var23 = var19;
            throw var19;
        } finally {
            if (stream != null) {
                if (var23 != null) {
                    try {
                        stream.close();
                    } catch (Throwable var18) {
                        var23.addSuppressed(var18);
                    }
                } else {
                    stream.close();
                }
            }

        }

    }

    // ─────────────────────────────────────────────────────────────
    // File DECRYPT — symmetric to fileEncrypt (hex key/iv expected)
    // ─────────────────────────────────────────────────────────────
    public static void FileDecrypt(String[] args) throws Exception {
        validateArgs(args);

        String file    = args[1];
        String key     = args[2];
        String iv      = args[3];
        String newFile = args[4];
        String type    = args[5];

        EnumAESType aesType = EnumAESType.valueOf(type.toUpperCase());

        // Carga .properties de entrada (cifrado por propiedad)
        Path readPath = Paths.get(file);
        if (!Files.exists(readPath, LinkOption.NOFOLLOW_LINKS) || Files.isDirectory(readPath)) {
            throw new IllegalArgumentException("El archivo de entrada no existe o es un directorio: " + file);
        }

        CustomProperties props = new CustomProperties();
        props.load(Files.newInputStream(readPath));

        // Descifra cada valor según el modo
        for (Enumeration<?> e = props.propertyNames(); e.hasMoreElements();) {
            String propKey = (String) e.nextElement();
            String encVal  = props.getProperty(propKey);
            if (encVal == null) continue;

            String decVal;
            switch (aesType) {
                case ECB:
                    decVal = new AESECBCipher().decrypt(encVal, key);               // ECB no usa IV
                    break;
                case CBC:
                    decVal = new AESCBCCipher().decrypt(encVal, key, iv);           // CBC requiere IV
                    break;
                case GCM:
                    decVal = new AESGCMCipher().decrypt(encVal, key);               // según tu FileEncrypt
                    break;
                default:
                    throw new IllegalArgumentException("AES type no soportado: " + aesType);
            }
            props.setProperty(propKey, decVal);
        }

        // Guarda el .properties descifrado
        Path writePath = Paths.get(newFile);
        if (writePath.getParent() != null && !Files.exists(writePath.getParent())) {
            Files.createDirectories(writePath.getParent());
        }
        try (OutputStream os = Files.newOutputStream(writePath)) {
            // Usa el mismo comentario o cambia por un DECRYPTING_PROPERTIES si lo tienes
            props.store(os, Constants.ENCRYPTING_PROPERTIES);
        }
    }

    private static void validateArgs(String[] args) {

        if (args != null && args.length >= 3) {
            validateFile(args[1]);
            validateKey(args[2]);
            if (args[0].equals(EnumAESType.CBC))
                validateIv(args[3]);
        } else {
            throw new RuntimeException(Constants.INSUFFICIENT_ARGUMENTS);
        }
    }

    private static void validateFile(String fileName) {
        if (!Files.exists(Paths.get(fileName), new LinkOption[0])) {
            throw new RuntimeException(Constants.FILE_DOES_NOT_EXIST);
        }
    }

    private static void validateIv(String iv) {
        if (iv.length() != 32) {
            throw new RuntimeException(Constants.AES_IV_INVALID_LENGTH);
        }
    }

    private static void validateKey(String key) {
        if (key.length() != 64) {
            throw new RuntimeException(Constants.INVALID_LEY_LENGTH);
        }
    }

    //===============================================


    // ─────────────────────────────────────────────────────────────
    // ENCRYPT (ANY FILE) — binario/stream, simétrico a DecryptAny
    // args: [1]=in, [2]=keyHex(64), [3]=ivHex(32 - CBC/GCM), [4]=out, [5]=ECB|CBC|GCM
    // ─────────────────────────────────────────────────────────────
    public static void FileEncryptAny(String[] args) throws Exception {
        // Reusa validación básica (archivo de entrada y key). IV lo validamos nosotros.
        validateArgs(args);

        final String inFile  = args[1];
        final String keyHex  = args[2];
        final String ivHex   = args[3];
        final String outFile = args[4];
        final String typeStr = args[5];

        final EnumAESType aesType = EnumAESType.valueOf(typeStr.toUpperCase());
        if (aesType != EnumAESType.ECB) {
            if (ivHex == null) throw new IllegalArgumentException("IV requerido para CBC/GCM.");
            validateIv(ivHex); // 32 hex (16 bytes) según tu política
        }

        final Path in  = Paths.get(inFile);
        final Path out = Paths.get(outFile);
        if (!Files.exists(in, LinkOption.NOFOLLOW_LINKS) || Files.isDirectory(in)) {
            throw new IllegalArgumentException("El archivo de entrada no existe o es un directorio: " + inFile);
        }
        if (out.getParent() != null && !Files.exists(out.getParent())) {
            Files.createDirectories(out.getParent());
        }

        final Cipher cipher = buildCipher(Cipher.ENCRYPT_MODE, aesType, keyHex, ivHex);

        try (InputStream is = Files.newInputStream(in);
            OutputStream os = Files.newOutputStream(out);
            CipherOutputStream cos = new CipherOutputStream(os, cipher)) {

            byte[] buf = new byte[64 * 1024];
            int r;
            while ((r = is.read(buf)) != -1) {
                cos.write(buf, 0, r);
            }
            cos.flush();
        }
    }

    // ─────────────────────────────────────────────────────────────
    // DECRYPT (ANY FILE) — binario/stream
    // args: [1]=in, [2]=keyHex(64), [3]=ivHex(32 - CBC/GCM), [4]=out, [5]=ECB|CBC|GCM
    // ─────────────────────────────────────────────────────────────
    public static void FileDecryptAny(String[] args) throws Exception {
        // Reusa validación básica (archivo de entrada y key). IV lo validamos nosotros.
        validateArgs(args);

        final String inFile  = args[1];
        final String keyHex  = args[2];
        final String ivHex   = args[3];
        final String outFile = args[4];
        final String typeStr = args[5];

        final EnumAESType aesType = EnumAESType.valueOf(typeStr.toUpperCase());
        if (aesType != EnumAESType.ECB) {
            if (ivHex == null) throw new IllegalArgumentException("IV requerido para CBC/GCM.");
            validateIv(ivHex);
        }

        final Path in  = Paths.get(inFile);
        final Path out = Paths.get(outFile);
        if (!Files.exists(in, LinkOption.NOFOLLOW_LINKS) || Files.isDirectory(in)) {
            throw new IllegalArgumentException("El archivo de entrada no existe o es un directorio: " + inFile);
        }
        if (out.getParent() != null && !Files.exists(out.getParent())) {
            Files.createDirectories(out.getParent());
        }

        final Cipher cipher = buildCipher(Cipher.DECRYPT_MODE, aesType, keyHex, ivHex);

        try (InputStream is = Files.newInputStream(in);
            CipherInputStream cis = new CipherInputStream(is, cipher);
            OutputStream os = Files.newOutputStream(out)) {

            byte[] buf = new byte[64 * 1024];
            int r;
            while ((r = cis.read(buf)) != -1) {
                os.write(buf, 0, r);
            }
            os.flush();
        }
    }

    // ─────────────────────────────────────────────────────────────
    // Helper: construir Cipher según modo (ECB/CBC/GCM)
    // ─────────────────────────────────────────────────────────────
    private static Cipher buildCipher(int mode,
                                    EnumAESType aesType,
                                    String keyHex,
                                    String ivHex) throws Exception {
        byte[] keyBytes = hexToBytes(keyHex);
        SecretKeySpec keySpec = new SecretKeySpec(keyBytes, "AES");
        Cipher cipher;
        switch (aesType) {
            case ECB: {
                cipher = Cipher.getInstance("AES/ECB/PKCS5Padding");
                cipher.init(mode, keySpec);
                break;
            }
            case CBC: {
                byte[] ivBytes = hexToBytes(ivHex);
                IvParameterSpec iv = new IvParameterSpec(ivBytes);
                cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
                cipher.init(mode, keySpec, iv);
                break;
            }
            case GCM: {
                byte[] ivBytes = hexToBytes(ivHex);
                // Tag de 128 bits; tu validateIv exige 16 bytes de IV (32 hex).
                GCMParameterSpec gcm = new GCMParameterSpec(128, ivBytes);
                cipher = Cipher.getInstance("AES/GCM/NoPadding");
                cipher.init(mode, keySpec, gcm);
                break;
            }
            default:
                throw new IllegalArgumentException("Modo AES no soportado: " + aesType);
        }
        return cipher;
    }

    // ─────────────────────────────────────────────────────────────
    // Helper local: hex → bytes (evita dependencia externa)
    // ─────────────────────────────────────────────────────────────
    private static byte[] hexToBytes(String hex) {
        int len = hex.length();
        byte[] out = new byte[len / 2];
        for (int i = 0; i < len; i += 2) {
            out[i / 2] = (byte) ((Character.digit(hex.charAt(i), 16) << 4)
                            +  Character.digit(hex.charAt(i + 1), 16));
        }
        return out;
    }

}

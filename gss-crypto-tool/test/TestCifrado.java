import com.scotiabank.gssvault.util.AESFileCipher;

import java.nio.file.*;
import java.nio.charset.StandardCharsets;

public class TestCifrado {
    public static void main(String[] args) {
        Path propsIn = Paths.get("test", "archivo.txt");  // .properties (clave=valor)
        final String KEY_HEX = "00112233445566778899AABBCCDDEEFF00112233445566778899AABBCCDDEEFF"; // 64 hex (32B)
        final String IV_HEX  = "AABBCCDDEEFF00112233445566778899";                                   // 32 hex (16B) (ECB lo ignora)

        try {
            Files.createDirectories(Paths.get("test"));
            if (!Files.exists(propsIn)) {
                throw new IllegalStateException("Falta test/archivo.txt (formato .properties: clave=valor).");
            }

            // 1) Como .properties (cifra/descifra por propiedad)
            runProps("ECB", KEY_HEX, IV_HEX, propsIn);
            runProps("CBC", KEY_HEX, IV_HEX, propsIn);
            runProps("GCM", KEY_HEX, IV_HEX, propsIn);

            // 2) Como archivo “cualquiera” (stream binario) usando el MISMO archivo.txt
            runAny("ECB", KEY_HEX, IV_HEX, propsIn); // IV se ignora en ECB
            runAny("CBC", KEY_HEX, IV_HEX, propsIn);
            runAny("GCM", KEY_HEX, IV_HEX, propsIn);

            System.out.println("\nListo. Revisa la carpeta test/ para los *.cif y *.dec");
        } catch (Exception e) {
            e.printStackTrace();
            System.exit(1);
        }
    }

    // ====== .properties con FileEncrypt/FileDecrypt ======
    private static void runProps(String type, String keyHex, String ivHex, Path input) throws Exception {
        String suf = type.toLowerCase();
        Path cipherOut = Paths.get("test", "archivo_" + suf + ".cif");
        Path plainOut  = Paths.get("test", "archivo_" + suf + ".dec");

        String[] encArgs = new String[6];
        encArgs[0] = type;                 // tu validateArgs lo usa
        encArgs[1] = input.toString();
        encArgs[2] = keyHex;
        encArgs[3] = ivHex;                // ECB lo ignora internamente
        encArgs[4] = cipherOut.toString();
        encArgs[5] = type;
        new AESFileCipher().FileEncrypt(encArgs);

        String[] decArgs = new String[6];
        decArgs[0] = type;
        decArgs[1] = cipherOut.toString();
        decArgs[2] = keyHex;
        decArgs[3] = ivHex;
        decArgs[4] = plainOut.toString();
        decArgs[5] = type;
        AESFileCipher.FileDecrypt(decArgs);

        String inTxt  = Files.readString(input,  StandardCharsets.UTF_8).trim();
        String outTxt = Files.readString(plainOut, StandardCharsets.UTF_8).trim();
        System.out.println("[PROPS] " + type + " -> " + (inTxt.equals(outTxt) ? "OK ✅" : "MISMATCH ❌"));
    }

    // ====== archivo cualquiera con FileEncryptAny/FileDecryptAny ======
    private static void runAny(String type, String keyHex, String ivHex, Path input) throws Exception {
        String suf = type.toLowerCase();
        Path cipherOut = Paths.get("test", "archivo_file_" + suf + ".cif");
        Path plainOut  = Paths.get("test", "archivo_file_" + suf + ".dec");

        String[] encArgs = new String[6];
        encArgs[0] = type;                 // para validateArgs()
        encArgs[1] = input.toString();     // aquí reutilizamos archivo.txt como “archivo general”
        encArgs[2] = keyHex;
        encArgs[3] = ivHex;                // ECB lo ignora
        encArgs[4] = cipherOut.toString();
        encArgs[5] = type;
        AESFileCipher.FileEncryptAny(encArgs);

        String[] decArgs = new String[6];
        decArgs[0] = type;
        decArgs[1] = cipherOut.toString();
        decArgs[2] = keyHex;
        decArgs[3] = ivHex;                // ECB lo ignora
        decArgs[4] = plainOut.toString();
        decArgs[5] = type;
        AESFileCipher.FileDecryptAny(decArgs);

        boolean iguales = Files.mismatch(input, plainOut) == -1;
        System.out.println("[FILE ] " + type + " -> " + (iguales ? "OK ✅" : "MISMATCH ❌"));
    }
}

package ir.behi.tools;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.StandardOpenOption;
import java.security.NoSuchAlgorithmException;
import java.util.Base64;
import java.util.regex.Pattern;

public class AESSimple {
    public final static String ALGORITHM = "AES";
    public final static String AESGCMNoPadding = "AES/GCM/NoPadding";
    private SecretKey key;
    private final int KEY_SIZE = 128; // 128,192,256
    private final int DATA_LENGTH = 128;
    private Cipher encryptionCipher;

    public void init() throws Exception {
        KeyGenerator keyGenerator = KeyGenerator.getInstance(ALGORITHM);
        keyGenerator.init(KEY_SIZE);
        key = keyGenerator.generateKey();
    }

    public static boolean isEncrypt(String text){
        String pattern= "^([A-Za-z0-9+/]{4})*([A-Za-z0-9+/]{3}=|[A-Za-z0-9+/]{2}==)?$";
        return Pattern.compile(pattern).matcher(text).find();
    }


    public String encrypt(String data) throws Exception {
        byte[] dataInBytes = data.getBytes();
        encryptionCipher = Cipher.getInstance(AESGCMNoPadding);
        encryptionCipher.init(Cipher.ENCRYPT_MODE, key);
        byte[] encryptedBytes = encryptionCipher.doFinal(dataInBytes);
        return encode(encryptedBytes);
    }

    public String decrypt(String encryptedData) throws Exception {
        byte[] dataInBytes = decode(encryptedData);
        Cipher decryptionCipher = Cipher.getInstance(AESGCMNoPadding);

        GCMParameterSpec spec = new GCMParameterSpec(DATA_LENGTH, encryptionCipher.getIV());
        decryptionCipher.init(Cipher.DECRYPT_MODE, key, spec);
        byte[] decryptedBytes = decryptionCipher.doFinal(dataInBytes);
        return new String(decryptedBytes);
    }

    private String encode(byte[] data) {
        return Base64.getEncoder().encodeToString(data);
    }

    private byte[] decode(String data) {
        return Base64.getDecoder().decode(data);
    }

    public static void writeProviderToFile() throws NoSuchAlgorithmException, IOException {
        String fileName = "AESProviders.txt";
        Path path = Paths.get(fileName);
        Files.createFile(path);
        KeyGenerator.getInstance(ALGORITHM).getProvider().values().stream()
                .map(m -> m.toString())
                .distinct()
                .sorted()
                .forEach(f -> {
                    try {
                        Files.write(path, (f + "\n").getBytes(), StandardOpenOption.APPEND);
                    } catch (Exception ex) {
                        ex.printStackTrace();
                    }
                });

    }
}

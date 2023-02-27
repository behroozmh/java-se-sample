package ir.behi.tools;

import javax.crypto.*;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.UnsupportedEncodingException;
import java.nio.charset.StandardCharsets;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;
import java.util.Base64;

public class AESCryptoCBC {
    public final static String ALGORITHM = "AES";
    public final static String PBKDF2WithHmacSHA256 = "PBKDF2WithHmacSHA256";
    public final static String AESCBCPKCS5Padding = "AES/CBC/PKCS5Padding";

    /**
     * @param n size of n (128, 192, and 256) bits
     * @return generate randomKey
     * @throws NoSuchAlgorithmException
     */
    public static SecretKey generateKey(int n) throws NoSuchAlgorithmException {
        KeyGenerator keyGenerator = KeyGenerator.getInstance(ALGORITHM);
        keyGenerator.init(n);
        SecretKey key = keyGenerator.generateKey();
        return key;
    }

    /**
     * @param password
     * @param salt
     * @return
     * @throws NoSuchAlgorithmException
     * @throws InvalidKeySpecException
     */
    public static SecretKey getKeyFromPassword(String cipherInstance, String password, String salt)
            throws NoSuchAlgorithmException, InvalidKeySpecException {
        SecretKeyFactory factory = SecretKeyFactory.getInstance(cipherInstance);
        KeySpec spec = new PBEKeySpec(password.toCharArray(), salt.getBytes(), 65536, 128);
        SecretKey secret = new SecretKeySpec(factory.generateSecret(spec).getEncoded(), ALGORITHM);
        return secret;
    }

    /**
     * @return
     */
    public static IvParameterSpec generateIv(String key) {
        byte[] iv = key.getBytes(StandardCharsets.UTF_8);
        return new IvParameterSpec(iv);
    }

    /**
     * @param cipherText
     * @param key
     * @return
     * @throws NoSuchPaddingException
     * @throws NoSuchAlgorithmException
     * @throws InvalidAlgorithmParameterException
     * @throws InvalidKeyException
     * @throws BadPaddingException
     * @throws IllegalBlockSizeException
     */
    public static String decrypt(String cipherText, SecretKey key) throws NoSuchPaddingException, NoSuchAlgorithmException,
            InvalidKeyException, BadPaddingException, IllegalBlockSizeException {
        Cipher cipher = Cipher.getInstance(ALGORITHM);
        cipher.init(Cipher.DECRYPT_MODE, key);
        byte[] plainText = cipher.doFinal(Base64.getDecoder().decode(cipherText));
        return new String(plainText, StandardCharsets.UTF_8);
    }

    /**
     *
     * @param input
     * @param cipherInstance
     * @param password
     * @param salt
     * @return
     * @throws Exception
     */
    public static String encrypt(String input, String cipherInstance, String password, String salt) throws Exception {
        SecretKey secretKey = getKeyFromPassword(cipherInstance, password, salt);
        Cipher cipher = Cipher.getInstance(ALGORITHM);
        cipher.init(Cipher.ENCRYPT_MODE, secretKey);
        byte[] cipherText = cipher.doFinal(input.getBytes(StandardCharsets.UTF_8));
        return Base64.getEncoder().encodeToString(cipherText);
    }

    /**
     *
     * @param cipherText
     * @param cipherInstance
     * @param ivPassword iv must multiple of 16 byte
     * @param saltPassword salt must be multiple of 16 byte
     * @return
     * @throws NoSuchPaddingException
     * @throws NoSuchAlgorithmException
     * @throws InvalidAlgorithmParameterException
     * @throws InvalidKeyException
     * @throws UnsupportedEncodingException
     * @throws IllegalBlockSizeException
     * @throws BadPaddingException
     */
    public static String encryptWithIv(String cipherText, String cipherInstance, String ivPassword, String saltPassword) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidAlgorithmParameterException, InvalidKeyException, UnsupportedEncodingException, IllegalBlockSizeException, BadPaddingException {
        Cipher cipher = Cipher.getInstance(cipherInstance);
        byte[] iv = ivPassword.getBytes(StandardCharsets.UTF_8);
        byte[] salt = saltPassword.getBytes(StandardCharsets.UTF_8);
        SecretKeySpec skeySpec = new SecretKeySpec(salt, ALGORITHM);
        cipher.init(Cipher.ENCRYPT_MODE, skeySpec, new IvParameterSpec(iv));
        byte[] outputBytes = cipher.doFinal(cipherText.getBytes(StandardCharsets.UTF_8));
        return Base64.getEncoder().encodeToString(outputBytes);
    }
}

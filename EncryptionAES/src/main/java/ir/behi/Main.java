package ir.behi;

import ir.behi.tools.AESCryptoCBC;
import ir.behi.tools.AESSimple;

public class Main {

    public static void main(String[] args) throws Exception {
        TestAESCBC();
//        TestAESSimple();
    }

    private static void TestAESCBC() throws Exception {
        String text = "jdbc:postgresql://localhost:5432/mydb";
        System.out.println("## Plain First=" + text);
        String password = "12";
        System.out.println("########## Plain password=" + password);

        String salt = "qwertyuiopasdfghjklzxc";
        System.out.println("########## Plain salt=" + salt);

        boolean isSalt=AESCryptoCBC.isEncrypt(salt);

        String encryptText = AESCryptoCBC.encrypt(text,AESCryptoCBC.PBKDF2WithHmacSHA256,password,salt);
        boolean isEncryptText=AESCryptoCBC.isEncrypt(encryptText);

        System.out.println("########## Plain encryptText=" + encryptText);

        String decryptText = AESCryptoCBC.decrypt(encryptText, AESCryptoCBC.getKeyFromPassword(AESCryptoCBC.PBKDF2WithHmacSHA256,password, salt));

        System.out.println("########## Plain decryptText=" + decryptText);

    }

    private static void TestAESSimple() throws Exception {
        AESSimple aes_encryption = new AESSimple();
        aes_encryption.init();
        String text = "Hello world";
        System.out.println("########## Base Data Text: " + text);
        String encryptedData = aes_encryption.encrypt(text);
        String decryptedData = aes_encryption.decrypt(encryptedData);
    }

}

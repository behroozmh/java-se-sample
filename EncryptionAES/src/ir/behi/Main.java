package ir.behi;

import ir.behi.tools.AESCryptoCBC;
import ir.behi.tools.AESSimple;

public class Main {

    public static void main(String[] args) throws Exception {
//        TestAESCBC();
        TestAESSimple();
    }

    private static void TestAESCBC() throws Exception {
        String text = "SakhadSecret";
        System.out.println("## Plain First=" + text);

        String password = "ThisIsSpartaThisIsSparta";
        System.out.println("########## Plain password=" + password);

        String salt = "qwertyuiopasdfghjklzxcvbnm";
        System.out.println("########## Plain salt=" + salt);

        String encryptText = AESCryptoCBC.encrypt(AESCryptoCBC.ALGORITHM, text,
                AESCryptoCBC.getKeyFromPassword(password, salt),
                AESCryptoCBC.generateIv());
        System.out.println("########## Plain encryptText=" + encryptText);

        String decryptText = AESCryptoCBC.decrypt(AESCryptoCBC.ALGORITHM, encryptText,
                AESCryptoCBC.getKeyFromPassword(password, salt),
                AESCryptoCBC.generateIv());
        System.out.println("########## Plain decryptText=" + decryptText);
    }

    private static void TestAESSimple() throws Exception {
        AESSimple aes_encryption = new AESSimple();
        aes_encryption.init();
        String encryptedData = aes_encryption.encrypt("Hello, welcome to the encryption world");
        String decryptedData = aes_encryption.decrypt(encryptedData);

        System.out.println("########## Encrypted Data : " + encryptedData);
        System.out.println("########## Decrypted Data : " + decryptedData);
    }
}

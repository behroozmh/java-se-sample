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
        String password = "ThisIsSpartaThisIsSparta";
        System.out.println("########## Plain password=" + password);

        String salt = "qwertyuiopasdfghjklzxc";
        System.out.println("########## Plain salt=" + salt);

        String encryptText = AESCryptoCBC.encrypt2(text);
        System.out.println("########## Plain encryptText=" + encryptText);

        String decryptText = AESCryptoCBC.decrypt(encryptText, AESCryptoCBC.getKeyFromPassword(password, salt));

        System.out.println("########## Plain decryptText=" + decryptText);
    }

    private static void TestAESSimple() throws Exception {
        AESSimple aes_encryption = new AESSimple();
//        aes_encryption.writeProviderToFile();
        aes_encryption.init("123");
        String text = "Hello, welcome to the encryption world";
        System.out.println("########## Base Data Text: " + text);
        String encryptedData = aes_encryption.encrypt(text);
        String decryptedData = aes_encryption.decrypt(encryptedData);
        System.out.println("########## Encrypted Data : " + encryptedData);
        System.out.println("########## Decrypted Data : " + decryptedData);
    }

}

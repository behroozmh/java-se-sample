package ir.behi;

import ir.behi.tools.AESSimple;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

public class MainTest {

    @Test
    public void testAESSimple() throws Exception {
        String simpleText = "Secret";
        System.out.println("########## simpleText Data : " + simpleText);
        AESSimple aes_encryption = new AESSimple();
        aes_encryption.init();
        String encryptedData = aes_encryption.encrypt(simpleText);
        System.out.println("########## Encrypted Data : " + encryptedData);
        String decryptedData = aes_encryption.decrypt(encryptedData);
        System.out.println("########## Decrypted Data : " + decryptedData);
        Assertions.assertEquals(simpleText,decryptedData);
    }

}

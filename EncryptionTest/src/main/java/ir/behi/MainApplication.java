package ir.behi;

import ir.behi.tools.MyCrypto;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;

public class MainApplication {
    public static void main(String[] args) throws NoSuchAlgorithmException, InvalidKeySpecException,
            InvalidAlgorithmParameterException, NoSuchPaddingException,
            IllegalBlockSizeException, BadPaddingException, InvalidKeyException {

        String text = "SakhadSecret";
        System.out.println("## Plain First=" + text);

        String password = "ThisIsSpartaThisIsSparta";
        System.out.println("## Plain password=" + password);

        String salt = "qwertyuiopasdfghjklzxcvbnm";
        System.out.println("## Plain salt=" + salt);

        String encryptText = MyCrypto.encrypt(MyCrypto.ALGORITHM, text,
                MyCrypto.getKeyFromPassword(password, salt),
                MyCrypto.generateIv());
        System.out.println("## Plain encryptText=" + encryptText);

        String decryptText = MyCrypto.decrypt(MyCrypto.ALGORITHM, encryptText,
                MyCrypto.getKeyFromPassword(password, salt),
                MyCrypto.generateIv());
        System.out.println("## Plain decryptText=" + decryptText);
    }
}

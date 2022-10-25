package code.shubham.random;

import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;

public class SaltUtil {

    public static byte[] createAndGetBytes() throws NoSuchAlgorithmException {
        SecureRandom rand = SecureRandom.getInstance("SHA1PRNG");
        byte[] salt = new byte[16];
        rand.nextBytes(salt);
        return salt;
    }

    public static byte[] concat(byte[] salt, byte[] encryptedData) {
        byte[] encryptedDataWithSalt = new byte[salt.length + encryptedData.length];
        System.arraycopy(salt, 0, encryptedDataWithSalt, 0, salt.length);
        System.arraycopy(encryptedData, 0, encryptedDataWithSalt, salt.length, encryptedData.length);
        return encryptedDataWithSalt;
    }

    public static byte[] extract(byte[] data) {
        byte[] salt = new byte[16];
        System.arraycopy(data, 0, salt, 0, salt.length);
        return salt;
    }

    public static byte[] extractKey(byte[] data) {
        byte[] encryptedData = new byte[data.length - 16];
        System.arraycopy(data, 16, encryptedData, 0, encryptedData.length);
        return encryptedData;
    }
}

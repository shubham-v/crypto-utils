package code.shubham;

import code.shubham.encryption.keys.asymmetric.RSAUtil;
import code.shubham.encryption.keys.symmetric.AESUtil;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.codec.binary.Base64;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;

@Slf4j
public class CryptoUtil {

    private static final String AES = "AES";


    public static byte[] encryptUsingSecretKey(byte[] key, byte[] data) {
        byte[] encryptedText = null;
        try {
            encryptedText = AESUtil.encrypt(key, data);
        } catch (Exception e) {
            log.error("Error while encrypting using secret key from byte array" + data, e);
        }
        return encryptedText;
    }

    public static byte[] decryptUsingSecretKey(byte[] key, byte[] data) {
        byte[] decryptedText = null;
        try {
            decryptedText = AESUtil.decrypt(key, data);
        } catch (Exception e) {
            log.error("Error while decrypting using secret key from byte array" + data, e);
        }
        return decryptedText;
    }

    public static byte[] decryptUsingPrivateKey(byte[] key, byte[] data) {
        byte[] decryptedText = null;
        try {
            decryptedText = RSAUtil.decrypt(key, data);
        } catch (Exception e) {
            log.error("Error while forming private key from byte array" + data, e);
        }
        return decryptedText;
    }

    public static SecretKey decryptAndGetSymmetricKey(String encryptedSymmetricKey, PrivateKey privateKey)
            throws NoSuchPaddingException, IllegalBlockSizeException, NoSuchAlgorithmException,
            BadPaddingException, InvalidKeyException {
        byte[] symmetricKey= RSAUtil.decrypt(privateKey, Base64.decodeBase64(encryptedSymmetricKey));
        return new SecretKeySpec(symmetricKey, 0, symmetricKey.length, AES);
    }
}

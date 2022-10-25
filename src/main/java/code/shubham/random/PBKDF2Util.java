package code.shubham.random;

import code.shubham.exception.CryptoException;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.ShortBufferException;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;

public class PBKDF2Util {
    public static byte[] encryptUsingPassword(String password, byte[] data) throws CryptoException {
        try {
            byte[] salt = SaltUtil.createAndGetBytes();
            SecretKey encKey = generateKey(password, salt);
            byte[] encryptedData = encrypt(encKey, data);
            return SaltUtil.concat(salt, encryptedData);
        } catch (Exception exception) {
            throw new CryptoException("Error while encrypting using password", exception);
        }
    }

    public static byte[] decryptUsingPassword(String password, byte[] data) throws CryptoException {
        try {
            byte[] salt = SaltUtil.extract(data);
            byte[] encryptedData = SaltUtil.extractKey(data);
            SecretKey encKey = generateKey(password, salt);
            return decrypt(encKey, encryptedData);
        } catch (Exception exception) {
            throw new CryptoException("Error while decrypting using password", exception);
        }
    }

    public static byte[] generateHash(String password, byte[] salt) throws NoSuchAlgorithmException, InvalidKeySpecException {
        PBEKeySpec passwordKeySpec = new PBEKeySpec(password.toCharArray(), salt, 1000, 128);
        SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA1");
        return factory.generateSecret(passwordKeySpec).getEncoded();
    }

    private static SecretKey generateKey(String password, byte[] salt) throws NoSuchAlgorithmException, InvalidKeySpecException {
        return new SecretKeySpec(generateHash(password, salt), "AES");
    }

    public static byte[] encrypt(SecretKey key, byte[] data) throws ShortBufferException, IllegalBlockSizeException, BadPaddingException, InvalidKeyException, NoSuchAlgorithmException, NoSuchPaddingException, InvalidAlgorithmParameterException {
        Cipher cipher = createCipherForEncryption(key, 1);
        return doCrypto(cipher, data);
    }

    public static byte[] decrypt(SecretKey key, byte[] data) throws InvalidKeyException, NoSuchAlgorithmException, NoSuchPaddingException, InvalidAlgorithmParameterException, ShortBufferException, IllegalBlockSizeException, BadPaddingException {
        Cipher cipher = createCipherForEncryption(key, 2);
        return doCrypto(cipher, data);
    }

    private static Cipher createCipherForEncryption(SecretKey key, int cipherMode) throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, InvalidAlgorithmParameterException {
        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        cipher.init(cipherMode, key, new IvParameterSpec(new byte[16]));
        return cipher;
    }

    private static byte[] doCrypto(Cipher cipher, byte[] data) throws ShortBufferException, IllegalBlockSizeException, BadPaddingException {
        return cipher.doFinal(data);
    }
}
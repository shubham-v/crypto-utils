package encryption.keys.symmetric;

import hash.Base64Util;
import lombok.extern.slf4j.Slf4j;
import random.SaltUtil;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.KeyGenerator;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SealedObject;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.ShortBufferException;
import javax.crypto.interfaces.PBEKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.Serializable;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;
import java.util.Base64;

@Slf4j
public class AESUtil {

    public static final String AES_ECB_PKCS5_PADDING = "AES/ECB/PKCS5Padding";
    public static final String AES_CBC_PKCS5_PADDING = "AES/CBC/PKCS5Padding";
    private static final String AES = "AES";
    private static final int SYMMETRIC_KEY_SIZE = 128;
    private static final String PBKDF2_WITH_HMAC_SHA_256 = "PBKDF2WithHmacSHA256";
    private static final int INITIALIZATION_VECTOR_SIZE =  16;
    private static final String PBKDF2_WITH_HMAC_SHA_1 = "PBKDF2WithHmacSHA1";

    public static String generate() throws Exception {
        return Base64Util.toBase64(generateKey().getEncoded());
    }

    private static SecretKey generateKey() throws Exception {
        SecretKey secretKey;
        try {
            KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
            keyGenerator.init(SYMMETRIC_KEY_SIZE);
            secretKey = keyGenerator.generateKey();
        } catch (Exception e) {
            log.error("Error while generating AES key", e);
            throw e;
        }
        return secretKey;
    }

    private static SecretKey generateKey(String password, byte[] salt)
            throws NoSuchAlgorithmException, InvalidKeySpecException {
        PBEKeySpec passwordKeySpec = new PBEKeySpec(password.toCharArray(), salt, 1000, 128);
        SecretKeyFactory factory = SecretKeyFactory.getInstance(PBKDF2_WITH_HMAC_SHA_1);
        PBEKey key = (PBEKey) factory.generateSecret(passwordKeySpec);
        SecretKeySpec encryptionKey = new SecretKeySpec(key.getEncoded(), AES);
        return encryptionKey;
    }

    public static IvParameterSpec generateInitializationVectorSpec() {
        byte[] initializationVectorSize = new byte[INITIALIZATION_VECTOR_SIZE];
        new SecureRandom().nextBytes(initializationVectorSize);
        return new IvParameterSpec(initializationVectorSize);
    }

    public static SecretKey getKeyFromPassword(String password, String salt)
            throws NoSuchAlgorithmException, InvalidKeySpecException {
        try {
            SecretKeyFactory factory = SecretKeyFactory.getInstance(PBKDF2_WITH_HMAC_SHA_256);
            KeySpec spec = new PBEKeySpec(password.toCharArray(), salt.getBytes(), 65536, 256);
            SecretKey secret = new SecretKeySpec(factory.generateSecret(spec).getEncoded(), AES);
            return secret;
        } catch (Exception ex) {
            log.error("Error getting AES key from password");
            throw ex;
        }
    }

    public static byte[] encrypt(byte[] aesKey, byte[] data) throws Exception {
        SecretKey key = new SecretKeySpec(aesKey, AES);
        return encrypt(key, data, AES_ECB_PKCS5_PADDING);
    }

    public static byte[] encrypt(SecretKey key, byte[] data, String transformation) throws Exception {
        byte[] encryptedText;
        try {
            Cipher cipher = Cipher.getInstance("AES");
            cipher.init(Cipher.ENCRYPT_MODE, key);
            encryptedText = cipher.doFinal(data);
        } catch (Exception ex) {
            log.error(String.format("Error while encrypting data using aes key %s", data));
            throw ex;
        }
        return encryptedText;
    }

    public static String encrypt(String algorithm, String input, SecretKey key,
                                 IvParameterSpec iv) throws NoSuchPaddingException, NoSuchAlgorithmException,
            InvalidAlgorithmParameterException, InvalidKeyException,
            BadPaddingException, IllegalBlockSizeException {
        Cipher cipher = Cipher.getInstance(algorithm);
        cipher.init(Cipher.ENCRYPT_MODE, key, iv);
        byte[] cipherText = cipher.doFinal(input.getBytes());
        return Base64.getEncoder().encodeToString(cipherText);
    }

    public static byte[] decrypt(byte[] aesKey, byte[] data) throws Exception {
        SecretKey key = new SecretKeySpec(aesKey, 0, aesKey.length, AES);
        return decrypt(key, data, AES_ECB_PKCS5_PADDING);
    }

    public static byte[] decrypt(SecretKey key, byte[] data, String transformation) throws Exception {
        byte[] decryptedText = null;
        try {
            Cipher cipher = Cipher.getInstance(transformation);
            cipher.init(Cipher.DECRYPT_MODE, key);
            decryptedText = cipher.doFinal(data);
        } catch (Exception ex) {
            log.error(String.format("Error while decrypting data using aes key %s", data), ex);
            throw ex;
        }
        return decryptedText;
    }

    public static String decrypt(String algorithm, String cipherText, SecretKey key,
                                 IvParameterSpec iv) throws NoSuchPaddingException, NoSuchAlgorithmException,
            InvalidAlgorithmParameterException, InvalidKeyException,
            BadPaddingException, IllegalBlockSizeException {
        Cipher cipher = Cipher.getInstance(algorithm);
        cipher.init(Cipher.DECRYPT_MODE, key, iv);
        byte[] plainText = cipher.doFinal(Base64.getDecoder()
                .decode(cipherText));
        return new String(plainText);
    }

    public static SealedObject encryptObject(String algorithm, Serializable object,
                                             SecretKey key, IvParameterSpec iv)
            throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidAlgorithmParameterException,
            InvalidKeyException, IOException, IllegalBlockSizeException {
        try {
            Cipher cipher = Cipher.getInstance(algorithm);
            cipher.init(Cipher.ENCRYPT_MODE, key, iv);
            SealedObject sealedObject = new SealedObject(object, cipher);
            return sealedObject;
        } catch (Exception ex) {
            log.error("Exception occurred while decrypting object");
            throw ex;
        }
    }

    public static Serializable decryptObject(String algorithm, SealedObject sealedObject,
                                             SecretKey key, IvParameterSpec iv)
            throws InvalidAlgorithmParameterException, NoSuchPaddingException, IllegalBlockSizeException,
            NoSuchAlgorithmException, IOException, BadPaddingException, InvalidKeyException, ClassNotFoundException {
        try {
            Cipher cipher = Cipher.getInstance(algorithm);
            cipher.init(Cipher.DECRYPT_MODE, key, iv);
            Serializable unsealObject = (Serializable) sealedObject.getObject(cipher);
            return unsealObject;
        } catch (Exception ex) {
            log.error("Exception occurred while decrypting object");
            throw ex;
        }
    }

    public static void encryptFile(String algorithm, SecretKey key, IvParameterSpec iv,
                                   File inputFile, File outputFile) throws IOException, NoSuchPaddingException,
            NoSuchAlgorithmException, InvalidAlgorithmParameterException, InvalidKeyException,
            BadPaddingException, IllegalBlockSizeException {
        try {
            Cipher cipher = Cipher.getInstance(algorithm);
            cipher.init(Cipher.ENCRYPT_MODE, key, iv);
            FileInputStream inputStream = new FileInputStream(inputFile);
            FileOutputStream outputStream = new FileOutputStream(outputFile);
            byte[] buffer = new byte[64];
            int bytesRead;
            while ((bytesRead = inputStream.read(buffer)) != -1) {
                byte[] output = cipher.update(buffer, 0, bytesRead);
                if (output != null) {
                    outputStream.write(output);
                }
            }
            byte[] outputBytes = cipher.doFinal();
            if (outputBytes != null) {
                outputStream.write(outputBytes);
            }
            inputStream.close();
            outputStream.close();
        } catch (Exception ex) {
            log.error("Exception occurred while encrypting file");
            throw ex;
        }
    }

    public static byte[] encryptUsingPassword(String password, byte[] data) throws Exception {
        try {
            byte[] saltInBytes = SaltUtil.createAndGetBytes();
            SecretKey encryptionKey = generateKey(password, saltInBytes);
            byte[] encryptedData = encrypt(encryptionKey, data);
            return SaltUtil.concat(saltInBytes, encryptedData);
        } catch (Exception ex) {
            log.error("Error while encrpting using password");
            throw ex;
        }
    }

    public static byte[] encrypt(SecretKey key, byte[] data) throws ShortBufferException, IllegalBlockSizeException, BadPaddingException, InvalidKeyException, NoSuchAlgorithmException, NoSuchPaddingException, InvalidAlgorithmParameterException {
        Cipher cipher = createCipher(key, Cipher.ENCRYPT_MODE);
        return doCrypto(cipher, data);
    }

    public static byte[] decrypt(SecretKey key, byte[] data) throws InvalidKeyException, NoSuchAlgorithmException, NoSuchPaddingException, InvalidAlgorithmParameterException, ShortBufferException, IllegalBlockSizeException, BadPaddingException {
        Cipher cipher = createCipher(key, Cipher.DECRYPT_MODE);
        return doCrypto(cipher, data);
    }

    private static Cipher createCipher(SecretKey key, int cipherMode) throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, InvalidAlgorithmParameterException {
        Cipher cipher = Cipher.getInstance(AES_CBC_PKCS5_PADDING);
        cipher.init(cipherMode, key, new IvParameterSpec(new byte[INITIALIZATION_VECTOR_SIZE]));
        return cipher;
    }

    private static byte[] doCrypto(Cipher cipher, byte[] data)
            throws ShortBufferException, IllegalBlockSizeException, BadPaddingException {
        return cipher.doFinal(data);
    }

}

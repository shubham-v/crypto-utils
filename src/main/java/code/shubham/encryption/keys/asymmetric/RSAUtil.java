package code.shubham.encryption.keys.asymmetric;

import lombok.extern.slf4j.Slf4j;
import org.apache.commons.codec.binary.Base64;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.KeyFactory;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateException;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;

@Slf4j
public class RSAUtil {

    private static final String RSA_ECB_PKCS1_PADDING = "RSA/ECB/PKCS1Padding";
    private static final String PKCS12 = "PKCS12";

    public static byte[] encrypt(byte[] key, byte[] data)
            throws InvalidKeySpecException, NoSuchAlgorithmException,
            NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException, InvalidKeyException {
        PublicKey publicKey = null;
        try {
            publicKey = KeyFactory.getInstance("RSA").generatePublic(new X509EncodedKeySpec(key));
        } catch (Exception ex) {
            log.error(String.format("Error while forming public key from byte array %s", data));
            throw ex;
        }
        return encrypt(publicKey, data);
    }

    public static byte[] encrypt(PublicKey key, byte[] data)
            throws NoSuchPaddingException, IllegalBlockSizeException,
            NoSuchAlgorithmException, BadPaddingException, InvalidKeyException {
        byte[] cipherText;
        try {
            final Cipher cipher = Cipher.getInstance(RSA_ECB_PKCS1_PADDING);
            cipher.init(Cipher.ENCRYPT_MODE, key);
            cipherText = cipher.doFinal(data);
        } catch (Exception ex) {
            log.error(String.format("Error while encrypting data using public key %s", data));
            throw ex;
        }
        return Base64.encodeBase64(cipherText);
    }

    public static byte[] decrypt(byte[] key, byte[] data)
            throws InvalidKeySpecException, NoSuchAlgorithmException,
            NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException, InvalidKeyException {
        PrivateKey privateKey = null;
        try {
            privateKey = KeyFactory.getInstance("RSA").generatePrivate(new PKCS8EncodedKeySpec(key));
        } catch (Exception ex) {
            log.error(String.format("Error while forming private key from byte array %s", data));
            throw ex;
        }
        return decrypt(privateKey, data);
    }

    public static byte[] decrypt(Key key, byte[] data)
            throws NoSuchPaddingException, IllegalBlockSizeException,
            NoSuchAlgorithmException, BadPaddingException, InvalidKeyException {
        byte[] decodedData = Base64.decodeBase64(data);
        byte[] decryptedText;
        try {
            final Cipher cipher = Cipher.getInstance(RSA_ECB_PKCS1_PADDING);
            cipher.init(Cipher.DECRYPT_MODE, key);
            decryptedText = cipher.doFinal(decodedData);
        } catch (Exception ex) {
            log.error(String.format("Error while decrypting data using private key %s", data));
            throw ex;
        }
        return decryptedText;
    }

    public PrivateKey getPrivateKey(byte[] p12Key, String password, String alias)
            throws UnrecoverableKeyException, CertificateException, KeyStoreException,
            IOException, NoSuchAlgorithmException {
        ByteArrayInputStream inputStream = null;
        PrivateKey privateKey;
        try {
            KeyStore ks = KeyStore.getInstance("PKCS12");
            inputStream = new ByteArrayInputStream(p12Key);
            ks.load(inputStream, password.toCharArray());
            privateKey = (PrivateKey) ks.getKey(alias, password.toCharArray());
        } catch (Exception ex) {
            log.error("Exception occurred while loading private key");
            throw ex;
        } finally {
            if (inputStream != null) {
                try {
                    inputStream.close();
                } catch (Exception ex) {
//                    log.error("Error while closing input stream for private key", ex);
                }
            }
        }
        return privateKey;
    }

    public PublicKey getPublicKey(byte[] p12Key, String password, String alias) {
        ByteArrayInputStream inputStream = null;
        PublicKey publicKey = null;
        try {
            KeyStore ks = KeyStore.getInstance(PKCS12);
            inputStream = new ByteArrayInputStream(p12Key);
            ks.load(inputStream, password.toCharArray());
            publicKey = ks.getCertificate(alias).getPublicKey();
        } catch (Exception e) {
            log.error("Exception occurred while loading public key");
        } finally {
            if (inputStream != null) {
                try {
                    inputStream.close();
                } catch (Exception ex) {
//                    log.error("Error while closing input stream for public key", ex);
                }
            }
        }
        return publicKey;
    }

}

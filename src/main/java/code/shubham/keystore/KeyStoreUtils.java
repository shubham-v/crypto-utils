package code.shubham.keystore;

import code.shubham.encryption.keys.asymmetric.RSAUtil;
import code.shubham.encryption.keys.symmetric.AESUtil;
import code.shubham.encryption.keys.symmetric.AES_KEY_SIZE;

import javax.crypto.SecretKey;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.Key;
import java.security.KeyPair;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;

public class KeyStoreUtils {

    public static KeyStore create(KeyStoreType type, Path storePath, String password)
            throws CertificateException, KeyStoreException, IOException, NoSuchAlgorithmException {
        return create(type, storePath, password.toCharArray());
    }

    public static KeyStore create(KeyStoreType type, Path storePath, char[] password)
            throws KeyStoreException, IOException, CertificateException, NoSuchAlgorithmException {
        KeyStore keyStore = KeyStore.getInstance(type.name());
        keyStore.load(null, password);
        if (!Files.exists(storePath)) {
            Files.createDirectories(storePath.getParent());
            Files.createFile(storePath);
        }
        try (FileOutputStream keyStoreOutputStream = new FileOutputStream("keystores/keystore.jks")) {
            keyStore.store(keyStoreOutputStream, password);
        } catch (FileNotFoundException e) {
            throw new RuntimeException(e);
        } catch (IOException e) {
            throw new RuntimeException(e);
        } catch (CertificateException e) {
            throw new RuntimeException(e);
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
        }
        return keyStore;
    }

    public static void saveSymmetricKey(String fileStoreName, SecretKey secretKey, String alias, char[] pwdArray) throws KeyStoreException, IOException, CertificateException, NoSuchAlgorithmException {
        KeyStore ks = KeyStore.getInstance("pkcs12");
        if (!Files.exists(Path.of(fileStoreName)))
            Files.createFile(Path.of(fileStoreName));
        ks.load(new FileInputStream(fileStoreName), pwdArray);
        KeyStore.SecretKeyEntry secret
                = new KeyStore.SecretKeyEntry(secretKey);
        KeyStore.ProtectionParameter password
                = new KeyStore.PasswordProtection(pwdArray);
        ks.setEntry(alias, secret, password);
    }

    public static void writeToFile(KeyStore store, char[] password, String filePath) throws IOException, CertificateException, KeyStoreException, NoSuchAlgorithmException {
        Path storePath = Path.of(filePath);
        if (!Files.exists(storePath)) {
            Files.createDirectories(storePath.getParent());
            Files.createFile(storePath);
        }
        FileOutputStream fos = new FileOutputStream(filePath);
        store.store(fos, password);
        fos.close();
    }


    public static KeyStore readFromFile(KeyStoreType type, String password, String filePath) throws IOException, CertificateException, KeyStoreException, NoSuchAlgorithmException {
        return KeyStoreUtils.readFromFile(type, password.toCharArray(), filePath);
    }

    public static KeyStore readFromFile(KeyStoreType type, char[] password, String filePath) throws IOException, CertificateException, KeyStoreException, NoSuchAlgorithmException {
        KeyStore store = KeyStore.getInstance(type.name());
        store.load(new FileInputStream(filePath), password);
        return store;
    }

    public static byte[] getBytes(KeyStore store, char[] password, String filePath) throws IOException, CertificateException, KeyStoreException, NoSuchAlgorithmException {
        KeyStoreUtils.writeToFile(store, password, filePath);
        InputStream inputStream = new FileInputStream(filePath);
        return inputStream.readAllBytes();
    }

    public static byte[] createKeyStoreAndGetBytes(
            String keyStoreFilePath, KeyStoreType keyStoreType, String password, String alias, SecretKey secretKey)
            throws CertificateException, KeyStoreException, IOException, NoSuchAlgorithmException {
        char[] passwordArray = password.toCharArray();

        KeyStore keyStore = KeyStore.getInstance(keyStoreType.name());
        keyStore.load(null, passwordArray);
        KeyStore.SecretKeyEntry secret
                = new KeyStore.SecretKeyEntry(secretKey);
        KeyStore.ProtectionParameter keyStorePassword
                = new KeyStore.PasswordProtection(passwordArray);
        keyStore.setEntry(alias, secret, keyStorePassword);

        return KeyStoreUtils.getBytes(keyStore, passwordArray, keyStoreFilePath);
    }

    public static byte[] createKeyStoreAndGetBytes(
            String keyStoreFilePath, KeyStoreType keyStoreType, String password, String alias,
            PrivateKey privateKey, PublicKey publicKey)
            throws Exception {
        char[] passwordArray = password.toCharArray();

        KeyStore keyStore = KeyStore.getInstance(keyStoreType.name());
        keyStore.load(null, passwordArray);
        X509Certificate[] certificateChain = new X509Certificate[2];
        certificateChain[0] = RSAUtil.createCertificate("CN=Client", "CN=CA", publicKey, privateKey);
        certificateChain[1] = RSAUtil.createCertificate("CN=CA", "CN=CA", publicKey, privateKey);
        keyStore.setKeyEntry(alias, privateKey, passwordArray, certificateChain);

        return KeyStoreUtils.getBytes(keyStore, passwordArray, keyStoreFilePath);
    }

    public static void main(String[] args) throws Exception {
        String keyStorePath = "keystores/keystore.p12";
        String password = "password";
        String alias = "AESSecretAccessTokenSecretAlias";
//        SecretKey secretKey = AESUtil.generateKey(AES_KEY_SIZE._256);

        KeyPair keyPair = RSAUtil.generate();
        X509Certificate certificate = RSAUtil.createCertificate("CN=Client", "CN=Client", keyPair.getPublic(), keyPair.getPrivate());
        byte[] keyBytes = createKeyStoreAndGetBytes(
                keyStorePath, KeyStoreType.pkcs12, password, alias, keyPair.getPrivate(), keyPair.getPublic());
        System.out.println(keyBytes);

        KeyStore store = KeyStoreUtils.readFromFile(KeyStoreType.pkcs12, password, keyStorePath);
        Key readKey = store.getKey(alias, password.toCharArray());

        if (keyPair.getPrivate().equals(readKey)) {
            System.out.println("true");
        }


//        String password = "passwordforalias1";
//        KeyStoreUtils.saveSymmetricKey(alias + "symmentric.p12", secretKey, alias, password.toCharArray());
    }

}

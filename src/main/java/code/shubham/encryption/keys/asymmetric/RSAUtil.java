package code.shubham.encryption.keys.asymmetric;

import lombok.extern.slf4j.Slf4j;
import org.apache.commons.codec.binary.Base64;
import org.bouncycastle.asn1.x509.X509Name;
import org.bouncycastle.x509.X509V3CertificateGenerator;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.nio.file.Files;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Security;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.security.spec.EncodedKeySpec;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Calendar;
import java.util.Random;

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
                    log.error("Error while closing input stream for public key", ex);
                }
            }
        }
        return publicKey;
    }

    public static KeyPair generate() throws NoSuchAlgorithmException {
        KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
        generator.initialize(2048);
        KeyPair pair = generator.generateKeyPair();
        PrivateKey privateKey = pair.getPrivate();
        PublicKey publicKey = pair.getPublic();
        return pair;
    }

    public static void writeToFile(KeyPair pair) {
        PrivateKey privateKey = pair.getPrivate();
        PublicKey publicKey = pair.getPublic();
        try (FileOutputStream fos = new FileOutputStream("public.key")) {
            fos.write(publicKey.getEncoded());
        } catch (FileNotFoundException e) {
            throw new RuntimeException(e);
        } catch (IOException e) {
            throw new RuntimeException(e);
        }

        try (FileOutputStream fos = new FileOutputStream("private.key")) {
            fos.write(privateKey.getEncoded());
        } catch (FileNotFoundException e) {
            throw new RuntimeException(e);
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }

    public static PublicKey readPublicKeyFromFile(String publicKeyFilePath)
            throws IOException, NoSuchAlgorithmException, InvalidKeySpecException {
        File publicKeyFile = new File(publicKeyFilePath);
        byte[] publicKeyBytes = Files.readAllBytes(publicKeyFile.toPath());
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        EncodedKeySpec publicKeySpec = new X509EncodedKeySpec(publicKeyBytes);
        return keyFactory.generatePublic(publicKeySpec);
    }

//    public static X509Certificate generateSelfSignedCertificate(KeyPair keyPair) throws CertificateException, IOException, NoSuchProviderException, NoSuchAlgorithmException, InvalidKeyException, SignatureException {
//        X509CertInfo certInfo = new X509CertInfo();
//        // Serial number and version
//        certInfo.set(X509CertInfo.SERIAL_NUMBER, new CertificateSerialNumber(new BigInteger(64, new SecureRandom())));
//        certInfo.set(X509CertInfo.VERSION, new CertificateVersion(CertificateVersion.V3));
//
//        // Subject & Issuer
//        X500Name owner = new X500Name(DN_NAME);
//        certInfo.set(X509CertInfo.SUBJECT, owner);
//        certInfo.set(X509CertInfo.ISSUER, owner);
//
//        // Key and algorithm
//        certInfo.set(X509CertInfo.KEY, new CertificateX509Key(keyPair.getPublic()));
//        AlgorithmId algorithm = new AlgorithmId(AlgorithmId.sha1WithRSAEncryption_oid);
//        certInfo.set(X509CertInfo.ALGORITHM_ID, new CertificateAlgorithmId(algorithm));
//
//        // Validity
//        Date validFrom = new Date();
//        Date validTo = new Date(validFrom.getTime() + 50L * 365L * 24L * 60L * 60L * 1000L); //50 years
//        CertificateValidity validity = new CertificateValidity(validFrom, validTo);
//        certInfo.set(X509CertInfo.VALIDITY, validity);
//
//        GeneralNameInterface dnsName = new DNSName("baeldung.com");
//        DerOutputStream dnsNameOutputStream = new DerOutputStream();
//        dnsName.encode(dnsNameOutputStream);
//
//        GeneralNameInterface ipAddress = new IPAddressName("127.0.0.1");
//        DerOutputStream ipAddressOutputStream = new DerOutputStream();
//        ipAddress.encode(ipAddressOutputStream);
//
//        GeneralNames generalNames = new GeneralNames();
//        generalNames.add(new GeneralName(dnsName));
//        generalNames.add(new GeneralName(ipAddress));
//
//        CertificateExtensions ext = new CertificateExtensions();
//        ext.set(SubjectAlternativeNameExtension.NAME, new SubjectAlternativeNameExtension(generalNames));
//
//        certInfo.set(X509CertInfo.EXTENSIONS, ext);
//
//        // Create certificate and sign it
//        X509CertImpl cert = new X509CertImpl(certInfo);
//        cert.sign(keyPair.getPrivate(), SHA1WITHRSA);
//
//        // Since the SHA1withRSA provider may have a different algorithm ID to what we think it should be,
//        // we need to reset the algorithm ID, and resign the certificate
//        AlgorithmId actualAlgorithm = (AlgorithmId) cert.get(X509CertImpl.SIG_ALG);
//        certInfo.set(CertificateAlgorithmId.NAME + "." + CertificateAlgorithmId.ALGORITHM, actualAlgorithm);
//        X509CertImpl newCert = new X509CertImpl(certInfo);
//        newCert.sign(keyPair.getPrivate(), SHA1WITHRSA);
//
//        return newCert;
//    }
//
//    public static Certificate selfSign(KeyPair keyPair, String subjectDN) throws OperatorCreationException, CertificateException, IOException
//    {
//        Provider bcProvider = new BouncyCastleProvider();
//        Security.addProvider(bcProvider);
//
//        long now = System.currentTimeMillis();
//        Date startDate = new Date(now);
//
//        X500Name dnName = new X500Name(subjectDN);
//        BigInteger certSerialNumber = new BigInteger(Long.toString(now)); // <-- Using the current timestamp as the certificate serial number
//
//        Calendar calendar = Calendar.getInstance();
//        calendar.setTime(startDate);
//        calendar.add(Calendar.YEAR, 1); // <-- 1 Yr validity
//
//        Date endDate = calendar.getTime();
//
//        String signatureAlgorithm = "SHA256WithRSA"; // <-- Use appropriate signature algorithm based on your keyPair algorithm.
//
//        ContentSigner contentSigner = new JcaContentSignerBuilder(signatureAlgorithm).build(keyPair.getPrivate());
//
//        JcaX509v3CertificateBuilder certBuilder = new JcaX509v3CertificateBuilder(dnName, certSerialNumber, startDate, endDate, dnName, keyPair.getPublic());
//
//        // Extensions --------------------------
//
//        // Basic Constraints
//        BasicConstraints basicConstraints = new BasicConstraints(true); // <-- true for CA, false for EndEntity
//
//        certBuilder.addExtension(new ASN1ObjectIdentifier("2.5.29.19"), true, basicConstraints); // Basic Constraints is usually marked as critical.
//
//        // -------------------------------------
//
//        return new JcaX509CertificateConverter().setProvider(bcProvider).getCertificate(certBuilder.build(contentSigner));
//    }

    public static X509Certificate createCertificate(String dn, String issuer,
                                                     PublicKey publicKey, PrivateKey privateKey) throws Exception {
        Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());
        X509V3CertificateGenerator certGenerator = new X509V3CertificateGenerator();
        certGenerator.setSerialNumber(BigInteger.valueOf(Math.abs(new Random()
                .nextLong())));
        certGenerator.setIssuerDN(new X509Name(dn));
        certGenerator.setSubjectDN(new X509Name(dn));
        certGenerator.setIssuerDN(new X509Name(issuer)); // Set issuer!
        certGenerator.setNotBefore(Calendar.getInstance().getTime());
        certGenerator.setNotAfter(Calendar.getInstance().getTime());
        certGenerator.setPublicKey(publicKey);
        certGenerator.setSignatureAlgorithm("SHA1WithRSAEncryption");
        X509Certificate certificate = (X509Certificate) certGenerator.generate(
                privateKey, "BC");
        return certificate;
    }

}

import encryption.keys.asymmetric.RSAUtil;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.codec.binary.Base64;
import random.SaltUtil;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;

@Slf4j
public class CryptoUtil {

    private static final String AES = "AES";

    public static SecretKey decryptAndGetSymmetricKey(String encryptedSymmetricKey, PrivateKey privateKey)
            throws NoSuchPaddingException, IllegalBlockSizeException, NoSuchAlgorithmException,
            BadPaddingException, InvalidKeyException {
        byte[] symmetricKey= RSAUtil.decrypt(privateKey, Base64.decodeBase64(encryptedSymmetricKey));
        return new SecretKeySpec(symmetricKey, 0, symmetricKey.length, AES);
    }

}

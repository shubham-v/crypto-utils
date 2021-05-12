package hash;

import lombok.extern.slf4j.Slf4j;
import org.apache.commons.codec.binary.Hex;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

@Slf4j
public class SH256 {

    public static String generate(String message) throws NoSuchAlgorithmException {
        try {
            MessageDigest messageDigest = MessageDigest.getInstance("SHA-256");
            messageDigest.update(message.getBytes());
            byte[] b = messageDigest.digest();
            return Hex.encodeHexString(b);
        } catch (Exception ex) {
            log.error(String.format("Error while generating SHA-256 Hash of data %s", message));
            throw ex;
        }
    }

}

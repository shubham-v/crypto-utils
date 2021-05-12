package hash;

import lombok.extern.slf4j.Slf4j;
import org.apache.commons.codec.binary.Hex;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

@Slf4j
public class SHA512 {

    private static final String SHA512 = "SHA-512";

    public static byte[] generate(String message) throws NoSuchAlgorithmException {
        try {
            MessageDigest messageDigest = MessageDigest.getInstance(SHA512);
            messageDigest.update(message.getBytes());
            return messageDigest.digest();
        } catch (Exception ex) {
            log.error("Error while generating SHA-512 hash");
            throw ex;
        }
    }

    public static String generateAndGetHexString(String data) throws NoSuchAlgorithmException {
        try {
            return Hex.encodeHexString(generate(data));
        } catch (Exception ex) {
            log.error(String.format("Error while generating SHA-512 Hash of data %s", data));
            throw ex;
        }
    }

    public static void main(String[] args) throws NoSuchAlgorithmException {
        System.out.println(generateAndGetHexString("test"));
        System.out.println(Hex.encodeHexString((generate("test"))));
    }

}


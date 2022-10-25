package code.shubham.hash;

import lombok.extern.slf4j.Slf4j;

import java.security.NoSuchAlgorithmException;

@Slf4j
public class HashUtil {
    public static String toBase64(byte[] message) {
        return Base64Util.toBase64(message);
    }

    public static byte[] decodeBase64(String base64String){
        return Base64Util.decodeBase64(base64String);
    }

    public static String generateSha512Hex(String message) {
        String sha512Hex = null;
        try {
            sha512Hex = SHA512.generateAndGetHexString(message);
        } catch (NoSuchAlgorithmException e) {
            log.error("", e);
        }
        return sha512Hex;
    }

    public static byte[] generateSha512(String message) {
        byte[] sha512 = null;
        try {
            sha512 = SHA512.generate(message);
        } catch (NoSuchAlgorithmException e) {
            log.error("", e);
        }
        return sha512;
    }

}

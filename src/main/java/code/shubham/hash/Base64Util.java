package code.shubham.hash;

import lombok.extern.slf4j.Slf4j;
import org.apache.commons.codec.binary.Base64;

@Slf4j
public class Base64Util {

    public static String toBase64(byte[] message) {
        return String.valueOf(Base64.encodeBase64(message));
    }

    public static byte[] decodeBase64(String base64String) {
        return Base64.decodeBase64(base64String);
    }
}

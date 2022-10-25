package code.shubham.otp;

import lombok.extern.slf4j.Slf4j;
import org.apache.commons.lang3.StringUtils;

import javax.crypto.Mac;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

@Slf4j
public class OTP {

    private static final int[] dd = new int[] { 0, 2, 4, 6, 8, 1, 3, 5, 7, 9 };

    private String generateOTP(String otpKey) {
        try {
            String t = Long.toString(System.currentTimeMillis());
            otpKey = otpKey + t;
            byte[] mySecret = otpKey.toString().getBytes();
            SecretKey key = new SecretKeySpec(mySecret, "HmacSHA1");
            Mac m = Mac.getInstance("HmacSHA1");
            m.init(key);
            byte[] hmac = m.doFinal();
            Integer otpTemp = formatOTP(hmac);
            return StringUtils.leftPad(otpTemp.toString(), 6, '0');
        } catch (Exception ex) {
			log.error("Error while generating code.shubham.otp.OTP ", ex);
            throw new RuntimeException("");
        }
    }

    private Integer formatOTP(byte[] hmac) {
        Integer offset = hmac[19] & 0xf;
        Integer binaryCode = (hmac[offset + 1] & 0xff) << 16 | (hmac[offset + 2] & 0xff) << 8 | (hmac[offset + 3] & 0xff);
        Integer codeDigits = binaryCode % 100000;
        Integer csum = checksum(codeDigits);
        return codeDigits * 10 + csum;
    }

    private int checksum(int codes) {
        int d2 = (codes / 100000) % 10;
        int d3 = (codes / 10000) % 10;
        int d4 = (codes / 1000) % 10;
        int d5 = (codes / 100) % 10;
        int d6 = (codes / 10) % 10;
        int d7 = codes % 10;
        return (10 - ((d2 + dd[d3] + d4 + dd[d5] + d6 + dd[d7]) % 10)) % 10;
    }

}

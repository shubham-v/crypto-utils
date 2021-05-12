package random;

import org.apache.commons.lang3.RandomStringUtils;

public class MPINUtil {
    private static final int MPIN_LENGTH = 4;

    private String generateMpin() {
        String characters = "0123456789";
        return RandomStringUtils.random(MPIN_LENGTH, characters);
    }
}

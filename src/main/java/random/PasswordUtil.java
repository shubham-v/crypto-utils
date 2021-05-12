package random;

import org.apache.commons.lang3.RandomStringUtils;

import java.util.Random;

public class PasswordUtil {

    private Random rand = new Random();

    private String generatePassword() {
        String characters = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789=[]@#$%^&*(){}?";
        int max = 15;
        int min = 8;
        int count = rand.nextInt(max - min) + min;
        return RandomStringUtils.random(count, characters);
    }

}

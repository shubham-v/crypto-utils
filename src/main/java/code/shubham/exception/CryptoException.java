package code.shubham.exception;

public class CryptoException extends RuntimeException {

    public CryptoException(String message, Throwable throwable) {
        super(message, throwable);
    }

}

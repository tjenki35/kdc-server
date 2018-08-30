package Cipher;

/**
 * Exception class for the Cipher Package
 */
public class CipherError extends Exception {

    CipherError(String msg, Exception ex) {
        super(msg,ex);
    }

    CipherError(String msg) {
        super(msg);
    }
    
}

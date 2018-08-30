package Cipher;

import java.math.BigInteger;
import java.security.SecureRandom;

//Class for diffie hellman related functions (currently implemented as a static type class for simplicity)
public class CipherDiffie {
    
    private CipherDiffie() {

    }

    //generates a securely random secret
    public static BigInteger generateSecret() {
        SecureRandom random = new SecureRandom();
        BigInteger secret = BigInteger.valueOf(random.nextLong());
        return secret.pow(2);
    }

    //modular exponentiation operation (BigInteger implementation)
    private static BigInteger modular_expo(BigInteger x, BigInteger y, BigInteger N) {
        if (y.compareTo(BigInteger.ZERO) == 0) {
            return BigInteger.ONE;
        } else {
            BigInteger z = modular_expo(x, y.divide(BigInteger.valueOf(2)), N);
            BigInteger precompute = z.mod(N).pow(2).mod(N);
            return (y.mod(BigInteger.valueOf(2)).compareTo(BigInteger.ZERO) == 0) ? precompute : precompute.multiply(x.mod(N)).mod(N);
        }
    }

    //prepares T_A or T_B depending on your perspective (the number each side sends in the clear)
    public static BigInteger prepareMessage(BigInteger g, BigInteger p, BigInteger secret) {
        return modular_expo(g, secret, p);
    }

    //combines T_B and secret to create g_SASB
    public static BigInteger combineSecrets(BigInteger T, BigInteger p, BigInteger secret) {
        return modular_expo(T, secret, p);
    }

}

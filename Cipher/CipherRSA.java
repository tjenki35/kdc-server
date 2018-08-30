package Cipher;

import java.math.BigInteger;
import java.security.SecureRandom;

//Class for RSA related functions (currently implemented as a static type class for simplicity)
public class CipherRSA {

    private CipherRSA() {

    }
    
    //public interface for encryption
    public static BigInteger encrypt(BigInteger input, BigInteger key, BigInteger modulus) {
        return modular_expo(input, key, modulus);

    }

    //private interface for decryption
    public static BigInteger decrypt(BigInteger cipher, BigInteger key, BigInteger modulus) {
        return modular_expo(cipher, key, modulus);
    }

    //perhaps the most interesting portion of this class, generates the public and private keys for a principle
    public static Truple<BigInteger> generate_keys() {

        SecureRandom random = new SecureRandom();
        BigInteger p = BigInteger.probablePrime(1024, random);
        BigInteger q = BigInteger.probablePrime(1024, random);

        BigInteger N = p.multiply(q);

        BigInteger one = BigInteger.ONE;
        BigInteger zero = BigInteger.ZERO;
        BigInteger two = BigInteger.valueOf(2);

        BigInteger totient = ((p.subtract(one)).multiply((q.subtract(one))));
        BigInteger e = one;
        BigInteger i = two;
        while (i.compareTo(N) < 0) {
            if (((i.mod(two)).compareTo(zero) != 0)) {
                if (gcd(i, totient).compareTo(one) == 0) {
                    e = i;
                    break;
                }
            }
            i = i.add(one);
        }
        BigInteger d = extended_e(e, totient).first;
        if (d.compareTo(BigInteger.ZERO) < 0) { // need to deal with negative d's
            d = d.mod(totient);
        }
        return new Truple(d, e, N);

    }
    
    //enxtended e algorithm for key generation (BigInteger implementation)
    private static Truple<BigInteger> extended_e(BigInteger a, BigInteger b) {

        //last frame
        BigInteger s = BigInteger.valueOf(0);
        BigInteger t = BigInteger.valueOf(1);
        BigInteger r = b;

        //previous values
        BigInteger t_i = BigInteger.valueOf(0);
        BigInteger s_i = BigInteger.valueOf(1);
        BigInteger r_i = a;

        while (r.compareTo(BigInteger.ZERO) != 0) {
            BigInteger q = r_i.divide(r);

            BigInteger temp = r;
            r = r_i.subtract(q.multiply(temp));
            r_i = temp;

            temp = s;
            s = s_i.subtract(q.multiply(temp));
            s_i = temp;

            temp = t;
            t = t_i.subtract(q.multiply(temp));
            t_i = temp;

        }

        return new Truple(s_i, t_i, r_i);
    }

    //modular exponentation algorithm for this class
    private static BigInteger modular_expo(BigInteger x, BigInteger y, BigInteger N) {
        if (y.compareTo(BigInteger.ZERO) == 0) {
            return BigInteger.ONE;
        } else {
            BigInteger z = modular_expo(x, y.divide(BigInteger.valueOf(2)), N);
            BigInteger precompute = z.mod(N).pow(2).mod(N);
            return (y.mod(BigInteger.valueOf(2)).compareTo(BigInteger.ZERO) == 0) ? precompute : precompute.multiply(x.mod(N)).mod(N);
        }
    }

    //gcd algorithm for this class
    private static BigInteger gcd(BigInteger a, BigInteger b) {
        if (b.equals(BigInteger.ZERO)) {
            return a;
        } else {
            return gcd(b, a.mod(b));
        }
    }
}

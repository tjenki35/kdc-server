package Cipher;

import java.math.BigInteger;
import java.security.InvalidKeyException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.Stack;
import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.KeyGenerator;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

public final class Cipher3DES {

    //Static identifiers
    public static final int ENCRYPT_MODE = Cipher.ENCRYPT_MODE;
    public static final int DECRYPT_MODE = Cipher.DECRYPT_MODE;
    public static final int CBC = 2;
    public static final int ECB = 1;

    //Object oriented portion of the class (promotes less resource use and code bloat)
    private Truple<SecretKey> keys;
    private Truple<Cipher> ciphers;
    private byte[] output_buffer;
    private byte[] input_buffer;
    private int en_mode = ENCRYPT_MODE;
    private int mode = ECB;

    //public constructor, validates information and then generates resources for cipher_operationss
    public Cipher3DES(Truple<SecretKey> ks, int en_mode, int mode) throws CipherError {
        validate(mode, en_mode);
        keys = ks;
        generate_ciphers(en_mode);

    }

    //reinitializes the cipher object by generating new cipher objects in the specified modes (probably could swap them around)
    public void reinit(int en_mode, int mode) throws CipherError {
        if (keys != null) {
            validate(mode, en_mode);
            generate_ciphers(en_mode);
            output_buffer = null;
        } else {
            throw new CipherError("No key given to Cipher");
        }
    }
    
    //set the given keys for the Cipher
    public void setKeys(Truple<SecretKey> ks) throws CipherError {
        keys = ks;
        generate_ciphers(en_mode);
    }

    //public encryption interface for input, (accepts variable size inputs)
    public byte[] encrypt(byte[] input) throws CipherError {

        input_buffer = input;
        //initialize components and stats used for the cypto process
        int quotient = input.length / KEY_SIZE;
        int remainder = input.length % KEY_SIZE;
        int padding = BLOCK_SIZE - remainder;
        
        if(padding < 0){
            throw new CipherError("Parsed Padding is Negative!: "+padding);
        }

        //all blocks = quotient + 1, plus 2 for padding and IV
        output_buffer = new byte[(quotient + 3) * BLOCK_SIZE];

        byte[] buffer = generate_padding_block(padding);
        byte[] last_block = new byte[BLOCK_SIZE];
        byte[] IV = generate_random_block();
        int k = BLOCK_SIZE;

        //encryption starts here.....
        copy_to_output(IV, 0);

        if (mode == CBC) {
            buffer = chain_blocks(IV, buffer);
        }
        buffer = cipher_operation(buffer, ciphers);

        copy_block(last_block, buffer);
        copy_to_output(buffer, k);

        //this is the bulk of the encryption process (similar to the decryption process)
        for (int j = 0; j < quotient; j++) {
            copy_from_input(buffer, k - BLOCK_SIZE, BLOCK_SIZE);
            if (mode == CBC) { // non implemented CBC patch code
                buffer = chain_blocks(last_block, buffer);
            }
            buffer = cipher_operation(buffer, ciphers);
            if (mode == CBC) {
                copy_block(last_block, buffer);
            }
            k += BLOCK_SIZE;
            copy_to_output(buffer, k);
        }

        //encrypt and copy out the last block
        copy_from_input(buffer, k - BLOCK_SIZE, remainder);
        buffer = Cipher3DES.pad_block(buffer, remainder);
        k += BLOCK_SIZE;
        if (mode == CBC) {
            buffer = chain_blocks(last_block, buffer);
        }
        buffer = cipher_operation(buffer, ciphers);
        copy_to_output(buffer, k);
        System.gc();
        return output_buffer;
        //encryption ends here
    }

    //public decrytion interface for input
    public byte[] decrypt(byte[] input) throws CipherError {

        input_buffer = input; //mount reference to input (needed for class methods)

        int quotient = input.length / BLOCK_SIZE; // quotient of the length (used later)

        byte[] buffer = new byte[BLOCK_SIZE]; // Buffer for operations
        byte[] last_block = new byte[BLOCK_SIZE]; // Buffer for CBC

        //get the initialization vector (*note that this is not an encrypted block)
        byte[] IV = new byte[BLOCK_SIZE]; //Initialization vector
        copy_from_input(IV, 0, BLOCK_SIZE);

        int pos = BLOCK_SIZE;

        //get the padding information from the ecryption process. 
        copy_from_input(buffer, pos, BLOCK_SIZE);
        if (mode == CBC) {
            copy_block(last_block, buffer);
        }

        buffer = cipher_operation(buffer, ciphers); // decrypt block
        if (mode == CBC) {
            buffer = chain_blocks(buffer, IV); // chain w/ the IV
        }

        //padding information is held in the first byte
        int padding = buffer[0];
        
        if(padding < 0){
            throw new CipherError("Parsed Padding is Negative! : "+padding);
        }

        //generate output buffer
        //all blocks = q + 1 - 2 for padding and IV
        output_buffer = new byte[(quotient - 1) * BLOCK_SIZE];

        pos += BLOCK_SIZE; //shift position on the input buffer

        //this is the bulk of the decryption process, the padding is stripped away later, so this just does a single cyrptopass  
        for (int j = 0; j < quotient - 2; j++) { //q-1 since we already consumed a single block
            copy_from_input(buffer, pos, BLOCK_SIZE);
            buffer = cipher_operation(buffer, ciphers); //do crypto function
            if (mode == CBC) { //does the reverse chain blocking if we are in CBC mode
                buffer = chain_blocks(last_block, buffer);
                copy_from_input(last_block, pos, BLOCK_SIZE);
            }
            copy_to_output(buffer, pos - BLOCK_SIZE * 2);  //copy results to the output buffer
            pos += BLOCK_SIZE; //next block
        }

        //padding is stripped out here 
        output_buffer = Arrays.copyOfRange(output_buffer, 0, output_buffer.length - (padding + BLOCK_SIZE));
        System.gc(); // attempt to remove sensitive data from memory. 
        return output_buffer; //return reference of the output buffer. 
    }

    //validation method
    private void validate(int mode, int en_mode) throws CipherError {
        if (mode == ECB || mode == CBC) {
            if (en_mode == ENCRYPT_MODE || en_mode == DECRYPT_MODE) {
                this.mode = mode;
                this.en_mode = en_mode;
            } else {
                throw new CipherError("Unsupported Mode (Encrypt/Decrypt?)");
            }
        } else {
            throw new CipherError("Mode not supported (ECB/CBC?)");
        }
    }
    
    //some helper methods to make the code more readible, copies a block to the output_buffer array
    private void copy_to_output(byte[] block, int start) throws CipherError {
        if (start >= 0) {
            if (output_buffer != null && block != null) {
                int k = 0;
                for (int i = start; i < start + block.length; i++) {
                    output_buffer[i] = block[k];
                    k++;
                }
            } else {
                throw new CipherError("Cannot copy to or from a null reference");
            }
        } else {
            throw new CipherError("Trying to copy using a negative indice");
        }
    }

    //copies to the input buffer given a block
    private void copy_from_input(byte[] block, int start, int how_many) throws CipherError {
        if (start >= 0 && how_many >= 0) {
            if (input_buffer != null && block != null) {
                int k = 0;
                for (int i = start; i < start + how_many; i++) {
                    block[k] = input_buffer[i];
                    k++;
                }
            } else {
                throw new CipherError("Cannot copy to or from a null reference");
            }
        } else {
            throw new CipherError("Trying to copy using a negative indice or count");
        }
    }

    //Static information on data boundaries
    public static int KEY_SIZE = 8;
    public static int BLOCK_SIZE = 8;

    //Does a generic symmetric cryptographic operation on the input using the given cipher trio
    //**note that this method does assume that the blocks given to this method are multiples of 64 bit sets of bytes
    private static byte[] cipher_operation(byte[] input, Truple<Cipher> ciphers) throws CipherError {
        try {
            input = ciphers.first.doFinal(input); // doFinal creates a new array so we need to update the reference
            input = ciphers.second.doFinal(input); // we toss the unaltered text
            input = ciphers.third.doFinal(input);
            return input;
        } catch (IllegalBlockSizeException ex) {
            throw new CipherError("Input for crypto function has an improperly sized block: " + input.length, ex);
        } catch (BadPaddingException ex) {
            throw new CipherError("Input for crypto funciton has malformed padding", ex);
        }
    }

    //Generates a set of Cipher Objects in a given encryption mode
    //mode - true == encrypt, false == decrypt
    private void generate_ciphers(int mode) throws CipherError {
        try {
            //uses the most basic form of DES, CBC and padding scheme is implemented elsewhere. 
            ciphers = new Truple<>(Cipher.getInstance("DES/ECB/NoPadding"), Cipher.getInstance("DES/ECB/NoPadding"), Cipher.getInstance("DES/ECB/NoPadding"));
            if (mode == ENCRYPT_MODE) {//encrypt
                ciphers.first.init(Cipher.ENCRYPT_MODE, keys.first);
                ciphers.second.init(Cipher.DECRYPT_MODE, keys.second);
                ciphers.third.init(Cipher.ENCRYPT_MODE, keys.third);
            }//decrypt
            else {
                ciphers.first.init(Cipher.DECRYPT_MODE, keys.third);
                ciphers.second.init(Cipher.ENCRYPT_MODE, keys.second);
                ciphers.third.init(Cipher.DECRYPT_MODE, keys.first);
            }
        } catch (NoSuchAlgorithmException ex) {
            throw new CipherError("DES is not supported in this version of Java", ex);
        } catch (NoSuchPaddingException ex) {
            throw new CipherError("NoPadding is not supported in this version of Java", ex);
        } catch (InvalidKeyException ex) {
            throw new CipherError("Invalid 3DES key given", ex);
        }
    }

    //generates a set of keys using the built in DES key generator
    public static Truple<SecretKey> generateKeys() throws CipherError {
        String type = "DES";
        try {
            KeyGenerator generator = KeyGenerator.getInstance(type);
            return new Truple<>(generator.generateKey(), generator.generateKey(), generator.generateKey());
        } catch (NoSuchAlgorithmException ex) {
            throw new CipherError("DES is not supported in this version of Java", ex);
        }
    }

    //generates a set of keys from a number that is known to both parties
    public static Truple<SecretKey> generateFromShared(BigInteger shared) throws CipherError {
        try {
            int num_keys = 3;
            MessageDigest md = MessageDigest.getInstance("SHA");
            Stack<SecretKey> secrets = new Stack();
            byte[] digest = shared.toByteArray();
            for (int i = 0; i < num_keys; i++) {
                digest = (md.digest(digest));
                byte[] key_ds = new byte[KEY_SIZE];
                System.arraycopy(digest, 0, key_ds, 0, key_ds.length);
                SecretKey key = new SecretKeySpec(key_ds, 0, key_ds.length, "DES");
                secrets.push(key);

            }
            return new Truple<>(secrets.pop(), secrets.pop(), secrets.pop());
        } catch (NoSuchAlgorithmException ex) {
            throw new CipherError("DES is not supported in this version of Java", ex);
        }
    }

    //generates a set of keys from a secure random object (supposedly "high quality")
    public static Truple<SecretKey> generatedFromSeed() {
        int num_keys = 3;
        Stack<SecretKey> secrets = new Stack();
        SecureRandom random = new SecureRandom();
        for (int i = 0; i < num_keys; i++) {
            byte[] key_ds = new byte[KEY_SIZE];
            byte[] rbytes = new byte[KEY_SIZE];
            random.nextBytes(rbytes);
            System.arraycopy(rbytes, 0, key_ds, 0, key_ds.length);
            SecretKey key = new SecretKeySpec(key_ds, 0, key_ds.length, "DES");
            secrets.push(key);
        }
        return new Truple<>(secrets.pop(), secrets.pop(), secrets.pop());
    }

    //Static Methods for block and padding operations
    //**Note that the padding scheme is defined here. 
    //generate a padding information block using random bytes
    private static byte[] generate_padding_block(int padc) {
        byte[] padding = generate_random_block();
        padding[0] = (byte) padc;
        return padding;
    }

    //takes two blocks and returns a new block that is the result of XOR each individual byte
    private static byte[] chain_blocks(byte[] prev, byte[] next) {
        if (prev.length != next.length || prev.length != BLOCK_SIZE) {
            return null;
        }
        byte[] block = new byte[BLOCK_SIZE];
        for (int i = 0; i < prev.length; i++) {
            block[i] = (byte) (prev[i] ^ next[i]);
        }
        return block;
    }

    //pad a block given a starting point, the padding consists of randomized bytes
    public static byte[] pad_block(byte[] block, int start) {
        //generate some padding to the tail of the input ( using randomized bytes )
        byte[] pads = generate_random_block();
        System.arraycopy(pads, start, block, start, block.length - start);
        return block;
    }

    //generate a securly random block (reseeded per use, BLOCKING)
    private static byte[] generate_random_block() {
        SecureRandom random = new SecureRandom();
        byte[] block = new byte[BLOCK_SIZE];
        random.nextBytes(block);
        return block;
    }

    //wrapper method to save on typing
    private static void copy_block(byte[] block, byte[] tocopy) {
        System.arraycopy(tocopy, 0, block, 0, BLOCK_SIZE);
    }

}

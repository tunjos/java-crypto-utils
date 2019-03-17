package co.tunjos.crypto.crypto;

import org.junit.jupiter.api.Test;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import java.nio.charset.StandardCharsets;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;

import static org.junit.jupiter.api.Assertions.assertEquals;

class CryptoUtilsTest {

    @Test
    void generateAES256Key() {
        final CryptoUtils cryptoUtils = CryptoUtils.getInstance();
        final SecretKey secretKey;
        try {
            secretKey = cryptoUtils.generateAES256Key();
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
            assert false;
            return;
        }

        assertEquals("AES", secretKey.getAlgorithm());
        assertEquals(32, secretKey.getEncoded().length);
    }

    @Test
    void generateAESKey256() {
        final CryptoUtils cryptoUtils = CryptoUtils.getInstance();
        final SecretKey secretKey;
        try {
            secretKey = cryptoUtils.generateAESKey(AesKeySizes.AES_256);
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
            assert false;
            return;
        }

        assertEquals("AES", secretKey.getAlgorithm());
        assertEquals(32, secretKey.getEncoded().length);
    }

    @Test
    void generateAESKey192() {
        final CryptoUtils cryptoUtils = CryptoUtils.getInstance();
        final SecretKey secretKey;
        try {
            secretKey = cryptoUtils.generateAESKey(AesKeySizes.AES_192);
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
            assert false;
            return;
        }

        assertEquals("AES", secretKey.getAlgorithm());
        assertEquals(24, secretKey.getEncoded().length);
    }

    @Test
    void generateAESKey128() {
        final CryptoUtils cryptoUtils = CryptoUtils.getInstance();
        final SecretKey secretKey;
        try {
            secretKey = cryptoUtils.generateAESKey(AesKeySizes.AES_128);
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
            assert false;
            return;
        }

        assertEquals("AES", secretKey.getAlgorithm());
        assertEquals(16, secretKey.getEncoded().length);
    }

    @Test
    void encryptAES256String() {
        final String test = "test";
        final CryptoUtils cryptoUtils = CryptoUtils.getInstance();
        final SecretKey secretKey;
        try {
            secretKey = cryptoUtils.generateAES256Key();
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
            assert false;
            return;
        }

        final byte[] initializationVector = new byte[16];
        new SecureRandom().nextBytes(initializationVector);


        final String encryptedString;
        try {
            encryptedString = cryptoUtils.encryptAES256String(test, initializationVector, secretKey);
        } catch (NoSuchAlgorithmException | BadPaddingException | IllegalBlockSizeException | NoSuchPaddingException |
                InvalidKeyException | InvalidAlgorithmParameterException e) {
            e.printStackTrace();
            assert false;
            return;
        }

        assertEquals(24, encryptedString.length());
    }

    @Test
    void encryptBytesAES256String() {
        final String test = "test";
        final CryptoUtils cryptoUtils = CryptoUtils.getInstance();
        final SecretKey secretKey;
        try {
            secretKey = cryptoUtils.generateAES256Key();
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
            assert false;
            return;
        }

        final byte[] initializationVector = new byte[16];
        new SecureRandom().nextBytes(initializationVector);


        final byte[] encryptedBytes;
        try {
            encryptedBytes = cryptoUtils.encryptBytesAES256String(test, initializationVector, secretKey);
        } catch (NoSuchAlgorithmException | BadPaddingException | IllegalBlockSizeException | NoSuchPaddingException |
                InvalidKeyException | InvalidAlgorithmParameterException e) {
            e.printStackTrace();
            assert false;
            return;
        }

        assertEquals(16, encryptedBytes.length);
    }

    @Test
    void encryptAES256Bytes() {
        final String test = "test";
        final CryptoUtils cryptoUtils = CryptoUtils.getInstance();
        final SecretKey secretKey;
        try {
            secretKey = cryptoUtils.generateAES256Key();
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
            assert false;
            return;
        }

        final byte[] initializationVector = new byte[16];
        new SecureRandom().nextBytes(initializationVector);

        final byte[] encryptedBytes;
        try {
            encryptedBytes = cryptoUtils.encryptAES256Bytes(test.getBytes(StandardCharsets.UTF_8), initializationVector, secretKey);
        } catch (NoSuchAlgorithmException | BadPaddingException | IllegalBlockSizeException | NoSuchPaddingException |
                InvalidKeyException | InvalidAlgorithmParameterException e) {
            e.printStackTrace();
            assert false;
            return;
        }

        assertEquals(16, encryptedBytes.length);
    }

    @Test
    void encryptDecryptAES256String() {
        final String test = "test";
        final CryptoUtils cryptoUtils = CryptoUtils.getInstance();
        final SecretKey secretKey;
        try {
            secretKey = cryptoUtils.generateAES256Key();
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
            assert false;
            return;
        }

        final byte[] initializationVector = new byte[16];
        new SecureRandom().nextBytes(initializationVector);

        final String encryptedString;
        try {
            encryptedString = cryptoUtils.encryptAES256String(test, initializationVector, secretKey);
        } catch (NoSuchAlgorithmException | BadPaddingException | IllegalBlockSizeException | NoSuchPaddingException |
                InvalidKeyException | InvalidAlgorithmParameterException e) {
            e.printStackTrace();
            assert false;
            return;
        }

        final String decryptedString;
        final byte[] decryptedBytes;
        try {
            decryptedString = cryptoUtils.decryptAES256String(encryptedString, initializationVector, secretKey);
            decryptedBytes = cryptoUtils.decryptAES256Bytes(encryptedString.getBytes(StandardCharsets.UTF_8), initializationVector, secretKey);
        } catch (NoSuchAlgorithmException | BadPaddingException | IllegalBlockSizeException | NoSuchPaddingException |
                InvalidKeyException | InvalidAlgorithmParameterException e) {
            e.printStackTrace();
            assert false;
            return;
        }

        assertEquals("test", decryptedString);
        assertEquals("test", new String(decryptedBytes, StandardCharsets.UTF_8));
    }
}
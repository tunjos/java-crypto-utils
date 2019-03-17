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
    void generateAES256Key() throws NoSuchAlgorithmException {
        final CryptoUtils cryptoUtils = CryptoUtils.getInstance();
        final SecretKey secretKey = cryptoUtils.generateAES256Key();

        assertEquals("AES", secretKey.getAlgorithm());
        assertEquals(32, secretKey.getEncoded().length);
    }

    @Test
    void generateAESKey256() throws NoSuchAlgorithmException {
        final CryptoUtils cryptoUtils = CryptoUtils.getInstance();
        final SecretKey secretKey = cryptoUtils.generateAESKey(AesKeySizes.AES_256);

        assertEquals("AES", secretKey.getAlgorithm());
        assertEquals(32, secretKey.getEncoded().length);
    }

    @Test
    void generateAESKey192() throws NoSuchAlgorithmException {
        final CryptoUtils cryptoUtils = CryptoUtils.getInstance();
        final SecretKey secretKey = cryptoUtils.generateAESKey(AesKeySizes.AES_192);

        assertEquals("AES", secretKey.getAlgorithm());
        assertEquals(24, secretKey.getEncoded().length);
    }

    @Test
    void generateAESKey128() throws NoSuchAlgorithmException {
        final CryptoUtils cryptoUtils = CryptoUtils.getInstance();
        final SecretKey secretKey = cryptoUtils.generateAESKey(AesKeySizes.AES_128);

        assertEquals("AES", secretKey.getAlgorithm());
        assertEquals(16, secretKey.getEncoded().length);
    }

    @Test
    void encryptAES256String() throws NoSuchAlgorithmException, IllegalBlockSizeException, InvalidKeyException,
            BadPaddingException, InvalidAlgorithmParameterException, NoSuchPaddingException {
        final String test = "test";
        final CryptoUtils cryptoUtils = CryptoUtils.getInstance();
        final SecretKey secretKey = cryptoUtils.generateAES256Key();

        final byte[] initializationVector = new byte[16];
        new SecureRandom().nextBytes(initializationVector);

        final String encryptedString = cryptoUtils.encryptAES256String(test, initializationVector, secretKey);

        assertEquals(24, encryptedString.length());
    }

    @Test
    void encryptBytesAES256String() throws NoSuchPaddingException, InvalidAlgorithmParameterException,
            NoSuchAlgorithmException, IllegalBlockSizeException, BadPaddingException, InvalidKeyException {
        final String test = "test";
        final CryptoUtils cryptoUtils = CryptoUtils.getInstance();
        final SecretKey secretKey = cryptoUtils.generateAES256Key();

        final byte[] initializationVector = new byte[16];
        new SecureRandom().nextBytes(initializationVector);

        final byte[] encryptedBytes = cryptoUtils.encryptBytesAES256String(test, initializationVector, secretKey);

        assertEquals(16, encryptedBytes.length);
    }

    @Test
    void encryptAES256Bytes() throws NoSuchPaddingException, InvalidAlgorithmParameterException,
            NoSuchAlgorithmException, IllegalBlockSizeException, BadPaddingException, InvalidKeyException {
        final String test = "test";
        final CryptoUtils cryptoUtils = CryptoUtils.getInstance();
        final SecretKey secretKey = cryptoUtils.generateAES256Key();

        final byte[] initializationVector = new byte[16];
        new SecureRandom().nextBytes(initializationVector);

        final byte[] encryptedBytes = cryptoUtils.encryptAES256Bytes(
                test.getBytes(StandardCharsets.UTF_8), initializationVector, secretKey);

        assertEquals(16, encryptedBytes.length);
    }

    @Test
    void encryptDecryptAES256String() throws NoSuchPaddingException, InvalidAlgorithmParameterException,
            NoSuchAlgorithmException, IllegalBlockSizeException, BadPaddingException, InvalidKeyException {
        final String test = "test";
        final CryptoUtils cryptoUtils = CryptoUtils.getInstance();
        final SecretKey secretKey = cryptoUtils.generateAES256Key();

        final byte[] initializationVector = new byte[16];
        new SecureRandom().nextBytes(initializationVector);

        final String encryptedString = cryptoUtils.encryptAES256String(test, initializationVector, secretKey);

        final String decryptedString = cryptoUtils.decryptAES256String(encryptedString, initializationVector, secretKey);
        final byte[] decryptedBytes = cryptoUtils.decryptAES256Bytes(encryptedString.getBytes(StandardCharsets.UTF_8),
                initializationVector, secretKey);

        assertEquals("test", decryptedString);
        assertEquals("test", new String(decryptedBytes, StandardCharsets.UTF_8));
    }
}
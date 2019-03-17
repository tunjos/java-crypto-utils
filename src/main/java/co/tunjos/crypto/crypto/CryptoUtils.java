package co.tunjos.crypto.crypto;

import org.jetbrains.annotations.NotNull;

import javax.crypto.*;
import javax.crypto.spec.IvParameterSpec;
import java.nio.charset.StandardCharsets;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.Base64;

/**
 * Java Cryptographic Utilities.
 *
 * @author tunjos
 * @version 1.0
 */
public class CryptoUtils {
    private static final String ALGORITHM_AES = "AES";
    private static final String _AES_CBC_PKCS5PADDING = "AES/CBC/PKCS5PADDING";
    private static final int AES_256 = 256;

    private static CryptoUtils ourInstance = new CryptoUtils();

    public static CryptoUtils getInstance() {
        return ourInstance;
    }

    private CryptoUtils() {
    }

    public SecretKey generateAES256Key() throws NoSuchAlgorithmException {
        final KeyGenerator keyGenerator = KeyGenerator.getInstance(ALGORITHM_AES);
        keyGenerator.init(AES_256);
        return keyGenerator.generateKey();
    }

    public SecretKey generateAESKey(@NotNull final AesKeySizes aesKeySizes) throws NoSuchAlgorithmException {
        final KeyGenerator keyGenerator = KeyGenerator.getInstance(ALGORITHM_AES);
        keyGenerator.init(aesKeySizes.getKeySize());
        return keyGenerator.generateKey();
    }

    public String encryptAES256String(@NotNull final String input, @NotNull byte[] initializationVector,
                                      @NotNull final SecretKey secretKey) throws NoSuchAlgorithmException,
            NoSuchPaddingException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException,
            InvalidAlgorithmParameterException {
        IvParameterSpec ivParameterSpec = new IvParameterSpec(initializationVector);

        Cipher cipher = Cipher.getInstance(_AES_CBC_PKCS5PADDING);
        cipher.init(Cipher.ENCRYPT_MODE, secretKey, ivParameterSpec);

        final byte[] encryptedBytes = cipher.doFinal(input.getBytes(StandardCharsets.UTF_8));
        return Base64.getEncoder().encodeToString(encryptedBytes);
    }

    public byte[] encryptBytesAES256String(@NotNull final String input, @NotNull byte[] initializationVector,
                                           @NotNull final SecretKey secretKey) throws NoSuchAlgorithmException,
            NoSuchPaddingException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException,
            InvalidAlgorithmParameterException {
        IvParameterSpec ivParameterSpec = new IvParameterSpec(initializationVector);

        Cipher cipher = Cipher.getInstance(_AES_CBC_PKCS5PADDING);
        cipher.init(Cipher.ENCRYPT_MODE, secretKey, ivParameterSpec);

        return cipher.doFinal(input.getBytes(StandardCharsets.UTF_8));
    }

    public byte[] encryptAES256Bytes(@NotNull final byte[] bytes, @NotNull byte[] initializationVector,
                                     @NotNull final SecretKey secretKey) throws NoSuchAlgorithmException,
            NoSuchPaddingException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException,
            InvalidAlgorithmParameterException {
        IvParameterSpec ivParameterSpec = new IvParameterSpec(initializationVector);

        Cipher cipher = Cipher.getInstance(_AES_CBC_PKCS5PADDING);
        cipher.init(Cipher.ENCRYPT_MODE, secretKey, ivParameterSpec);

        return cipher.doFinal(bytes);
    }

    public String decryptAES256String(@NotNull final String input, @NotNull byte[] initializationVector,
                                      @NotNull final SecretKey secretKey) throws NoSuchAlgorithmException,
            NoSuchPaddingException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException,
            InvalidAlgorithmParameterException {
        byte[] decodedBytes = Base64.getDecoder().decode(input.getBytes(StandardCharsets.UTF_8));
        IvParameterSpec ivParameterSpec = new IvParameterSpec(initializationVector);

        Cipher cipher = Cipher.getInstance(_AES_CBC_PKCS5PADDING);
        cipher.init(Cipher.DECRYPT_MODE, secretKey, ivParameterSpec);

        final byte[] decryptedBytes = cipher.doFinal(decodedBytes);
        return new String(decryptedBytes, StandardCharsets.UTF_8);
    }

    public byte[] decryptAES256Bytes(@NotNull final byte[] bytes, @NotNull byte[] initializationVector,
                                     @NotNull final SecretKey secretKey) throws NoSuchAlgorithmException,
            NoSuchPaddingException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException,
            InvalidAlgorithmParameterException {
        byte[] decodedBytes = Base64.getDecoder().decode(bytes);
        IvParameterSpec ivParameterSpec = new IvParameterSpec(initializationVector);

        Cipher cipher = Cipher.getInstance(_AES_CBC_PKCS5PADDING);
        cipher.init(Cipher.DECRYPT_MODE, secretKey, ivParameterSpec);

        return cipher.doFinal(decodedBytes);
    }
}


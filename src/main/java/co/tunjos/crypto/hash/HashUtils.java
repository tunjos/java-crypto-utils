package co.tunjos.crypto.hash;

import org.jetbrains.annotations.NotNull;

import javax.xml.bind.DatatypeConverter;
import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.DigestInputStream;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

/**
 * Java Hash Utilities.
 *
 * @author tunjos
 * @version 1.0
 */
public class HashUtils {
    private static final String ALGORITHM_MD5 = "MD5";
    private static final String ALGORITHM_SHA1 = "SHA-1";
    private static final String ALGORITHM_SHA256 = "SHA-256";
    private static final String ALGORITHM_SHA512 = "SHA-512";

    private static final int HASH_MD5_FILE_BUFFER_SIZE = 4096;

    private static HashUtils ourInstance = new HashUtils();

    public static HashUtils getInstance() {
        return ourInstance;
    }

    private HashUtils() {
    }

    /**
     * Apply the MD5 Hashing algorithm on an input String.
     * Digest Size: 128 bit
     *
     * @param input The input String to apply the MD5 Hashing algorithm on.
     * @return The hashed MD5 String.
     * @throws NoSuchAlgorithmException if the algorithm cannot be found.
     */
    @Deprecated
    @NotNull
    public String md5DigestString(@NotNull final String input) throws NoSuchAlgorithmException {
        final MessageDigest messageDigest = MessageDigest.getInstance(ALGORITHM_MD5);
        System.out.println(messageDigest.getProvider());
        final byte[] digestBytes = messageDigest.digest(input.getBytes(StandardCharsets.UTF_8));
        return DatatypeConverter.printHexBinary(digestBytes).toLowerCase();
    }

    /**
     * Apply the MD5 Hashing algorithm on an input file.
     * Digest Size: 128 bit
     *
     * @param filePath The path to the file to apply the MD5 Hashing algorithm on.
     * @return The hashed MD5 result.
     * @throws NoSuchAlgorithmException if the algorithm cannot be found.
     * @throws IOException              if an I/O error occurs.
     */
    @Deprecated
    @NotNull
    public String md5DigestFile(@NotNull final String filePath) throws NoSuchAlgorithmException, IOException {
        final MessageDigest messageDigest = MessageDigest.getInstance(ALGORITHM_MD5);

        try (InputStream is = Files.newInputStream(Paths.get(filePath))) {
            DigestInputStream digestInputStream = new DigestInputStream(is, messageDigest);
            byte[] buffer = new byte[HASH_MD5_FILE_BUFFER_SIZE];
            //noinspection StatementWithEmptyBody
            while (digestInputStream.read(buffer) > 0) {
            }
        }

        byte[] digestBytes = messageDigest.digest();
        return DatatypeConverter.printHexBinary(digestBytes).toLowerCase();
    }

    /**
     * Apply the SHA-1 Hashing algorithm on an input String.
     * Digest Size: 160 bit
     *
     * @param input The input String to apply the SHA-1 Hashing algorithm on.
     * @return The hashed SHA-1 String.
     * @throws NoSuchAlgorithmException if the algorithm cannot be found.
     */
    @NotNull
    public String sha1DigestString(@NotNull final String input) throws NoSuchAlgorithmException {
        final MessageDigest messageDigest = MessageDigest.getInstance(ALGORITHM_SHA1);
        final byte[] digestBytes = messageDigest.digest(input.getBytes(StandardCharsets.UTF_8));
        return DatatypeConverter.printHexBinary(digestBytes).toLowerCase();
    }

    /**
     * Apply the SHA-1 Hashing algorithm on an input file.
     * Digest Size: 160 bit
     *
     * @param filePath The path to the file to apply the SHA-1 Hashing algorithm on.
     * @return The hashed SHA-1 result.
     * @throws NoSuchAlgorithmException if the algorithm cannot be found.
     * @throws IOException              if an I/O error occurs.
     */
    @NotNull
    public String sha1DigestFile(@NotNull final String filePath) throws NoSuchAlgorithmException, IOException {
        final MessageDigest messageDigest = MessageDigest.getInstance(ALGORITHM_SHA1);

        try (InputStream is = Files.newInputStream(Paths.get(filePath))) {
            DigestInputStream digestInputStream = new DigestInputStream(is, messageDigest);
            byte[] buffer = new byte[HASH_MD5_FILE_BUFFER_SIZE];
            //noinspection StatementWithEmptyBody
            while (digestInputStream.read(buffer) > 0) {
            }
        }

        byte[] digestBytes = messageDigest.digest();
        return DatatypeConverter.printHexBinary(digestBytes).toLowerCase();
    }

    /**
     * Apply the SHA-256 Hashing algorithm on an input String.
     * Digest Size: 256 bit
     *
     * @param input The input String to apply the SHA-256 Hashing algorithm on.
     * @return The hashed SHA-256 String.
     * @throws NoSuchAlgorithmException if the algorithm cannot be found.
     */
    @NotNull
    public String sha256DigestString(@NotNull final String input) throws NoSuchAlgorithmException {
        final MessageDigest messageDigest = MessageDigest.getInstance(ALGORITHM_SHA256);
        final byte[] digestBytes = messageDigest.digest(input.getBytes(StandardCharsets.UTF_8));
        return DatatypeConverter.printHexBinary(digestBytes).toLowerCase();
    }

    /**
     * Apply the SHA-256 Hashing algorithm on an input file.
     * Digest Size: 256 bit
     *
     * @param filePath filePath The path to the file to apply the SHA-256 Hashing algorithm on.
     * @return The hashed SHA-256 result.
     * @throws NoSuchAlgorithmException if the algorithm cannot be found.
     * @throws IOException              if an I/O error occurs.
     */
    @NotNull
    public String sha256DigestFile(@NotNull final String filePath) throws NoSuchAlgorithmException, IOException {
        final MessageDigest messageDigest = MessageDigest.getInstance(ALGORITHM_SHA256);

        try (InputStream is = Files.newInputStream(Paths.get(filePath))) {
            DigestInputStream digestInputStream = new DigestInputStream(is, messageDigest);
            byte[] buffer = new byte[HASH_MD5_FILE_BUFFER_SIZE];
            //noinspection StatementWithEmptyBody
            while (digestInputStream.read(buffer) > 0) {
            }
        }

        byte[] digestBytes = messageDigest.digest();
        return DatatypeConverter.printHexBinary(digestBytes).toLowerCase();
    }

    /**
     * Apply the SHA-512 Hashing algorithm on an input String.
     * Digest Size: 512 bit
     *
     * @param input The input String to apply the SHA-512 Hashing algorithm on.
     * @return The hashed SHA-512 String.
     * @throws NoSuchAlgorithmException if the algorithm cannot be found.
     */
    @NotNull
    public String sha512DigestString(@NotNull final String input) throws NoSuchAlgorithmException {
        final MessageDigest messageDigest = MessageDigest.getInstance(ALGORITHM_SHA512);
        final byte[] digestBytes = messageDigest.digest(input.getBytes(StandardCharsets.UTF_8));
        return DatatypeConverter.printHexBinary(digestBytes).toLowerCase();
    }

    /**
     * Apply the SHA-512 Hashing algorithm on an input file.
     * Digest Size: 512 bit
     *
     * @param filePath filePath filePath The path to the file to apply the SHA-512 Hashing algorithm on.
     * @return The hashed SHA-512 result.
     * @throws NoSuchAlgorithmException if the algorithm cannot be found.
     * @throws IOException              if an I/O error occurs.
     */
    @NotNull
    public String sha512DigestFile(@NotNull final String filePath) throws NoSuchAlgorithmException, IOException {
        final MessageDigest messageDigest = MessageDigest.getInstance(ALGORITHM_SHA512);

        try (InputStream is = Files.newInputStream(Paths.get(filePath))) {
            DigestInputStream digestInputStream = new DigestInputStream(is, messageDigest);
            byte[] buffer = new byte[HASH_MD5_FILE_BUFFER_SIZE];
            //noinspection StatementWithEmptyBody
            while (digestInputStream.read(buffer) > 0) {
            }
        }

        byte[] digestBytes = messageDigest.digest();
        return DatatypeConverter.printHexBinary(digestBytes).toLowerCase();
    }

    /**
     * Apply a SHA- Hashing algorithm on an input String.
     * Digest Size: Depends on the chosen algorithm
     *
     * @param input     The input String to apply the SHA-512 Hashing algorithm on.
     * @param algorithm The Hash algorithm to use, chosen from {@link HashAlgorithms}
     * @return The hashed SHA-512 String.
     * @throws NoSuchAlgorithmException if the algorithm cannot be found.
     */
    @NotNull
    public String shaDigestString(@NotNull final String input, @NotNull final HashAlgorithms algorithm)
            throws NoSuchAlgorithmException {
        final MessageDigest messageDigest = MessageDigest.getInstance(algorithm.toString());
        final byte[] digestBytes = messageDigest.digest(input.getBytes(StandardCharsets.UTF_8));
        return DatatypeConverter.printHexBinary(digestBytes).toLowerCase();
    }


    /**
     * Apply a SHA- Hashing algorithm on an input file.
     * Digest Size: Depends on the chosen algorithm
     *
     * @param filePath  The input String to apply the SHA-512 Hashing algorithm on.
     * @param algorithm The Hash algorithm to use, chosen from {@link HashAlgorithms}.
     * @return The hashed SHA-512 result.
     * @throws NoSuchAlgorithmException if the algorithm cannot be found.
     * @throws IOException              if an I/O error occurs.
     */
    @NotNull
    public String shaDigestFile(@NotNull final String filePath, @NotNull final HashAlgorithms algorithm)
            throws NoSuchAlgorithmException, IOException {
        final MessageDigest messageDigest = MessageDigest.getInstance(algorithm.toString());

        try (InputStream is = Files.newInputStream(Paths.get(filePath))) {
            DigestInputStream digestInputStream = new DigestInputStream(is, messageDigest);
            byte[] buffer = new byte[HASH_MD5_FILE_BUFFER_SIZE];
            //noinspection StatementWithEmptyBody
            while (digestInputStream.read(buffer) > 0) {
            }
        }

        byte[] digestBytes = messageDigest.digest();
        return DatatypeConverter.printHexBinary(digestBytes).toLowerCase();
    }
}

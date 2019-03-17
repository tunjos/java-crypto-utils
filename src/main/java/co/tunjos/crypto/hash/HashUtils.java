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

    @NotNull
    public String md5DigestString(@NotNull String string) throws NoSuchAlgorithmException {
        final MessageDigest messageDigest = MessageDigest.getInstance(ALGORITHM_MD5);
        final byte[] digestBytes = messageDigest.digest(string.getBytes(StandardCharsets.UTF_8));
        return DatatypeConverter.printHexBinary(digestBytes).toLowerCase();
    }

    @NotNull
    public String md5DigestFile(@NotNull String filePath) throws NoSuchAlgorithmException, IOException {
        final MessageDigest messageDigest = MessageDigest.getInstance(ALGORITHM_MD5);

        try (InputStream is = Files.newInputStream(Paths.get(filePath));
             DigestInputStream digestInputStream = new DigestInputStream(is, messageDigest)) {
            byte[] buffer = new byte[HASH_MD5_FILE_BUFFER_SIZE];
            //noinspection StatementWithEmptyBody
            while (digestInputStream.read(buffer) > 0) {
            }
        } catch (IOException e) {
            throw e;
        }

        byte[] digestBytes = messageDigest.digest();
        return DatatypeConverter.printHexBinary(digestBytes).toLowerCase();
    }

    @NotNull
    public String sha1DigestString(@NotNull String string) throws NoSuchAlgorithmException {
        final MessageDigest messageDigest = MessageDigest.getInstance(ALGORITHM_SHA1);
        final byte[] digestBytes = messageDigest.digest(string.getBytes(StandardCharsets.UTF_8));
        return DatatypeConverter.printHexBinary(digestBytes).toLowerCase();
    }

    @NotNull
    public String sha1DigestFile(@NotNull String filePath) throws NoSuchAlgorithmException, IOException {
        final MessageDigest messageDigest = MessageDigest.getInstance(ALGORITHM_SHA1);

        try (InputStream is = Files.newInputStream(Paths.get(filePath));
             DigestInputStream digestInputStream = new DigestInputStream(is, messageDigest)) {
            byte[] buffer = new byte[HASH_MD5_FILE_BUFFER_SIZE];
            //noinspection StatementWithEmptyBody
            while (digestInputStream.read(buffer) > 0) {
            }
        } catch (IOException e) {
            throw e;
        }

        byte[] digestBytes = messageDigest.digest();
        return DatatypeConverter.printHexBinary(digestBytes).toLowerCase();
    }

    @NotNull
    public String sha256DigestString(@NotNull String string) throws NoSuchAlgorithmException {
        final MessageDigest messageDigest = MessageDigest.getInstance(ALGORITHM_SHA256);
        final byte[] digestBytes = messageDigest.digest(string.getBytes(StandardCharsets.UTF_8));
        return DatatypeConverter.printHexBinary(digestBytes).toLowerCase();
    }

    @NotNull
    public String sha256DigestFile(@NotNull String filePath) throws NoSuchAlgorithmException, IOException {
        final MessageDigest messageDigest = MessageDigest.getInstance(ALGORITHM_SHA256);

        try (InputStream is = Files.newInputStream(Paths.get(filePath));
             DigestInputStream digestInputStream = new DigestInputStream(is, messageDigest)) {
            byte[] buffer = new byte[HASH_MD5_FILE_BUFFER_SIZE];
            //noinspection StatementWithEmptyBody
            while (digestInputStream.read(buffer) > 0) {
            }
        } catch (IOException e) {
            throw e;
        }

        byte[] digestBytes = messageDigest.digest();
        return DatatypeConverter.printHexBinary(digestBytes).toLowerCase();
    }

    @NotNull
    public String sha512DigestString(@NotNull String string) throws NoSuchAlgorithmException {
        final MessageDigest messageDigest = MessageDigest.getInstance(ALGORITHM_SHA512);
        final byte[] digestBytes = messageDigest.digest(string.getBytes(StandardCharsets.UTF_8));
        return DatatypeConverter.printHexBinary(digestBytes).toLowerCase();
    }

    @NotNull
    public String sha512DigestFile(@NotNull String filePath) throws NoSuchAlgorithmException, IOException {
        final MessageDigest messageDigest = MessageDigest.getInstance(ALGORITHM_SHA512);

        try (InputStream is = Files.newInputStream(Paths.get(filePath));
             DigestInputStream digestInputStream = new DigestInputStream(is, messageDigest)) {
            byte[] buffer = new byte[HASH_MD5_FILE_BUFFER_SIZE];
            //noinspection StatementWithEmptyBody
            while (digestInputStream.read(buffer) > 0) {
            }
        } catch (IOException e) {
            throw e;
        }

        byte[] digestBytes = messageDigest.digest();
        return DatatypeConverter.printHexBinary(digestBytes).toLowerCase();
    }

    @NotNull
    public String shaDigestString(@NotNull String string, @NotNull HashAlgorithms algorithm) throws NoSuchAlgorithmException {
        final MessageDigest messageDigest = MessageDigest.getInstance(algorithm.toString());
        final byte[] digestBytes = messageDigest.digest(string.getBytes(StandardCharsets.UTF_8));
        return DatatypeConverter.printHexBinary(digestBytes).toLowerCase();
    }

    @NotNull
    public String shaDigestFile(@NotNull String filePath, @NotNull HashAlgorithms algorithm) throws NoSuchAlgorithmException, IOException {
        final MessageDigest messageDigest = MessageDigest.getInstance(algorithm.toString());

        try (InputStream is = Files.newInputStream(Paths.get(filePath));
             DigestInputStream digestInputStream = new DigestInputStream(is, messageDigest)) {
            byte[] buffer = new byte[HASH_MD5_FILE_BUFFER_SIZE];
            //noinspection StatementWithEmptyBody
            while (digestInputStream.read(buffer) > 0) {
            }
        } catch (IOException e) {
            throw e;
        }

        byte[] digestBytes = messageDigest.digest();
        return DatatypeConverter.printHexBinary(digestBytes).toLowerCase();
    }
}

package co.tunjos.crypto.hash;

import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.security.NoSuchAlgorithmException;

import static org.junit.jupiter.api.Assertions.assertEquals;

class HashUtilsTest {

    @Test
    void md5DigestString() {
        final String test = "test";
        HashUtils hashUtils = HashUtils.getInstance();

        final String hash;
        try {
            hash = hashUtils.md5DigestString(test);
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
            assert false;
            return;
        }
        assertEquals("098f6bcd4621d373cade4e832627b4f6", hash);
    }

    @Test
    void md5DigestFile() {
        final String test = "src/test/resources/test.txt";
        HashUtils hashUtils = HashUtils.getInstance();

        final String hash;

        try {
            hash = hashUtils.md5DigestFile(test);
        } catch (NoSuchAlgorithmException | IOException e) {
            e.printStackTrace();
            assert false;
            return;
        }
        assertEquals("d8e8fca2dc0f896fd7cb4cb0031ba249", hash);
    }
}
package co.tunjos.crypto.hash;

import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.security.NoSuchAlgorithmException;

import static org.junit.jupiter.api.Assertions.assertEquals;

class HashUtilsTest {

    @Test
    void md5DigestString() throws NoSuchAlgorithmException {
        final String test = "test";
        HashUtils hashUtils = HashUtils.getInstance();

        final String hash = hashUtils.md5DigestString(test);

        assertEquals("098f6bcd4621d373cade4e832627b4f6", hash);
    }

    @Test
    void md5DigestFile() throws IOException, NoSuchAlgorithmException {
        final String filepath = "src/test/resources/test.txt";
        HashUtils hashUtils = HashUtils.getInstance();

        final String hash = hashUtils.md5DigestFile(filepath);

        assertEquals("d8e8fca2dc0f896fd7cb4cb0031ba249", hash);
    }

    @Test
    void sha1DigestString() throws NoSuchAlgorithmException {
        final String test = "test";
        HashUtils hashUtils = HashUtils.getInstance();

        final String hash = hashUtils.sha1DigestString(test);

        assertEquals("a94a8fe5ccb19ba61c4c0873d391e987982fbbd3", hash);
    }

    @Test
    void sha1DigestFile() throws IOException, NoSuchAlgorithmException {
        final String filepath = "src/test/resources/test.txt";
        HashUtils hashUtils = HashUtils.getInstance();

        final String hash = hashUtils.sha1DigestFile(filepath);

        assertEquals("4e1243bd22c66e76c2ba9eddc1f91394e57f9f83", hash);
    }

    @Test
    void sha256DigestString() throws NoSuchAlgorithmException {
        final String test = "test";
        HashUtils hashUtils = HashUtils.getInstance();

        final String hash = hashUtils.sha256DigestString(test);

        assertEquals("9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08", hash);
    }

    @Test
    void sha256DigestFile() throws IOException, NoSuchAlgorithmException {
        final String filepath = "src/test/resources/test.txt";
        HashUtils hashUtils = HashUtils.getInstance();

        final String hash = hashUtils.sha256DigestFile(filepath);

        assertEquals("f2ca1bb6c7e907d06dafe4687e579fce76b37e4e93b7605022da52e6ccc26fd2", hash);
    }

    @Test
    void sha512DigestString() throws NoSuchAlgorithmException {
        final String test = "test";
        HashUtils hashUtils = HashUtils.getInstance();

        final String hash = hashUtils.sha512DigestString(test);

        assertEquals("ee26b0dd4af7e749aa1a8ee3c10ae9923f618980772e473f8819a5d4940e0db27ac185f8a0e1d5f84f88bc887" +
                "fd67b143732c304cc5fa9ad8e6f57f50028a8ff", hash);
    }

    @Test
    void sha512DigestFile() throws IOException, NoSuchAlgorithmException {
        final String filepath = "src/test/resources/test.txt";
        HashUtils hashUtils = HashUtils.getInstance();

        final String hash = hashUtils.sha512DigestFile(filepath);

        assertEquals("0e3e75234abc68f4378a86b3f4b32a198ba301845b0cd6e50106e874345700cc6663a86c1ea125dc5e92be17c" +
                "98f9a0f85ca9d5f595db2012f7cc3571945c123", hash);
    }
}
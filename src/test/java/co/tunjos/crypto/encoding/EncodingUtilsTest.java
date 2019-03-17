package co.tunjos.crypto.encoding;

import org.junit.jupiter.api.Test;

import java.io.UnsupportedEncodingException;

import static org.junit.jupiter.api.Assertions.assertEquals;

class EncodingUtilsTest {

    @Test
    void based64EncodeBytes() {
        final String test = "test";
        final EncodingUtils encodingUtils = EncodingUtils.getInstance();
        final String encodedString = encodingUtils.based64EncodeBytes(test.getBytes());

        assertEquals("dGVzdA==", encodedString);
    }

    @Test
    void based64EncodeString() {
        final String test = "test";
        final EncodingUtils encodingUtils = EncodingUtils.getInstance();
        final String encodedString = encodingUtils.based64EncodeString(test);

        assertEquals("dGVzdA==", encodedString);
    }

    @Test
    void based64DecodeBytes() {
        final String test = "dGVzdA==";
        final EncodingUtils encodingUtils = EncodingUtils.getInstance();
        final String decodedString = encodingUtils.based64DecodeBytes(test.getBytes());

        assertEquals("test", decodedString);
    }

    @Test
    void based64DecodeString() {
        final String test = "dGVzdA==";
        final EncodingUtils encodingUtils = EncodingUtils.getInstance();
        final String hash = encodingUtils.based64DecodeString(test);

        assertEquals("test", hash);
    }

    @Test
    void urlEncodeString() throws UnsupportedEncodingException {
        final String test = "https://test.com/test?test=test";
        final EncodingUtils encodingUtils = EncodingUtils.getInstance();
        final String encodedString = encodingUtils.urlEncodeString(test);

        assertEquals("https%3A%2F%2Ftest.com%2Ftest%3Ftest%3Dtest", encodedString);
    }

    @Test
    void urlDecodeString() throws UnsupportedEncodingException {
        final String test = "https%3A%2F%2Ftest.com%2Ftest%3Ftest%3Dtest";
        final EncodingUtils encodingUtils = EncodingUtils.getInstance();
        final String decodedString = encodingUtils.urlDecodeString(test);

        assertEquals("https://test.com/test?test=test", decodedString);
    }
}
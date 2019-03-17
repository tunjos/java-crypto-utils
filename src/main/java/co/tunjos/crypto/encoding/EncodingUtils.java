package co.tunjos.crypto.encoding;

import org.jetbrains.annotations.NotNull;

import java.io.UnsupportedEncodingException;
import java.net.URLDecoder;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.Base64;

public class EncodingUtils {
    private static EncodingUtils ourInstance = new EncodingUtils();

    public static EncodingUtils getInstance() {
        return ourInstance;
    }

    private EncodingUtils() {
    }

    @NotNull
    public String based64EncodeBytes(@NotNull byte[] bytes) {
        final Base64.Encoder base64Encoder = Base64.getEncoder();
        return base64Encoder.encodeToString(bytes);
    }

    @NotNull
    public String based64EncodeString(@NotNull String input) {
        final Base64.Encoder base64Encoder = Base64.getEncoder();
        return base64Encoder.encodeToString(input.getBytes());
    }

    @NotNull
    public String based64DecodeBytes(@NotNull byte[] bytes) {
        final Base64.Decoder base64Decoder = Base64.getDecoder();
        byte[] decodedBytes = base64Decoder.decode(bytes);
        return new String(decodedBytes);
    }

    @NotNull
    public String based64DecodeString(@NotNull String input) {
        final Base64.Decoder base64Decoder = Base64.getDecoder();
        byte[] decodedBytes = base64Decoder.decode(input.getBytes());
        return new String(decodedBytes);
    }

    @NotNull
    public String urlEncodeString(@NotNull String input) throws UnsupportedEncodingException {
        return URLEncoder.encode(input, StandardCharsets.UTF_8.name());
    }

    @NotNull
    public String urlDecodeString(@NotNull String input) throws UnsupportedEncodingException {
        return URLDecoder.decode(input, StandardCharsets.UTF_8.name());
    }
}

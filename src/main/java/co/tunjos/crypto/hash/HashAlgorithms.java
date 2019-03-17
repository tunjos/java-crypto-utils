package co.tunjos.crypto.hash;

import org.jetbrains.annotations.NotNull;

public enum HashAlgorithms {
    MD5("MD5"),

    SHA1("SHA-1"),

    SHA2224("SHA-224"),
    SHA256("SHA-256"),
    SHA384("SHA-384"),
    SHA512("SHA-512"),

    // Only Available from JDK 9+
    SHA512_224("SHA-512/224"),
    SHA512_256("SHA-512/256"),

    // Only Available from JDK 9+
    SHA3_224("SHA3-224"),
    SHA3_256("SHA3-256"),
    SHA3_384("SHA3-384"),
    SHA3_512("SHA3-512");

    private final String algorithm;

    HashAlgorithms(@NotNull final String algorithm) {
        this.algorithm = algorithm;
    }

    @Override
    public String toString() {
        return algorithm;
    }
}

package co.tunjos.crypto.crypto;

public enum AesKeySizes {
    AES_256(256),
    AES_192(192),
    AES_128(128);

    private final int keySize;

    AesKeySizes(final int keySize) {
        this.keySize = keySize;
    }

    public int getKeySize() {
        return keySize;
    }

    @Override
    public String toString() {
        return Integer.toString(keySize);
    }
}

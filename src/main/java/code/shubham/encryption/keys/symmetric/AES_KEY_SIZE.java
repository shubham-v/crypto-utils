package code.shubham.encryption.keys.symmetric;

public enum AES_KEY_SIZE {
    _128( 128),
    _192( 192),
    _256( 256);

    private final int size;

    AES_KEY_SIZE(int size) {
        this.size = size;
    }

    public int get() {
        return size;
    }
}

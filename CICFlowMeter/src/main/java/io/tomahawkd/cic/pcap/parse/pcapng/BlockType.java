package io.tomahawkd.cic.pcap.parse.pcapng;

public enum BlockType {

    SECTION_HEADER(0x0A0D0D0A),
    INTERFACE_DESC(0x00000001),
    ENHANCED_PACKET(0x00000006),
    SIMPLE_PACKET(0x00000003),
    NAME_RESOLVE(0x00000004),
    INTERFACE_STAT(0x00000005),
    SYSTEMD_JORNL(0x00000009),
    DCRYPT_SECRET(0x0000000a),
    OTHER(0x00000000);

    private final long signature;

    BlockType(long sign) {
        this.signature = sign;
    }

    public long signature() {
        return signature;
    }

    public static BlockType getTypeBySignature(long signature) {
        for (BlockType value : BlockType.values()) {
            if (value.signature == signature) return value;
        }

        return OTHER;
    }
}

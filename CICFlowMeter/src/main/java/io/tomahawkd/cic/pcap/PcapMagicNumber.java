package io.tomahawkd.cic.pcap;

import java.util.Arrays;

public enum PcapMagicNumber {

    PCAP(new byte[] {-44, -61, -78, -95}),
    PCAPNG(new byte[] {0x0a, 0x0d, 0x0d, 0x0a}),
    UNKNOWN(new byte[] {0x00, 0x00, 0x00, 0x00});

    private final byte[] magic;

    PcapMagicNumber(byte[] magic) {
        this.magic = magic;
    }

    public static PcapMagicNumber getTypeBySignature(byte[] magic) {
        for (PcapMagicNumber value : PcapMagicNumber.values()) {
            if (Arrays.equals(magic, value.magic)) return value;
        }

        return UNKNOWN;
    }
}

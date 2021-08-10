package io.tomahawkd.cic.pcap.parse.pcapng;

import io.kaitai.struct.KaitaiStream;

import java.nio.ByteOrder;
import java.util.Arrays;

//                         1                   2                   3
//    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
//   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// 0 |                   Block Type = 0x0A0D0D0A                     |
//   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// 4 |                      Block Total Length                       |
//   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// 8 |                      Byte-Order Magic                         |
//   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//12 |          Major Version        |         Minor Version         |
//   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//16 |                                                               |
//   |                          Section Length                       |
//   |                                                               |
//   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//24 /                                                               /
//   /                      Options (variable)                       /
//   /                                                               /
//   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//   |                      Block Total Length                       |
//   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
public class SectionHeader extends GenericBlock {

    private byte[] byteOrderMagic;

    private ByteOrder order;

    private int versionMajor;

    private int versionMinor;

    public SectionHeader(KaitaiStream _io, Pcapng parent) {
        super(_io, parent, BlockType.SECTION_HEADER);
    }

    @Override
    public void readBody(KaitaiStream stream) {
        this.byteOrderMagic = stream.readBytes(4);
        this.versionMajor = stream.readU2le();
        this.versionMinor = stream.readU2le();

        if (Arrays.equals(byteOrderMagic, new byte[] {0x4d, 0x3c, 0x2b, 0x1a})) {
            this.order = ByteOrder.LITTLE_ENDIAN;
        }
    }

    public byte[] getByteOrderMagic() {
        return byteOrderMagic;
    }

    public ByteOrder getOrder() {
        return order;
    }

    public int getVersionMajor() {
        return versionMajor;
    }

    public int getVersionMinor() {
        return versionMinor;
    }
}

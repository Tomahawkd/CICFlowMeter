package io.tomahawkd.cic.pcap.parse.pcapng;

import io.kaitai.struct.ByteBufferKaitaiStream;
import io.kaitai.struct.KaitaiStream;
import io.tomahawkd.cic.pcap.parse.EthernetFrame;
import io.tomahawkd.cic.pcap.parse.LinkType;

//                         1                   2                   3
//    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
//   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// 0 |                    Block Type = 0x00000006                    |
//   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// 4 |                      Block Total Length                       |
//   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// 8 |                         Interface ID                          |
//   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//12 |                        Timestamp (High)                       |
//   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//16 |                        Timestamp (Low)                        |
//   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//20 |                    Captured Packet Length                     |
//   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//24 |                    Original Packet Length                     |
//   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//28 /                                                               /
//   /                          Packet Data                          /
//   /              variable length, padded to 32 bits               /
//   /                                                               /
//   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//   /                                                               /
//   /                      Options (variable)                       /
//   /                                                               /
//   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//   |                      Block Total Length                       |
//   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
public class EnhancedPacket extends AbstractPacketBlock {

    private long interfaceId;

    private long timestampHigh;

    private long timestampLow;

    public EnhancedPacket(EndianDeclaredKaitaiStream _io, Pcapng parent) {
        super(_io, parent, BlockType.ENHANCED_PACKET);
    }

    @Override
    public void readBody(KaitaiStream stream) {
        this.interfaceId = stream.readU4be();
        this.timestampHigh = stream.readU4be();
        this.timestampLow = stream.readU4be();
        this.inclLen = stream.readU4be();
        this.oriLen = stream.readU4be();
        byte[] _raw_body = stream.readBytes(inclLen());
        InterfaceDescription desc = getInterface();
        if (desc != null && desc.linkType() == LinkType.ETHERNET) {
            KaitaiStream _io__raw_body = new ByteBufferKaitaiStream(_raw_body);
            this.body = new EthernetFrame(_io__raw_body);
        }
    }

    public long getInterfaceId() {
        return interfaceId;
    }

    public long getTimestamp() {
        return (timestampHigh << 32) + timestampLow;
    }

    public long getTimestampHigh() {
        return timestampHigh;
    }

    public long getTimestampLow() {
        return timestampLow;
    }

    public long inclLen() {
        return inclLen;
    }

    public long getOriLen() {
        return oriLen;
    }
}

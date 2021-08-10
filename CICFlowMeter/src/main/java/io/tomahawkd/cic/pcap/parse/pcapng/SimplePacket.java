package io.tomahawkd.cic.pcap.parse.pcapng;

import io.kaitai.struct.ByteBufferKaitaiStream;
import io.kaitai.struct.KaitaiStream;
import io.tomahawkd.cic.pcap.parse.EthernetFrame;
import io.tomahawkd.cic.pcap.parse.LinkType;

//                         1                   2                   3
//    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
//   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// 0 |                    Block Type = 0x00000003                    |
//   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// 4 |                      Block Total Length                       |
//   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// 8 |                    Original Packet Length                     |
//   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//12 /                                                               /
//   /                          Packet Data                          /
//   /              variable length, padded to 32 bits               /
//   /                                                               /
//   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//   |                      Block Total Length                       |
//   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//
// For that there is no capture length

@Deprecated
public class SimplePacket extends AbstractPacketBlock {

    public SimplePacket(EndianDeclaredKaitaiStream _io, Pcapng parent) {
        super(_io, parent, BlockType.SIMPLE_PACKET);
    }

    @Override
    public void readBody(KaitaiStream stream) {
        this.oriLen = stream.readU4le();
        InterfaceDescription desc = getInterface();
        if (desc != null && desc.linkType() == LinkType.ETHERNET) {
            this.inclLen = Math.min(desc.snapLen(), oriLen);
            byte[] _raw_body = stream.readBytes(inclLen);
            KaitaiStream _io__raw_body = new ByteBufferKaitaiStream(_raw_body);
            this.body = new EthernetFrame(_io__raw_body);
        }
    }

    // implicitly refer to 0
    @Override
    public long getInterfaceId() {
        return 0;
    }

    // actually this is the point that we cannot accept such packets
    // into the flow analyser. It has no timestamp so all analysis
    // based on time could run into error.
    @Override
    public long getTimestamp() {
        return 0;
    }
}

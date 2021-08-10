package io.tomahawkd.cic.pcap.parse.pcapng;

import io.kaitai.struct.KaitaiStream;
import io.tomahawkd.cic.pcap.parse.LinkType;

//                         1                   2                   3
//    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
//   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// 0 |                    Block Type = 0x00000001                    |
//   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// 4 |                      Block Total Length                       |
//   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// 8 |           LinkType            |           Reserved            |
//   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//12 |                            SnapLen                            |
//   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//16 /                                                               /
//   /                      Options (variable)                       /
//   /                                                               /
//   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//   |                      Block Total Length                       |
//   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
public class InterfaceDescription extends GenericBlock {

    private LinkType linkType;

    private long snapLen;

    public InterfaceDescription(KaitaiStream _io, Pcapng parent) {
        super(_io, parent, BlockType.INTERFACE_DESC);
    }

    @Override
    public void readBody(KaitaiStream stream) {
        this.linkType = LinkType.byId(stream.readU2le());
        stream.readU2le();
        this.snapLen = stream.readU4le();
    }

    public LinkType linkType() {
        return linkType;
    }

    public long snapLen() {
        return snapLen;
    }
}

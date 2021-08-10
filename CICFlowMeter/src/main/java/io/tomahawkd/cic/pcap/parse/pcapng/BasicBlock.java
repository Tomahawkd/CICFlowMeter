package io.tomahawkd.cic.pcap.parse.pcapng;

import io.kaitai.struct.KaitaiStream;

public class BasicBlock extends GenericBlock {

    public BasicBlock(KaitaiStream _io, Pcapng parent, BlockType type) {
        super(_io, parent, type);
    }

    @Override
    public void readBody(KaitaiStream stream) {

    }
}

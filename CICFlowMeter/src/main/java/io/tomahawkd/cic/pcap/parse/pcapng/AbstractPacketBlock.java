package io.tomahawkd.cic.pcap.parse.pcapng;

import io.kaitai.struct.KaitaiStream;
import io.tomahawkd.cic.pcap.parse.EthernetFrame;
import io.tomahawkd.cic.pcap.parse.PcapPacket;

public abstract class AbstractPacketBlock extends GenericBlock implements PcapPacket {

    protected long inclLen;
    protected long oriLen;

    protected EthernetFrame body;

    public AbstractPacketBlock(EndianDeclaredKaitaiStream _io, Pcapng parent, BlockType type) {
        super(_io, parent, type);
    }

    public abstract void readBody(KaitaiStream stream);

    public final EthernetFrame ethernet() {
        return body;
    }

    public abstract long getInterfaceId();

    public InterfaceDescription getInterface() {
        try {
            return this.parent().descs().get((int) getInterfaceId());
        } catch (IndexOutOfBoundsException e) {
            return null;
        }
    }
}

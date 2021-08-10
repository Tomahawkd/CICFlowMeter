package io.tomahawkd.cic.pcap.parse.pcapng;

import io.kaitai.struct.KaitaiStream;
import io.kaitai.struct.KaitaiStruct;
import io.tomahawkd.cic.pcap.BigFileKaitaiStream;
import io.tomahawkd.cic.pcap.parse.PcapFileReader;
import io.tomahawkd.cic.pcap.parse.PcapPacket;

import java.io.IOException;
import java.nio.ByteOrder;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;


/**
 * PCAPNG (named after libpcap / winpcap) is a popular format for saving
 * network traffic grabbed by network sniffers. It is typically
 * produced by tools like [Wireshark](https://www.wireshark.org/).
 *
 * @see <a href="https://www.ietf.org/id/draft-tuexen-opsawg-pcapng-03.html">Source</a>
 */
public class Pcapng extends KaitaiStruct implements PcapFileReader {

    private SectionHeader hdr;
    private final List<InterfaceDescription> descs;

    public static Pcapng fromFile(Path file) throws IOException {
        return new Pcapng(new BigFileKaitaiStream(file));
    }

    public Pcapng(KaitaiStream _io) {
        super(_io);
        long sign = this._io.readU4le();
        BlockType type = BlockType.getTypeBySignature(sign);
        if (type != BlockType.SECTION_HEADER)
            throw new KaitaiStream.ValidationNotEqualError(sign, type.signature(), _io(), "/types/header/seq/0");
        this.hdr = new SectionHeader(this._io, this);
        this.descs = new ArrayList<>();
    }

    public boolean hasNext() {
        return !this._io.isEof();
    }

    // Logical view of the pcapng
    // Section Header
    // |
    // +- Interface Description
    // |  +- Simple Packet
    // |  +- Enhanced Packet
    // |  +- Interface Statistics
    // |
    // +- Name Resolution
    public PcapPacket next() {
        while (hasNext()) {
            GenericBlock next = readNextBlock(this.hdr.getOrder());

            if (next.getType() == BlockType.ENHANCED_PACKET) {
                return (PcapPacket) next;
            } else if (next.getType() == BlockType.SECTION_HEADER) {
                // interface description should be clear for every section
                this.hdr = (SectionHeader) next;
                this.descs.clear();
            } else if (next.getType() == BlockType.INTERFACE_DESC) {
                descs.add((InterfaceDescription) next);
            }
            // else ignore other type blocks
        }

        // end of file
        return null;
    }

    private GenericBlock readNextBlock(ByteOrder order) {
        long sign = this._io.readU4le();
        BlockType type = BlockType.getTypeBySignature(sign);
        switch (type) {
            case SECTION_HEADER: return new SectionHeader(this._io, this);
            // we just drop the simple packet, since it is incomplete for the analysis
            // case SIMPLE_PACKET: return new SimplePacket(new EndianDeclaredKaitaiStream(this._io, order), this);
            case ENHANCED_PACKET: return new EnhancedPacket(new EndianDeclaredKaitaiStream(this._io, order), this);
            case INTERFACE_DESC: return new InterfaceDescription(new EndianDeclaredKaitaiStream(this._io, order), this);
            default:
                return new BasicBlock(new EndianDeclaredKaitaiStream(this._io, order), this, type);
        }
    }

    // for compatibility leave empty here
    @SuppressWarnings("unused")
    private void _read() {
    }

    public SectionHeader hdr() {
        return hdr;
    }

    public List<InterfaceDescription> descs() {
        return descs;
    }

    public KaitaiStruct _parent() {
        return null;
    }
}

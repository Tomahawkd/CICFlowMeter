package io.tomahawkd.cic.packet;

import io.tomahawkd.cic.pcap.*;
import io.tomahawkd.cic.util.IdGenerator;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import java.io.EOFException;
import java.io.IOException;

public class PcapReader {

    private static final Logger logger = LogManager.getLogger(PcapReader.class);
    private final Pcap pcapReader;

    private final IdGenerator generator = new IdGenerator();

    public PcapReader(String filename) {
        logger.debug("Read file {} with reader.", filename);
        try {
            pcapReader = Pcap.fromFile(filename);
        } catch (IOException e) {
            logger.error("Read pcap file error.", e);
            throw new RuntimeException("Read pcap file error", e);
        }
    }

    public PacketInfo nextPacket() throws EOFException {
        if (pcapReader.hasNext()) {
            return parsePacket(pcapReader.next(), new PacketInfo(generator.nextId()));
        } else throw new EOFException("End of pcap file.");
    }

    private PacketInfo parsePacket(Packet packet, PacketInfo info) {
        EthernetFrame frame = packet.getEthernetPacket();
        if (frame == null) return null;

        Ipv4Packet ipv4 = new Ipv4PacketDelegate().parse(info, frame);
        if (ipv4 == null) return null;

        TcpSegment tcp = new TcpPacketDelegate().parse(info, ipv4);
        if (tcp == null) return null;

        if (new HttpPreprocessPacketDelegate().parse(info)) {
            info.finishParse();
            return info;
        } else return null;
    }
}

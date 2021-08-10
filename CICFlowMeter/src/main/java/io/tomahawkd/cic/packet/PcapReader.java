package io.tomahawkd.cic.packet;

import io.tomahawkd.cic.pcap.PcapFileReaderProvider;
import io.tomahawkd.cic.pcap.parse.*;
import io.tomahawkd.cic.util.IdGenerator;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import java.io.EOFException;
import java.io.IOException;
import java.nio.file.Path;

public class PcapReader {

    private static final Logger logger = LogManager.getLogger(PcapReader.class);
    private final PcapFileReader pcapReader;

    private final IdGenerator generator = new IdGenerator();

    public PcapReader(Path file) {
        logger.debug("Read file {} with reader.", file);
        try {
            pcapReader = PcapFileReaderProvider.INSTANCE.newReader(file);
        } catch (IOException e) {
            logger.error("Read pcap file error.", e);
            throw new RuntimeException("Read pcap file error", e);
        }
    }

    public PacketInfo nextPacket() throws EOFException {
        if (!pcapReader.hasNext()) return eof();

        PcapPacket packet = pcapReader.next();
        if (packet == null) return eof();
        return parsePacket(packet, new PacketInfo(generator.nextId()));
    }

    private PacketInfo eof() throws EOFException {
        throw new EOFException("End of pcap file.");
    }

    private PacketInfo parsePacket(PcapPacket packet, PacketInfo info) {
        info.setTimestamp(packet.getTimestamp());
        EthernetFrame frame = packet.ethernet();
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

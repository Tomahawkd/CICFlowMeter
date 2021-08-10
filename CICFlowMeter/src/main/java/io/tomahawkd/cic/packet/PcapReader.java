package io.tomahawkd.cic.packet;

import io.tomahawkd.cic.pcap.PcapFileReaderProvider;
import io.tomahawkd.cic.pcap.parse.PcapFileReader;
import io.tomahawkd.cic.pcap.parse.PcapPacket;
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

    // e.g., IPv4
    private final PacketDelegate[] internetLayerDelegates =
            new PacketDelegate[] {
                    new Ipv4PacketDelegate()
            };
    // e.g., TCP
    private final PacketDelegate[] transportLayerDelegates =
            new PacketDelegate[] {
                    new TcpPacketDelegate()
            };
    // e.g., HTTP
    private final PacketDelegate[] appLayerDelegates =
            new PacketDelegate[] {
                    new HttpPreprocessPacketDelegate()
            };

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
        for (PacketDelegate delegate : internetLayerDelegates) {
            if (delegate.parse(info, packet)) {
                info.setTimestamp(packet.getTimestamp());
                for (PacketDelegate transport: transportLayerDelegates) {
                    if (transport.parse(info, packet)) {
                        for (PacketDelegate app: appLayerDelegates) {
                            if (app.parse(info, packet)) {
                                // post-parse works
                                info.finishParse();
                                return info;
                            }
                        }
                    }
                }
            }
        }
        return null;
    }
}

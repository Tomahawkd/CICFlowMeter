package io.tomahawkd.cic.packet;

import io.tomahawkd.cic.kaitai.Pcap;
import io.tomahawkd.cic.util.IdGenerator;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.jnetpcap.protocol.lan.Ethernet;
import org.jnetpcap.protocol.vpn.L2TP;

import java.io.EOFException;
import java.io.IOException;

public class PacketReader {

    private static final Logger logger = LogManager.getLogger(PacketReader.class);
    private final IdGenerator generator = new IdGenerator();
    private final Pcap pcapReader;
    private final String file;

    // e.g., IPv4
    private final PacketDelegate[] internetLayerDelegates =
            new PacketDelegate[] {
                    new Ipv4PacketDelegate(),
                    //new Ipv6PackageDelegate()
            };
    // e.g., TCP
    private final PacketDelegate[] transportLayerDelegates =
            new PacketDelegate[] {
                    new TcpPacketDelegate(),
                    //new UdpPackageDelegate()
            };
    // e.g., HTTP
    private final PacketDelegate[] appLayerDelegates =
            new PacketDelegate[] {
                    new HttpPacketDelegate()
            };

    public PacketReader(String filename) {
        file = filename;
        logger.debug("Read file {} with reader.", filename);

        try {
            pcapReader = Pcap.fromFile(filename);
        } catch (IOException e) {
            logger.error("Cannot Instantiate Pcap reader with file {}", filename);
            throw new RuntimeException("Cannot Instantiate Pcap reader with file " + filename);
        }
    }

    public PacketInfo nextPacket() throws EOFException {
            if (pcapReader.hasNext()) {
                try {
                    return parse(pcapReader.next(), new PacketInfo(generator.nextId()));
                } catch (Exception e) {
                    logger.error("Packet parse error.");
                    return null;
                }
            } else {
                logger.info("Reach the EOF of the file {}", file);
                throw new EOFException("Unexpected Exception");
            }

    }

    private PacketInfo parse(Pcap.Packet packet, PacketInfo info) {
        for (PacketDelegate delegate : internetLayerDelegates) {
            if (delegate.parse(info, packet)) {
                info.setTimestamp(packet.tsUsec());
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

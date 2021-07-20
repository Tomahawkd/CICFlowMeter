package io.tomahawkd.cic.packet;

import io.tomahawkd.cic.util.IdGenerator;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.jnetpcap.Pcap;
import org.jnetpcap.PcapClosedException;
import org.jnetpcap.PcapHeader;
import org.jnetpcap.nio.JBuffer;
import org.jnetpcap.nio.JMemory;
import org.jnetpcap.packet.PcapPacket;
import org.jnetpcap.protocol.lan.Ethernet;
import org.jnetpcap.protocol.vpn.L2TP;

public class PacketReader {

    private static final Logger logger = LogManager.getLogger(PacketReader.class);
    private final IdGenerator generator = new IdGenerator();
    private final Pcap pcapReader;
    private PcapHeader hdr;
    private JBuffer buf;
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
                    new HttpPacketDelegate(),
                    new UnknownAppLayerPacketDelegate()
            };

    public PacketReader(String filename) {
        file = filename;
        logger.debug("Read file {} with reader.", filename);
        StringBuilder errBuf = new StringBuilder(); // For any error msgs
        pcapReader = Pcap.openOffline(filename, errBuf);

        if (pcapReader == null) {
            logger.error("Error while opening file for capture: " + errBuf);
            System.exit(-1);
        } else {
            hdr = new PcapHeader(JMemory.POINTER);
            buf = new JBuffer(JMemory.POINTER);
        }
    }

    public PacketInfo nextPacket() {
        try {
            int status;
            if ((status = pcapReader.nextEx(hdr, buf)) == Pcap.NEXT_EX_OK) {
                PacketInfo info = new PacketInfo(generator.nextId());
                PcapPacket packet = new PcapPacket(hdr, buf);
                packet.scan(Ethernet.ID);

                PacketInfo temp = parse(packet, info);
                if (temp == null) {
                    packet.scan(L2TP.ID);
                    temp = parse(packet, info);
                }
                return temp;
            } else if (status == Pcap.NEXT_EX_EOF) {
                logger.info("Reach the EOF of the file {}", file);
                throw new PcapClosedException();
            } else {
                logger.error("Unexpected Exception while reading pcap file {}", file);
                throw new IllegalStateException("Unexpected Exception");
            }
        } catch (PcapClosedException e) {
            throw e;
        } catch (IllegalStateException e) {
            return null;
        }
    }

    private PacketInfo parse(PcapPacket packet, PacketInfo info) {
        for (PacketDelegate delegate : internetLayerDelegates) {
            if (delegate.parse(info, packet)) {
                info.setTimestamp(packet.getCaptureHeader().timestampInMicros());
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

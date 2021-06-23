package io.tomahawkd.cic.jnetpcap;

import io.tomahawkd.cic.data.*;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.jnetpcap.Pcap;
import org.jnetpcap.PcapClosedException;
import org.jnetpcap.PcapHeader;
import org.jnetpcap.nio.JBuffer;
import org.jnetpcap.nio.JMemory;
import org.jnetpcap.packet.PcapPacket;
import org.jnetpcap.protocol.lan.Ethernet;

public class PacketReader {

    private static final Logger logger = LogManager.getLogger(PacketReader.class);
    private final IdGenerator generator = new IdGenerator();
    private final Pcap pcapReader;
    private long firstPacket;
    private long lastPacket;
    private PcapHeader hdr;
    private JBuffer buf;
    private final String file;

    // e.g., IPv4
    private final PackageDelegate[] internetLayerDelegates =
            new PackageDelegate[]{
                    new Ipv4PackageDelegate(),
                    new Ipv6PackageDelegate()
            };
    // e.g., TCP
    private final PackageDelegate[] transportLayerDelegates =
            new PackageDelegate[]{
                    new TcpPackageDelegate(),
                    new UdpPackageDelegate()
            };
    // e.g., HTTP
    private final PackageDelegate[] appLayerDelegates =
            new PackageDelegate[]{};

    public PacketReader(String filename) {
        file = filename;
        StringBuilder errBuf = new StringBuilder(); // For any error msgs
        pcapReader = Pcap.openOffline(filename, errBuf);

        this.firstPacket = 0L;
        this.lastPacket = 0L;

        if (pcapReader == null) {
            logger.error("Error while opening file for capture: " + errBuf);
            System.exit(-1);
        } else {
            hdr = new PcapHeader(JMemory.POINTER);
            buf = new JBuffer(JMemory.POINTER);
        }
    }

    public PackageInfo nextPacket() {
        try {
            PackageInfo info = new PackageInfo(generator.nextId());
            if (pcapReader.nextEx(hdr, buf) == Pcap.NEXT_EX_OK) {
                PcapPacket packet = new PcapPacket(hdr, buf);
                packet.scan(Ethernet.ID);

                int complete = 0;
                outer:
                for (PackageDelegate ild: internetLayerDelegates) {
                    if (ild.canAccept(packet)) {
                        ild.parse(info, packet);
                        info.setTimestamp(packet.getCaptureHeader().timestampInMicros());
                        complete = 1;
                        for (PackageDelegate tld: transportLayerDelegates) {
                            if (tld.canAccept(packet)) {
                                tld.parse(info, packet);
                                // TODO: ignore app layer for now
                                complete = 2;
                                break outer;
                            }
                        }
                    }
                }

                if (complete == 0) {
                    logger.warn("No Internet Layer Protocol could parse the package, discarded");
                    return null;
                } else if (complete == 1) {
                    logger.warn("No Transport Layer Protocol could parse the package, discarded");
                    return null;
                }
                // TODO: ignoring App layer

                // post-parse works
                if (this.firstPacket == 0L)
                    this.firstPacket = packet.getCaptureHeader().timestampInMillis();
                this.lastPacket = packet.getCaptureHeader().timestampInMillis();
                info.finishParse();
                return info;
            } else {
                throw new PcapClosedException();
            }
        } catch (PcapClosedException e) {
            logger.debug("Read All packets on {}", file);
            throw e;
        } catch (Exception ex) {
            logger.error(ex.getMessage());
            return null;
        }
    }
}

package io.tomahawkd.cic.util;

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
                    new HttpPacketDelegate()
            };

    public PacketReader(String filename) {
        file = filename;
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
            if (pcapReader.nextEx(hdr, buf) == Pcap.NEXT_EX_OK) {
                PacketInfo info = new PacketInfo(generator.nextId());
                PcapPacket packet = new PcapPacket(hdr, buf);
                packet.scan(Ethernet.ID);

                PacketInfo temp = parse(packet, info);
                if (temp == null) {
                    packet.scan(L2TP.ID);
                    temp = parse(packet, info);
                }
                return temp;
            } else {
                throw new PcapClosedException();
            }
        } catch (
                PcapClosedException e) {
            logger.debug("Read All packets on {}", file);
            throw e;
        } catch (
                Exception ex) {
            logger.error(ex.getMessage());
            return null;
        }
    }

    private PacketInfo parse(PcapPacket packet, PacketInfo info) {
        if (internetLayerDelegates[0].parse(info, packet)) {
            info.setTimestamp(packet.getCaptureHeader().timestampInMicros());
            if (transportLayerDelegates[0].parse(info, packet)) {
                if (appLayerDelegates[0].parse(info, packet)) {
                    // post-parse works
                    info.finishParse();
                    return info;
                }
            }
        }
        return null;
    }
}

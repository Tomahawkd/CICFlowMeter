package io.tomahawkd.cic.jnetpcap;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.jnetpcap.Pcap;
import org.jnetpcap.PcapClosedException;
import org.jnetpcap.PcapHeader;
import org.jnetpcap.nio.JBuffer;
import org.jnetpcap.nio.JMemory;
import org.jnetpcap.packet.PcapPacket;
import org.jnetpcap.protocol.lan.Ethernet;
import org.jnetpcap.protocol.network.Ip4;
import org.jnetpcap.protocol.tcpip.Http;
import org.jnetpcap.protocol.tcpip.Tcp;
import org.jnetpcap.protocol.vpn.L2TP;

public class PacketReader {

    private static final Logger logger = LogManager.getLogger(PacketReader.class);
    private final IdGenerator generator = new IdGenerator();
    private final Pcap pcapReader;
    private PcapHeader hdr;
    private JBuffer buf;
    private final String file;

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

    public BasicPacketInfo nextPacket() {
        PcapPacket packet;
        BasicPacketInfo packetInfo = null;
        try {
            if (pcapReader.nextEx(hdr, buf) == Pcap.NEXT_EX_OK) {
                packet = new PcapPacket(hdr, buf);
                packet.scan(Ethernet.ID);

                packetInfo = getIpv4Info(packet);
                if (packetInfo == null) {
                    packetInfo = getVPNInfo(packet);
                }
            } else {
                throw new PcapClosedException();
            }
        } catch (PcapClosedException e) {
            logger.debug("Read All packets on {}", file);
            throw e;
        } catch (Exception ex) {
            logger.debug(ex.getMessage());
        }
        return packetInfo;
    }

    private BasicPacketInfo getIpv4Info(PcapPacket packet) {
        BasicPacketInfo packetInfo = null;
        Ip4 ipv4 = new Ip4();
        try {
            if (packet.hasHeader(ipv4)) {
                packetInfo = new BasicPacketInfo(this.generator);
                packetInfo.setSrc(ipv4.source());
                packetInfo.setDst(ipv4.destination());
                //packetInfo.setTimeStamp(packet.getCaptureHeader().timestampInMillis());
                packetInfo.setTimeStamp(packet.getCaptureHeader().timestampInMicros());

                Tcp tcp = new Tcp();
                if (packet.hasHeader(tcp)) {
                    packetInfo.setTCPWindow(tcp.window());
                    packetInfo.setSrcPort(tcp.source());
                    packetInfo.setDstPort(tcp.destination());
                    packetInfo.setProtocol(6);
                    packetInfo.setFlagFIN(tcp.flags_FIN());
                    packetInfo.setFlagPSH(tcp.flags_PSH());
                    packetInfo.setFlagURG(tcp.flags_URG());
                    packetInfo.setFlagSYN(tcp.flags_SYN());
                    packetInfo.setFlagACK(tcp.flags_ACK());
                    packetInfo.setFlagECE(tcp.flags_ECE());
                    packetInfo.setFlagCWR(tcp.flags_CWR());
                    packetInfo.setFlagRST(tcp.flags_RST());
                    packetInfo.setPayloadBytes(tcp.getPayloadLength());
                    packetInfo.setHeaderBytes(tcp.getHeaderLength());

                    Http http = new Http();
                    if (packet.hasHeader(http)) {
                        getHTTPInfo(packetInfo, packet);
                    }
                }
            }
        } catch (Exception e) {
            //e.printStackTrace();
            packet.scan(ipv4.getId());
            String errormsg = "";
            errormsg += e.getMessage() + "\n";
            //errormsg+=packet.getHeader(new Ip4())+"\n";
            errormsg += "********************************************************************************" + "\n";
            errormsg += packet.toHexdump() + "\n";

            //System.out.println(errormsg);
            logger.debug(errormsg);
            //System.exit(-1);
            return null;
        }
        return packetInfo;
    }

    private BasicPacketInfo getVPNInfo(PcapPacket packet) {
        BasicPacketInfo packetInfo = null;
        L2TP l2tp = new L2TP();
        try {
            packet.scan(L2TP.ID);
            if (packet.hasHeader(l2tp)) {
                packet.scan(Ip4.ID);
                packetInfo = getIpv4Info(packet);
            }
        } catch (Exception e) {
            logger.debug(e.getMessage());
            packet.scan(l2tp.getId());
            String errormsg = "";
            errormsg += e.getMessage() + "\n";
            //errormsg+=packet.getHeader(new L2TP())+"\n";
            errormsg += "********************************************************************************" + "\n";
            errormsg += packet.toHexdump() + "\n";

            //System.out.println(errormsg);
            logger.debug(errormsg);
            //System.exit(-1);
            return null;
        }

        return packetInfo;
    }

    private void getHTTPInfo(BasicPacketInfo packetInfo, PcapPacket packet) {
    }
}

package io.tomahawkd.cic.data;

import org.jnetpcap.packet.PcapPacket;
import org.jnetpcap.protocol.tcpip.Tcp;

public class TcpPackageDelegate extends AbstractPackageDelegate {

    public TcpPackageDelegate() {
        super(Tcp.ID);
    }

    @Override
    public void parse(PackageInfo dst, PcapPacket packet) {
        packet.scan(Tcp.ID);
        Tcp tcp = new Tcp();
        if (!packet.hasHeader(tcp)) {
            throw new IllegalArgumentException("Not an TCP header.");
        }

        dst.addFeature(MetaFeature.SRC_PORT, tcp.source());
        dst.addFeature(MetaFeature.DST_PORT, tcp.destination());
        dst.addFeature(Feature.TCP_WINDOW, tcp.window());
        dst.addFeature(MetaFeature.PROTO, 6);
        dst.addFeature(Feature.FIN, tcp.flags_FIN());
        dst.addFeature(Feature.PSH, tcp.flags_PSH());
        dst.addFeature(Feature.URG, tcp.flags_URG());
        dst.addFeature(Feature.SYN, tcp.flags_SYN());
        dst.addFeature(Feature.ACK, tcp.flags_ACK());
        dst.addFeature(Feature.ECE, tcp.flags_ECE());
        dst.addFeature(Feature.CWR, tcp.flags_CWR());
        dst.addFeature(Feature.RST, tcp.flags_RST());
        dst.addFeature(Feature.PAYLOAD_LEN, tcp.getPayloadLength());
        dst.addFeature(Feature.HEADER_LEN, tcp.getHeaderLength());
        dst.addFeature(MetaFeature.TCP, true);
    }

    enum Feature implements PackageFeature {
        TCP_WINDOW, FIN, PSH, URG, SYN, ACK, ECE, CWR, RST, PAYLOAD_LEN, HEADER_LEN,
    }
}
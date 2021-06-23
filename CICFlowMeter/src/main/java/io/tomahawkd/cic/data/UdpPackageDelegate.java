package io.tomahawkd.cic.data;

import org.jnetpcap.packet.PcapPacket;
import org.jnetpcap.protocol.lan.Ethernet;
import org.jnetpcap.protocol.tcpip.Udp;

public class UdpPackageDelegate extends AbstractPackageDelegate {

    public UdpPackageDelegate() {
        super(Udp.ID);
    }

    @Override
    public void parse(PackageInfo dst, PcapPacket packet) {
        packet.scan(Ethernet.ID);
        Udp udp = new Udp();
        if (!packet.hasHeader(udp)) {
            throw new IllegalArgumentException("Not an UDP header.");
        }

        dst.addFeature(MetaFeature.SRC_PORT, udp.source());
        dst.addFeature(MetaFeature.DST_PORT, udp.destination());
        dst.addFeature(MetaFeature.PROTO, 17);
        dst.addFeature(MetaFeature.PAYLOAD_LEN, udp.getPayloadLength());
        dst.addFeature(MetaFeature.HEADER_LEN, udp.getHeaderLength());
        dst.addFeature(MetaFeature.UDP, true);
    }
}
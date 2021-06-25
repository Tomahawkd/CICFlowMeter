package io.tomahawkd.cic.data;

import org.jnetpcap.packet.PcapPacket;
import org.jnetpcap.protocol.tcpip.Udp;

public class UdpPackageDelegate extends AbstractPackageDelegate {

    public UdpPackageDelegate() {
        super(Udp.ID);
    }

    @Override
    public boolean parse(PackageInfo dst, PcapPacket packet) {
        Udp udp = new Udp();
        if (!packet.hasHeader(udp)) {
            return false;
        }

        dst.addFeature(MetaFeature.SRC_PORT, udp.source());
        dst.addFeature(MetaFeature.DST_PORT, udp.destination());
        dst.addFeature(MetaFeature.PROTO, 17);
        dst.addFeature(MetaFeature.PAYLOAD_LEN, udp.getPayloadLength());
        dst.addFeature(MetaFeature.HEADER_LEN, udp.getHeaderLength());
        dst.addFeature(MetaFeature.UDP, true);
        return true;
    }
}
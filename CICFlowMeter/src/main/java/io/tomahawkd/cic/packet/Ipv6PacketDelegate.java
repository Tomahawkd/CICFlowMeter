package io.tomahawkd.cic.packet;

import org.jnetpcap.packet.PcapPacket;
import org.jnetpcap.protocol.network.Ip6;

@AtLayer(LayerType.INTERNET)
public class Ipv6PacketDelegate extends AbstractPacketDelegate {

    public Ipv6PacketDelegate() {
        super(Ip6.ID);
    }

    @Override
    public boolean parse(PacketInfo dst, PcapPacket packet) {
        Ip6 ipv6 = new Ip6();
        if (!packet.hasHeader(ipv6)) {
            return false;
        }

        dst.addFeature(MetaFeature.SRC, ipv6.source());
        dst.addFeature(MetaFeature.DST, ipv6.destination());
        dst.addFeature(MetaFeature.IPV6, true);
        return true;
    }
}

package io.tomahawkd.cic.packet;

import org.jnetpcap.packet.PcapPacket;
import org.jnetpcap.protocol.network.Ip4;

@Layer(LayerType.INTERNET)
public class Ipv4PacketDelegate extends AbstractPacketDelegate {


    public Ipv4PacketDelegate() {
        super(Ip4.ID);
    }

    @Override
    public boolean parse(PacketInfo dst, PcapPacket packet) {
        Ip4 ipv4 = new Ip4();
        if (!packet.hasHeader(ipv4)) {
            return false;
        }

        dst.addFeature(MetaFeature.SRC, ipv4.source());
        dst.addFeature(MetaFeature.DST, ipv4.destination());
        dst.addFeature(MetaFeature.IPV4, true);
        return true;
    }
}

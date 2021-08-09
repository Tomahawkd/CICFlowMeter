package io.tomahawkd.cic.packet;

import io.tomahawkd.cic.pcap.EthernetFrame;
import io.tomahawkd.cic.pcap.Ipv4Packet;

@Layer(LayerType.INTERNET)
public class Ipv4PacketDelegate {

    public Ipv4Packet parse(PacketInfo dst, EthernetFrame frame) {

        Ipv4Packet ipv4 = frame.body();
        if (ipv4 == null) return null;

        dst.addFeature(MetaFeature.SRC, ipv4.srcIpAddr());
        dst.addFeature(MetaFeature.DST, ipv4.dstIpAddr());
        dst.addFeature(MetaFeature.IPV4, true);
        return ipv4;
    }
}

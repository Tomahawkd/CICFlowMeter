package io.tomahawkd.cic.packet;

import org.jnetpcap.packet.PcapPacket;
import org.jnetpcap.protocol.tcpip.Udp;

@AtLayer(LayerType.TRANSPORT)
public class UdpPacketDelegate extends AbstractPacketDelegate {

    public UdpPacketDelegate() {
        super(Udp.ID);
    }

    @Override
    public boolean parse(PacketInfo dst, PcapPacket packet) {
        Udp udp = new Udp();
        if (!packet.hasHeader(udp)) {
            return false;
        }

        dst.addFeature(MetaFeature.SRC_PORT, udp.source());
        dst.addFeature(MetaFeature.DST_PORT, udp.destination());
        dst.addFeature(MetaFeature.PAYLOAD_LEN, udp.getPayloadLength());
        dst.addFeature(MetaFeature.HEADER_LEN, udp.getHeaderLength());
        dst.addFeature(MetaFeature.UDP, true);
        return true;
    }
}
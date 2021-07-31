package io.tomahawkd.cic.packet;

import org.jnetpcap.packet.PcapPacket;

@AtLayer(LayerType.APPLICATION)
public class UnknownAppLayerPacketDelegate extends AbstractPacketDelegate {

    public UnknownAppLayerPacketDelegate() {
        super(0);
    }

    @Override
    public boolean parse(PacketInfo dst, PcapPacket packet) {
        dst.addFeature(MetaFeature.HTTP, false);
        return true;
    }
}

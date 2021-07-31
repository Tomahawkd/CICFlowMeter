package io.tomahawkd.cic.packet;

import org.jnetpcap.packet.PcapPacket;
import org.jnetpcap.protocol.tcpip.Tcp;

@AtLayer(LayerType.TRANSPORT)
public class TcpPacketDelegate extends AbstractPacketDelegate {

    public TcpPacketDelegate() {
        super(Tcp.ID);
    }

    @Override
    public boolean parse(PacketInfo dst, PcapPacket packet) {
        Tcp tcp = new Tcp();
        if (!packet.hasHeader(tcp)) {
            return false;
        }

        dst.addFeature(MetaFeature.SRC_PORT, tcp.source());
        dst.addFeature(MetaFeature.DST_PORT, tcp.destination());
        dst.addFeature(Feature.TCP_WINDOW, tcp.window());
        dst.addFeature(Feature.FLAG, tcp.flags());
        dst.addFeature(MetaFeature.PAYLOAD_LEN, tcp.getPayloadLength());
        dst.addFeature(MetaFeature.HEADER_LEN, tcp.getHeaderLength());
        dst.addFeature(Feature.SEQ, tcp.seq());
        dst.addFeature(Feature.ACK, tcp.ack());
        dst.addFeature(MetaFeature.TCP, true);
        return true;
    }

    public enum Feature implements PacketFeature {
        TCP_WINDOW(Integer.class), FLAG(Integer.class), SEQ(Long.class), ACK(Long.class);

        private final Class<?> type;

        Feature(Class<?> type) {
            this.type = type;
        }

        @Override
        public Class<?> getType() {
            return type;
        }
    }
}
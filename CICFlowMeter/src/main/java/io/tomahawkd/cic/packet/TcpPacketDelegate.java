package io.tomahawkd.cic.packet;

import io.tomahawkd.cic.pcap.data.TcpSegment;
import io.tomahawkd.cic.pcap.parse.PcapPacket;

@Layer(LayerType.TRANSPORT)
public class TcpPacketDelegate implements PacketDelegate {

    public boolean parse(PacketInfo dst, PcapPacket packet) {
        TcpSegment tcp = packet.tcp();
        if (tcp == null) return false;

        dst.addFeature(MetaFeature.SRC_PORT, tcp.srcPort());
        dst.addFeature(MetaFeature.DST_PORT, tcp.dstPort());
        dst.addFeature(Feature.TCP_WINDOW, tcp.window());
        dst.addFeature(Feature.FLAG, tcp.flags());
        dst.addFeature(MetaFeature.PAYLOAD_LEN, tcp.payloadLength());
        dst.addFeature(MetaFeature.HEADER_LEN, tcp.headerLength());
        dst.addFeature(Feature.SEQ, tcp.seq());
        dst.addFeature(Feature.ACK, tcp.ack());
        dst.addFeature(MetaFeature.APP_DATA, tcp.payload());
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
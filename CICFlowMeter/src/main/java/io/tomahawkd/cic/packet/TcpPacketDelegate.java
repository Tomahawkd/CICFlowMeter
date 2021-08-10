package io.tomahawkd.cic.packet;

import io.tomahawkd.cic.pcap.parse.Ipv4Packet;
import io.tomahawkd.cic.pcap.parse.TcpSegment;

@Layer(LayerType.TRANSPORT)
public class TcpPacketDelegate {

    public TcpSegment parse(PacketInfo dst, Ipv4Packet packet) {
        TcpSegment tcp = packet.body();
        if (tcp == null) return null;

        dst.addFeature(MetaFeature.SRC_PORT, tcp.srcPort());
        dst.addFeature(MetaFeature.DST_PORT, tcp.dstPort());
        dst.addFeature(Feature.TCP_WINDOW, tcp.windowSize());
        dst.addFeature(Feature.FLAG, tcp.flags());
        dst.addFeature(MetaFeature.PAYLOAD_LEN, tcp.body().length);
        dst.addFeature(MetaFeature.HEADER_LEN, tcp.offset() * 4);
        dst.addFeature(Feature.SEQ, tcp.seqNum());
        dst.addFeature(Feature.ACK, tcp.ackNum());
        dst.addFeature(MetaFeature.APP_DATA, tcp.body());
        dst.addFeature(MetaFeature.TCP, true);
        return tcp;
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
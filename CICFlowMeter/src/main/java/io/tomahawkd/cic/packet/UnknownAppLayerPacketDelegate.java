package io.tomahawkd.cic.packet;

import org.apache.commons.lang3.ArrayUtils;
import org.jnetpcap.packet.PcapPacket;

@AtLayer(LayerType.APPLICATION)
public class UnknownAppLayerPacketDelegate extends AbstractPacketDelegate {

    public UnknownAppLayerPacketDelegate() {
        super(0);
    }

    @Override
    public boolean parse(PacketInfo dst, PcapPacket packet) {
        dst.addFeature(MetaFeature.HTTP, false);

        byte[] payload = dst.getFeature(TcpPacketDelegate.Feature.PAYLOAD, byte[].class);
        if (payload != null && payload.length > 0) {
            int i = 0;
            int terminationCount = 0;
            while (i < payload.length) {
                if (isReadable(payload[i])) {

                    // HTTP header termination 0x0d 0x0a 0x0d 0x0a
                    //             count       1    2    3    4
                    // If we not found the termination, just record all readable chars
                    if (payload[i] == 0x0d) {
                        if (terminationCount == 0 || terminationCount == 2) {
                            terminationCount++; // 1/3
                        } else terminationCount = 0;
                    } else if (payload[i] == 0x0a) {
                        if (terminationCount == 1) {
                            terminationCount++; // 2
                        } else if (terminationCount == 3) {
                            dst.addFeature(Feature.CRLF, true); // 4
                            break;
                        } else terminationCount = 0;
                    } else terminationCount = 0;
                    i++;
                } else {
                    dst.addFeature(Feature.CRLF, false);
                    break;
                }
            }

            String readableString = new String(ArrayUtils.subarray(payload, 0, i));
            dst.addFeature(Feature.PAYLOAD, readableString);
        }
        dst.removeFeature(TcpPacketDelegate.Feature.PAYLOAD);

        return true;
    }

    private boolean isReadable(byte b) {
        return (b >= 0x20 && b <= 0x7e) || b == 0x0d || b == 0x0a;
    }

    public enum Feature implements PacketFeature {
        PAYLOAD(String.class), CRLF(Boolean.class);

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

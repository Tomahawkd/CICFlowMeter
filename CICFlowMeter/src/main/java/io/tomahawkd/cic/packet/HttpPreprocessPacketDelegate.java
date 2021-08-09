package io.tomahawkd.cic.packet;

import org.apache.commons.lang3.ArrayUtils;
import org.jnetpcap.packet.PcapPacket;

@Layer(LayerType.APPLICATION)
public class HttpPreprocessPacketDelegate extends AbstractPacketDelegate {

    public HttpPreprocessPacketDelegate() {
        super(0);
    }

    @Override
    public boolean parse(PacketInfo dst, PcapPacket packet) {
        byte[] payload = dst.getFeature(MetaFeature.APP_DATA, byte[].class);
        boolean readable = false;
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

            if (i >= payload.length) {
                dst.addFeature(Feature.CRLF, false);
            }

            if (i != 0) {
                String readableString = new String(ArrayUtils.subarray(payload, 0, i + 1));
                readable = true;
                dst.addFeature(Feature.PAYLOAD, readableString);
            }
            dst.addFeature(MetaFeature.READABLE, readable);
        }
        dst.removeFeature(MetaFeature.APP_DATA);

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

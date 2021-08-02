package io.tomahawkd.cic.flow.features.http;

import io.tomahawkd.cic.packet.*;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import java.util.function.Consumer;

public class TcpReassembler {

    private static final Logger logger = LogManager.getLogger(TcpReassembler.class);

    // used for building incomplete string
    private StringBuilder incompleteStringBuilder = new StringBuilder();

    private final Consumer<PacketInfo> flowFeature;

    public TcpReassembler(Consumer<PacketInfo> releaseCallback) {
        this.flowFeature = releaseCallback;
        reset();
    }

    /**
     * @param info packet IN ORDER (pushed by the TcpReorderer)
     * @see TcpReorderer
     */
    public void addPacket(PacketInfo info) {
        // contains http header
        if (info.getBoolFeature(MetaFeature.HTTP)) {
            // clear all for that this packet is the first one
            if (incompleteStringBuilder.length() > 0) {
                forceParse();
            }

            // if complete, the packet is already parsed at packet layer feature extraction
            if (!info.getBoolFeature(HttpPacketDelegate.Feature.INCOMPLETE)) {
                flowFeature.accept(info);
                return;
            }

            String incompleteString = info.getFeature(HttpPacketDelegate.Feature.INCOM_SEGMENT, String.class);
            // discard the packet
            if (incompleteString == null || incompleteString.isEmpty()) {
                logger.warn("The first HTTP header segment is empty.");
            }

            incompleteStringBuilder.append(incompleteString);
        } else {
            // not http section

            // the first packet must be http
            // so the packet should be discarded
            if (incompleteStringBuilder.length() == 0) {
                return;
            }

            String readableString = info.getFeature(UnknownAppLayerPacketDelegate.Feature.PAYLOAD, String.class);
            if (readableString == null || readableString.isEmpty()) {
                logger.warn("The HTTP header segment (not first) is empty.");
            }

            // exact the next segment
            incompleteStringBuilder.append(readableString);

            // terminate by CRLF * 2, that is, the header ends
            if (info.getBoolFeature(UnknownAppLayerPacketDelegate.Feature.CRLF)) {
                String header = incompleteStringBuilder.toString();
                logger.debug("Complete one header [{}]", header);
                int parsed = HttpPacketDelegate.parseFeatures(info, header, false);
                if (parsed != HttpPacketDelegate.OK) {
                    logger.warn("The header [{}] parsed failed which is not expected.", header);
                    info.addFeature(Feature.INVALID, true);
                }

                // since it is complete, delete all
                reset();
                flowFeature.accept(info);
            }
        }
    }

    public void forceParse() {
        if (incompleteStringBuilder.length() == 0) return;
        PacketInfo info = new PacketInfo(-1);
        String header = incompleteStringBuilder.toString();
        int parsed = HttpPacketDelegate.parseFeatures(info, header, false);
        if (parsed != HttpPacketDelegate.OK) {
            info.addFeature(Feature.INVALID, true);
        }

        // since it is complete, delete all
        reset();
        flowFeature.accept(info);
    }

    public void reset() {
        if (incompleteStringBuilder.length() == 0) return;
        incompleteStringBuilder = new StringBuilder();
    }

    public enum Feature implements PacketFeature {

        INVALID(Boolean.class);

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

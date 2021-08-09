package io.tomahawkd.cic.flow.features.http;

import io.tomahawkd.cic.packet.*;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import java.util.function.Consumer;

public class TcpReassembler {

    private static final Logger logger = LogManager.getLogger(TcpReassembler.class);

    // used for building incomplete string
    private StringBuilder incompleteStringBuilder = new StringBuilder();

    private final HttpPacketParser parser;

    private final Consumer<PacketInfo> flowFeature;

    public TcpReassembler(Consumer<PacketInfo> releaseCallback) {
        this.flowFeature = releaseCallback;
        this.parser = new HttpPacketParser();
    }

    /**
     * @param info packet IN ORDER (pushed by the TcpReorderer)
     * @see TcpReorderer
     */
    public void addPacket(PacketInfo info) {

        String readableString = info.getFeature(HttpPreprocessPacketDelegate.Feature.PAYLOAD, String.class);
        if (readableString == null || readableString.isEmpty()) {
            logger.warn("The payload is empty.");
            return;
        }

        // check the payload first
        HttpPacketParser.Status parsed = parser.parseFeatures(info, readableString, false);

        if (parsed != HttpPacketParser.Status.INVALID) {

            // if parsed packet is not invalid, that is, it is a http header
            // so that we need to clear the stringBuilder
            if (incompleteStringBuilder.length() != 0) forceParse();

            if (parsed == HttpPacketParser.Status.OK) {
                flowFeature.accept(info);
                return;
            } else if (parsed == HttpPacketParser.Status.INCOMPLETE) {
                incompleteStringBuilder.append(readableString);
                return;
            }
        }

        // parsed == HttpPacketParser.Status.INVALID
        // parse reassembled packets
        if (incompleteStringBuilder.length() != 0) {
            // we still have incomplete string
            // exactly the next segment
            incompleteStringBuilder.append(readableString);

            // terminate by CRLF * 2, that is, the header ends
            if (info.getBoolFeature(HttpPreprocessPacketDelegate.Feature.CRLF)) {
                String header = incompleteStringBuilder.toString();
                logger.debug("Complete one header [{}]", header);
                parsed = parser.parseFeatures(info, header, false);
                if (parsed != HttpPacketParser.Status.OK) {
                    logger.warn("The header [{}] parsed failed which is not expected.", header);
                    info.addFeature(HttpPacketFeature.INVALID, true);
                }

                flowFeature.accept(info);
                // since it is complete, delete all
                reset();
            }
        }
    }

    public void forceParse() {
        if (incompleteStringBuilder.length() == 0) return;
        PacketInfo info = new PacketInfo(-1);
        String header = incompleteStringBuilder.toString();
        HttpPacketParser.Status parsed = parser.parseFeatures(info, header, true);
        if (parsed == HttpPacketParser.Status.OK) {
            flowFeature.accept(info);
        } else {
            logger.debug("Discarded forcibly parsed packet");
        }

        // since it is complete, delete all
        reset();
    }

    public void reset() {
        if (incompleteStringBuilder.length() == 0) return;
        incompleteStringBuilder = new StringBuilder();
    }
}

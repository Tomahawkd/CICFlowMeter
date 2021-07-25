package io.tomahawkd.cic.flow.features;

import io.tomahawkd.cic.flow.Flow;
import io.tomahawkd.cic.packet.HttpPacketDelegate;
import io.tomahawkd.cic.packet.MetaFeature;
import io.tomahawkd.cic.packet.PacketInfo;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import java.util.Optional;

public abstract class AbstractHttpFeature extends AbstractFlowFeature {

    private static final Logger logger = LogManager.getLogger(AbstractHttpFeature.class);

    public AbstractHttpFeature(Flow flow) {
        super(flow);
    }

    @Override
    public final void addPacket(PacketInfo info, boolean fwd) {

        Boolean http = Optional.ofNullable(info.getFeature(MetaFeature.HTTP, Boolean.class)).orElse(false);
        if (!http) return;

        Boolean request = info.getFeature(HttpPacketDelegate.Feature.REQUEST, Boolean.class);
        if (request == null) {
            logger.warn("Packet {} has no request tag, discarded", info.getFlowId());
            logger.warn("Packet Content: {}", info.toString());
            return;
        }

        addGenericPacket(info, request);
        if (request) addRequestPacket(info);
        else addResponsePacket(info);
    }

    public void addGenericPacket(PacketInfo info, boolean isRequest) {

    }

    public void addRequestPacket(PacketInfo info) {

    }

    public void addResponsePacket(PacketInfo info) {

    }
}

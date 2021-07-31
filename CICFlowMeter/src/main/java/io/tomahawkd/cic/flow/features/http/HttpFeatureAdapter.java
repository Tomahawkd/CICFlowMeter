package io.tomahawkd.cic.flow.features.http;

import io.tomahawkd.cic.flow.Flow;
import io.tomahawkd.cic.flow.features.AbstractFlowFeature;
import io.tomahawkd.cic.flow.features.Feature;
import io.tomahawkd.cic.flow.features.FeatureType;
import io.tomahawkd.cic.flow.features.FlowFeatureTag;
import io.tomahawkd.cic.packet.HttpPacketDelegate;
import io.tomahawkd.cic.packet.MetaFeature;
import io.tomahawkd.cic.packet.PacketInfo;
import io.tomahawkd.config.util.ClassManager;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Modifier;
import java.util.*;
import java.util.stream.Collectors;

@Feature(name = "HttpFeatures", tags = {}, ordinal = 8, type = FeatureType.HTTP)
public class HttpFeatureAdapter extends AbstractFlowFeature {

    private static final Logger logger = LogManager.getLogger(HttpFeatureAdapter.class);

    private final TcpPayloadReassembler reassembler = new TcpPayloadReassembler();
    private final List<HttpFeature> features;

    public HttpFeatureAdapter(Flow flow) {
        super(flow);
        features = new ArrayList<>();
        List<FlowFeatureTag> tags = new ArrayList<>();
        createFeatures(flow, tags);
        super.setHeaders(tags.toArray(new FlowFeatureTag[0]));
    }

    private void createFeatures(Flow flow, List<FlowFeatureTag> tags) {
        new ArrayList<>(
                ClassManager.createManager(null)
                        .loadClasses(HttpFeature.class, "io.tomahawkd.cic.flow.features.http")
        ).stream()
                .filter(f -> !Modifier.isAbstract(f.getModifiers()))
                .filter(f -> f.getAnnotation(Feature.class) != null)
                .peek(f -> logger.debug("Loading class {}", f.getName()))
                .sorted(Comparator.comparingInt(f -> f.getAnnotation(Feature.class).ordinal()))
                .collect(Collectors.toList())
                .forEach(c -> {
                    Feature feature = c.getAnnotation(Feature.class);
                    if (!feature.manual()) {
                        try {
                            logger.debug("Creating instance of class {}", c.getName());
                            HttpFeature newFeature = c.getConstructor(HttpFeatureAdapter.class).newInstance(this);
                            features.add(newFeature);
                        } catch (NoSuchMethodException | InstantiationException |
                                IllegalAccessException | InvocationTargetException e) {
                            logger.error("Cannot create new instance of {}", c, e);
                            throw new RuntimeException(e);
                        }
                    } else {
                        try {
                            getByType(c);
                        } catch (IllegalArgumentException e) {
                            logger.error("A manually created feature {} is not found in the list.", c.getName());
                            throw e;
                        }
                    }
                    tags.addAll(Arrays.stream(feature.tags()).collect(Collectors.toList()));
                });
    }

    @Override
    public final void addPacket(PacketInfo info, boolean fwd) {
        reassembler.flushIncompletePackets(info.seq(), this::acceptPacket, fwd);

        Boolean http = Optional.ofNullable(info.getFeature(MetaFeature.HTTP, Boolean.class)).orElse(false);
        if (!http) {
            // no incomplete packet yet
            if (reassembler.isEmpty(fwd)) return;

            // complete the packets if it could
            if (!reassembler.canCompleteIncompletePacket(info, fwd)) return;
            // else accept the packet
        }

        // if current is incomplete
        if (Optional.ofNullable(info.getFeature(HttpPacketDelegate.Feature.INCOMPLETE, Boolean.class)).orElse(false)) {
            reassembler.addIncompletePacket(info, fwd);
            // ignore the package temporarily
            return;
        }

        acceptPacket(info);
    }

    private void acceptPacket(PacketInfo info) {
        Boolean request = info.getFeature(HttpPacketDelegate.Feature.REQUEST, Boolean.class);
        if (request == null) {
            logger.warn("Packet {} has no request tag, discarded", info.getFlowId());
            logger.warn("Packet Content: {}", info.toString());
            return;
        }

        for (HttpFeature feature : features) {
            feature.addGenericPacket(info, request);
            if (request) feature.addRequestPacket(info);
            else feature.addResponsePacket(info);
        }
    }

    @Override
    public final void finalizeFlow() {
        // deal with incomplete packets
        if (!reassembler.isEmpty()) {
            reassembler.cleanIncompletePackets(this::acceptPacket);
        }
    }

    public final <T extends HttpFeature> T getByType(Class<T> type) {
        for (HttpFeature item: features) {
            if (item.getClass().equals(type)) return type.cast(item);
        }

        throw new IllegalArgumentException(type.getName() + " not found.");
    }
}

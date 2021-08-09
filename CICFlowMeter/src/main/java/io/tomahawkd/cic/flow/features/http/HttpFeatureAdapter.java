package io.tomahawkd.cic.flow.features.http;

import io.tomahawkd.cic.config.CommandlineDelegate;
import io.tomahawkd.cic.flow.Flow;
import io.tomahawkd.cic.flow.features.AbstractFlowFeature;
import io.tomahawkd.cic.flow.features.Feature;
import io.tomahawkd.cic.flow.features.FeatureType;
import io.tomahawkd.cic.flow.features.FlowFeatureTag;
import io.tomahawkd.cic.packet.HttpPreprocessPacketDelegate;
import io.tomahawkd.cic.packet.MetaFeature;
import io.tomahawkd.cic.packet.PacketInfo;
import io.tomahawkd.config.ConfigManager;
import io.tomahawkd.config.util.ClassManager;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Modifier;
import java.util.*;

@Feature(name = "HttpFeatures", tags = {}, ordinal = 8, type = FeatureType.HTTP)
public class HttpFeatureAdapter extends AbstractFlowFeature {

    private static final Logger logger = LogManager.getLogger(HttpFeatureAdapter.class);

    private final TcpReorderer fwdReorderer;
    private final TcpReorderer bwdReorderer;
    private final List<HttpFlowFeature> features;
    private final boolean disableReassembling;

    private final HttpPacketParser parser;

    private int httpPackets = 0;

    public HttpFeatureAdapter(Flow flow) {
        super(flow);
        features = new ArrayList<>();
        List<FlowFeatureTag> tags = createFeatures();
        super.setHeaders(tags.toArray(new FlowFeatureTag[0]));
        disableReassembling = ConfigManager.get().getDelegateByType(CommandlineDelegate.class).isDisableReassemble();
        if (disableReassembling) {
            parser = new HttpPacketParser();
            fwdReorderer = null;
            bwdReorderer = null;
        } else {
            parser = null;
            fwdReorderer = new TcpReorderer(this::acceptPacket);
            bwdReorderer = new TcpReorderer(this::acceptPacket);
        }
    }

    private List<FlowFeatureTag> createFeatures() {
        List<FlowFeatureTag> tags = new ArrayList<>();
        new ArrayList<>(ClassManager.createManager(null)
                        .loadClasses(HttpFlowFeature.class, "io.tomahawkd.cic.flow.features.http"))
                .stream()
                .filter(f -> !Modifier.isAbstract(f.getModifiers()))
                .filter(f -> f.getAnnotation(Feature.class) != null)
                .peek(f -> logger.debug("Loading class {}", f.getName()))
                .sorted(Comparator.comparingInt(f -> f.getAnnotation(Feature.class).ordinal()))
                .forEachOrdered(c -> {
                    Feature feature = c.getAnnotation(Feature.class);
                    if (!feature.manual()) {
                        try {
                            logger.debug("Creating instance of class {}", c.getName());
                            HttpFlowFeature newFeature = c.getConstructor(HttpFeatureAdapter.class).newInstance(this);
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
                    tags.addAll(Arrays.asList(feature.tags()));
                });

        return tags;
    }

    @Override
    public final void addPacket(PacketInfo info, boolean fwd) {
        if (disableReassembling) {
            if (!info.getBoolFeature(MetaFeature.READABLE)) return;
            String readableString = info.getFeature(HttpPreprocessPacketDelegate.Feature.PAYLOAD, String.class);
            HttpPacketParser.Status parsed = parser.parseFeatures(info, readableString, true);
            if (parsed == HttpPacketParser.Status.OK) {
                acceptPacket(info);
            } else {
                logger.warn("Discarded packet [{}]", info);
            }

        } else {
            TcpReorderer reorderer = fwd ? fwdReorderer : bwdReorderer;
            reorderer.addPacket(info);
        }
    }

    private void acceptPacket(PacketInfo info) {
        Boolean request = info.getFeature(HttpPacketFeature.REQUEST, Boolean.class);
        if (request == null) {
            logger.warn("Packet {} has no request tag, discarded", info.getFlowId());
            logger.warn("Packet Content: {}", info.toString());
            return;
        }

        for (HttpFlowFeature feature : features) {
            feature.addGenericPacket(info, request);
            if (request) feature.addRequestPacket(info);
            else feature.addResponsePacket(info);
        }
        httpPackets++;
    }

    @Override
    public final void finalizeFlow() {
        if (!disableReassembling) {
            // deal with incomplete packets
            fwdReorderer.finalizeFlow();
            bwdReorderer.finalizeFlow();
        }
    }

    @Override
    public String exportData() {
        StringBuilder builder = new StringBuilder();
        for (HttpFlowFeature item: features) {
            builder.append(item.exportData());
        }
        return builder.toString();
    }

    public final <T extends HttpFlowFeature> T getByType(Class<T> type) {
        for (HttpFlowFeature item: features) {
            if (item.getClass().equals(type)) return type.cast(item);
        }

        throw new IllegalArgumentException(type.getName() + " not found.");
    }

    public final int getHttpPackets() {
        return httpPackets;
    }
}

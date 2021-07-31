package io.tomahawkd.cic.flow.features.http;

import io.tomahawkd.cic.packet.PacketInfo;

public abstract class HttpFeature {

    protected final String SEPARATOR = ",";
    protected final HttpFeatureAdapter httpFeatures;

    protected HttpFeature(HttpFeatureAdapter httpFeatures) {
        this.httpFeatures = httpFeatures;
    }

    public void addGenericPacket(PacketInfo info, boolean isRequest) {

    }

    public void addRequestPacket(PacketInfo info) {

    }

    public void addResponsePacket(PacketInfo info) {

    }

    public abstract String exportData();

    protected final void addZeroesToBuilder(StringBuilder builder, int count) {
        for (int i = 0; i < count; i++) {
            builder.append(0).append(SEPARATOR);
        }
    }

    protected final <T extends HttpFeature> T getDep(Class<T> type) {
        return httpFeatures.getByType(type);
    }
}

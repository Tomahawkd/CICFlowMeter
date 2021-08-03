package io.tomahawkd.cic.flow.features.http;

import io.tomahawkd.cic.flow.features.Feature;
import io.tomahawkd.cic.flow.features.FeatureType;
import io.tomahawkd.cic.flow.features.FlowFeatureTag;
import io.tomahawkd.cic.packet.HttpPacketDelegate;
import io.tomahawkd.cic.packet.PacketInfo;

@Feature(name = "HttpCookieFeature", tags = {
        FlowFeatureTag.set_cookie_count,
        FlowFeatureTag.cookie_count,
        FlowFeatureTag.no_cookie_count
}, ordinal = 5, type = FeatureType.HTTP)
public class HttpCookieFeature extends HttpFeature {

    private long set_cookie_count = 0;
    private long cookie_count = 0;
    private long no_cookie_count = 0;

    public HttpCookieFeature(HttpFeatureAdapter httpFeature) {
        super(httpFeature);
    }

    @Override
    public void addRequestPacket(PacketInfo info) {
        String cookie = info.getFeature(HttpPacketDelegate.Feature.COOKIE, String.class);
        if (cookie == null) no_cookie_count++;
        else cookie_count++;
    }

    @Override
    public void addResponsePacket(PacketInfo info) {
        String set_cookie = info.getFeature(HttpPacketDelegate.Feature.SET_COOKIE, String.class);
        if (set_cookie != null) set_cookie_count++;
    }

    @Override
    public String exportData() {
        StringBuilder builder = new StringBuilder();
        builder.append(set_cookie_count).append(SEPARATOR); // FlowFeatureTag.set_cookie_count,
        builder.append(cookie_count).append(SEPARATOR); // FlowFeatureTag.cookie_count
        builder.append(no_cookie_count).append(SEPARATOR); // FlowFeatureTag.no_cookie_count
        return builder.toString();
    }
}

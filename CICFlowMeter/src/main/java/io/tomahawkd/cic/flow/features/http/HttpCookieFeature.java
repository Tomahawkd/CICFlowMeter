package io.tomahawkd.cic.flow.features.http;

import io.tomahawkd.cic.flow.features.Feature;
import io.tomahawkd.cic.flow.features.FeatureType;
import io.tomahawkd.cic.flow.features.FlowFeatureTag;
import io.tomahawkd.cic.packet.PacketInfo;

import java.util.HashMap;
import java.util.Map;

@Feature(name = "HttpCookieFeature", tags = {
        FlowFeatureTag.set_cookie_count,
        FlowFeatureTag.cookie_count,
        FlowFeatureTag.no_cookie_count,
        FlowFeatureTag.cookie_match_count,
        FlowFeatureTag.cookie_partial_match_count,
        FlowFeatureTag.cookie_no_match_count
}, ordinal = 5, type = FeatureType.HTTP)
public class HttpCookieFeature extends HttpFlowFeature {

    private long set_cookie_count = 0;
    private long cookie_count = 0;
    private long no_cookie_count = 0;

    private long cookie_not_match = 0;
    private long cookie_partial_match = 0;
    private long cookie_match = 0;

    private final Map<String, String> cookies = new HashMap<>();

    public HttpCookieFeature(HttpFeatureAdapter httpFeature) {
        super(httpFeature);
    }

    @Override
    public void addRequestPacket(PacketInfo info) {
        String cookie = info.getFeature(HttpPacketFeature.COOKIE, String.class);
        if (cookie == null) {
            no_cookie_count++;
            return;
        }

        cookie_count++;
        int matchCount = 0;
        for (String cookiePair : cookie.split(";")) {
            String[] pair = cookiePair.split("=", 2);
            if (pair.length == 2) {
                if (pair[1].equals(cookies.get(pair[0]))) matchCount++;
            } else {
                if ("".equals(cookies.get(cookiePair))) matchCount++;
            }
        }

        // if cookies has no cookie, that is, the cookie is generated by the client, outcome: no match
        if (matchCount == 0) cookie_not_match++;
        else if (matchCount == cookies.size()) cookie_match++;
        else cookie_partial_match++;
    }

    @Override
    public void addResponsePacket(PacketInfo info) {
        String set_cookie = info.getFeature(HttpPacketFeature.SET_COOKIE, String.class);
        if (set_cookie != null) {
            set_cookie_count++;
            cookies.clear();
            for (String cookiePair : set_cookie.split(";")) {
                String[] pair = cookiePair.split("=", 2);
                if (pair.length == 2) {
                    cookies.put(pair[0], pair[1]);
                } else cookies.put(cookiePair, "");
            }
        }
    }

    @Override
    public String exportData() {
        StringBuilder builder = new StringBuilder();
        builder.append(set_cookie_count).append(SEPARATOR); // FlowFeatureTag.set_cookie_count,
        builder.append(cookie_count).append(SEPARATOR); // FlowFeatureTag.cookie_count
        builder.append(no_cookie_count).append(SEPARATOR); // FlowFeatureTag.no_cookie_count
        builder.append(cookie_match).append(SEPARATOR); //        FlowFeatureTag.cookie_match_count,
        builder.append(cookie_partial_match).append(SEPARATOR); // FlowFeatureTag.cookie_partial_match_count,
        builder.append(cookie_not_match).append(SEPARATOR); // FlowFeatureTag.cookie_no_match_count
        return builder.toString();
    }
}

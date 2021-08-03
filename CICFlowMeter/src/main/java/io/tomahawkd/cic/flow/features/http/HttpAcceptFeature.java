package io.tomahawkd.cic.flow.features.http;

import io.tomahawkd.cic.flow.features.Feature;
import io.tomahawkd.cic.flow.features.FeatureType;
import io.tomahawkd.cic.flow.features.FlowFeatureTag;
import io.tomahawkd.cic.packet.HttpPacketDelegate;
import io.tomahawkd.cic.packet.PacketInfo;

@Feature(name = "HttpAcceptFeature", tags = {
        FlowFeatureTag.accept_count,
        FlowFeatureTag.accept_use_wildcard_count,
        FlowFeatureTag.no_accept_count,
        FlowFeatureTag.lang_count,
        FlowFeatureTag.lang_use_wildcard_count,
        FlowFeatureTag.no_lang_count
}, ordinal = 3, type = FeatureType.HTTP)
public class HttpAcceptFeature extends HttpFeature {

    private long acceptCount = 0;
    private long acceptOnlyUseWildcardCount = 0;
    private long noAcceptCount = 0;
    private long languageCount = 0;
    private long languageOnlyUseWildcardCount = 0;
    private long noLanguageCount = 0;

    public HttpAcceptFeature(HttpFeatureAdapter httpFeature) {
        super(httpFeature);
    }

    @Override
    public void addRequestPacket(PacketInfo info) {
        String accept = info.getFeature(HttpPacketDelegate.Feature.CONTENT_TYPE, String.class);
        if (accept != null) {
            acceptCount++;
            if (accept.startsWith("*/*")) acceptOnlyUseWildcardCount++;
        } else noAcceptCount++;

        String lang = info.getFeature(HttpPacketDelegate.Feature.LANGUAGE, String.class);
        if (lang != null) {
            languageCount++;
            if (lang.startsWith("*")) languageOnlyUseWildcardCount++;
        } else noLanguageCount++;
    }

    @Override
    public String exportData() {
        StringBuilder builder = new StringBuilder();
        builder.append(acceptCount).append(SEPARATOR); // FlowFeatureTag.accept_count,
        builder.append(acceptOnlyUseWildcardCount).append(SEPARATOR); // FlowFeatureTag.accept_use_wildcard_count,
        builder.append(noAcceptCount).append(SEPARATOR); // FlowFeatureTag.no_accept_count,
        builder.append(languageCount).append(SEPARATOR); // FlowFeatureTag.lang_count,
        builder.append(languageOnlyUseWildcardCount).append(SEPARATOR); // FlowFeatureTag.lang_use_wildcard_count,
        builder.append(noLanguageCount).append(SEPARATOR); // FlowFeatureTag.no_lang_count
        return builder.toString();
    }
}

package io.tomahawkd.cic.flow.features.http;

import io.tomahawkd.cic.flow.features.Feature;
import io.tomahawkd.cic.flow.features.FeatureType;
import io.tomahawkd.cic.flow.features.FlowFeatureTag;
import io.tomahawkd.cic.packet.HttpPacketDelegate;
import io.tomahawkd.cic.packet.PacketInfo;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import java.net.MalformedURLException;
import java.net.URL;

@Feature(name = "HttpRefererFeature", tags = {
        FlowFeatureTag.no_host_count,
        FlowFeatureTag.referer_count,
        FlowFeatureTag.referer_from_same_source,
        FlowFeatureTag.referer_from_search_engine,
}, ordinal = 9, type = FeatureType.HTTP)
public class HttpRefererFeature extends HttpFeature {

    private static final Logger logger = LogManager.getLogger(HttpRefererFeature.class);

    private long noHostCount = 0;
    private long refererCount = 0;
    private long refererSameOriginCount = 0;
    private long refererFromSearchEngineCount = 0;

    public HttpRefererFeature(HttpFeatureAdapter httpFeature) {
        super(httpFeature);
    }

    @Override
    public void addRequestPacket(PacketInfo info) {
        String host = info.getFeature(HttpPacketDelegate.Feature.HOST, String.class);
        if (host == null) {
            noHostCount++;
            logger.warn("Packet {} has no host in HTTP protocol.", info.getFlowId());
            logger.warn("Packet Content: {}", info.toString());
        }

        String referer = info.getFeature(HttpPacketDelegate.Feature.REFERER, String.class);
        if (referer != null) {
            try {
                URL url = new URL(referer);
                refererCount++;
                if (url.getHost().equalsIgnoreCase(host)) {
                    refererSameOriginCount++;
                } else {
                    for (String se : searchEngineNameList) {
                        if (url.getHost().contains(se)) {
                            refererFromSearchEngineCount++;
                            break;
                        }
                    }
                }
            } catch (MalformedURLException e) {
                logger.warn("Invalid referer {} in packet {}", referer, info.toString());
            }
        }
    }

    @Override
    public String exportData() {
        StringBuilder builder = new StringBuilder();
        builder.append(noHostCount).append(SEPARATOR); // FlowFeatureTag.no_host_count,
        builder.append(refererCount).append(SEPARATOR); // FlowFeatureTag.referer_count,
        builder.append(refererSameOriginCount).append(SEPARATOR); // FlowFeatureTag.referer_from_same_source,
        builder.append(refererFromSearchEngineCount).append(SEPARATOR); // FlowFeatureTag.referer_from_search_engine,
        return builder.toString();
    }

    private static final String[] searchEngineNameList = {
            "google", "baidu", "bing", "yahoo", "aol", "duckduckgo"
    };
}

package io.tomahawkd.cic.flow.features;

import io.tomahawkd.cic.flow.Flow;
import io.tomahawkd.cic.packet.HttpPacketDelegate;
import io.tomahawkd.cic.packet.PacketInfo;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import java.net.MalformedURLException;
import java.net.URL;

@Feature(name = "HttpRefererFeature", tags = {
        FlowFeatureTag.referer_count,
})
public class HttpRefererFeature extends AbstractHttpFeature {

    private static final Logger logger = LogManager.getLogger(HttpRefererFeature.class);

    private long refererCount = 0;
    private long refererSameOriginCount = 0;
    private long refererFromSearchEngineCount = 0;
    // private long refererFromUnknownSource = refererCount - refererSameOriginCount - refererFromSearchEngineCount;

    public HttpRefererFeature(Flow flow) {
        super(flow);
    }

    @Override
    public void addRequestPacket(PacketInfo info) {
        String host = info.getFeature(HttpPacketDelegate.Feature.HOST, String.class);
        if (host == null) return;

        String referer = info.getFeature(HttpPacketDelegate.Feature.REFERER, String.class);
        if (referer != null) {

            try {
                URL url = new URL(referer);
                if (host.equalsIgnoreCase(url.getHost())) {
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
                return;
            }

            // TODO: Need more check such as from a related link/search engine/totally irrelevant
            refererCount++;

        }
    }

    @Override
    public String exportData() {
        StringBuilder builder = new StringBuilder();
        builder.append(refererCount).append(SEPARATOR); // FlowFeatureTag.referer_count,
        return builder.toString();
    }

    private static final String[] searchEngineNameList = {
            "google", "baidu", "bing", "yahoo", "aol", "duckduckgo"
    };
}

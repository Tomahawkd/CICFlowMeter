package io.tomahawkd.cic.flow.features;

import io.tomahawkd.cic.flow.Flow;
import io.tomahawkd.cic.packet.HttpPacketDelegate;
import io.tomahawkd.cic.packet.PacketInfo;
import org.apache.commons.math3.stat.descriptive.SummaryStatistics;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import java.util.Optional;

@Feature(name = "HttpFeature", tags = {
        FlowFeatureTag.content_length_avg,
        FlowFeatureTag.content_length_std,
        FlowFeatureTag.content_length_max,
        FlowFeatureTag.content_length_min,
        FlowFeatureTag.content_length_total,
        FlowFeatureTag.req_content_length_avg,
        FlowFeatureTag.req_content_length_std,
        FlowFeatureTag.req_content_length_max,
        FlowFeatureTag.req_content_length_min,
        FlowFeatureTag.req_content_length_total,
        FlowFeatureTag.res_content_length_avg,
        FlowFeatureTag.res_content_length_std,
        FlowFeatureTag.res_content_length_max,
        FlowFeatureTag.res_content_length_min,
        FlowFeatureTag.res_content_length_total,
        FlowFeatureTag.keep_alive_packet_ratio,
        FlowFeatureTag.method_get_count,
        FlowFeatureTag.method_post_count,
})
public class HttpBasicFeature extends AbstractHttpFeature {

    private static final Logger logger = LogManager.getLogger(HttpBasicFeature.class);

    private final SummaryStatistics content_length = new SummaryStatistics();
    private final SummaryStatistics content_length_req = new SummaryStatistics();
    private final SummaryStatistics content_length_res = new SummaryStatistics();
    private long keepAliveCount = 0L;
    private long getCount = 0;
    private long postCount = 0;

    public HttpBasicFeature(Flow flow) {
        super(flow);
    }

    @Override
    public void addGenericPacket(PacketInfo info, boolean isRequest) {
        int contentLength = Optional.ofNullable(
                info.getFeature(HttpPacketDelegate.Feature.CONTENT_LEN, Integer.class))
                .orElse(0);
        content_length.addValue(contentLength);

        if (isRequest) {
            content_length_req.addValue(contentLength);
        } else {
            content_length_res.addValue(contentLength);
        }
    }

    @Override
    public void addRequestPacket(PacketInfo info) {
        // TODO: URL query and more
        String path = info.getFeature(HttpPacketDelegate.Feature.URL, String.class);
        String host = info.getFeature(HttpPacketDelegate.Feature.HOST, String.class);
        if (host == null) {
            logger.warn("Packet {} has no host in HTTP protocol.", info.getFlowId());
            logger.warn("Packet Content: {}", info.toString());

        }

        String connection = info.getFeature(HttpPacketDelegate.Feature.CONNECTION, String.class);
        if (connection != null) {
            if (connection.equalsIgnoreCase("keep-alive")) keepAliveCount++;
        }

        String method = info.getFeature(HttpPacketDelegate.Feature.METHOD, String.class);
        if (method != null) {
            if (method.equalsIgnoreCase("get")) getCount++;
            else if (method.equalsIgnoreCase("post")) postCount++;
        }
    }

    @Override
    public String exportData() {
        StringBuilder builder = new StringBuilder();
        buildContentLength(builder, content_length);
        buildContentLength(builder, content_length_req);
        buildContentLength(builder, content_length_res);

        builder.append(keepAliveCount).append(SEPARATOR); // FlowFeatureTag.keep_alive_packet_ratio,
        builder.append(getCount).append(SEPARATOR); // FlowFeatureTag.method_get_count,
        builder.append(postCount).append(SEPARATOR); // FlowFeatureTag.method_post_count,
        return builder.toString();
    }

    private void buildContentLength(StringBuilder builder, SummaryStatistics content_length) {
        if (content_length.getN() > 0) {
            builder.append(content_length.getMean()).append(SEPARATOR); // content_length_avg,
            builder.append(content_length.getStandardDeviation()).append(SEPARATOR); // content_length_std,
            builder.append(content_length.getMax()).append(SEPARATOR); // content_length_max,
            builder.append(content_length.getMin()).append(SEPARATOR); // content_length_min,
            builder.append(content_length.getSum()).append(SEPARATOR); // content_length_total,
        } else {
            addZeroesToBuilder(builder, 5);
        }
    }
}

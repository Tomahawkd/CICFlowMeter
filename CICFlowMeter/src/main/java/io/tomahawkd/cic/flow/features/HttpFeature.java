package io.tomahawkd.cic.flow.features;

import io.tomahawkd.cic.packet.HttpPacketDelegate;
import io.tomahawkd.cic.packet.PacketInfo;
import io.tomahawkd.cic.flow.Flow;
import org.apache.commons.math3.stat.descriptive.SummaryStatistics;

import java.util.Optional;

@Feature(name = "HttpFeature", tags = {
        FlowFeatureTag.content_length_avg,
        FlowFeatureTag.content_length_std,
        FlowFeatureTag.content_length_max,
        FlowFeatureTag.content_length_min,
        FlowFeatureTag.content_length_total,
        FlowFeatureTag.fw_content_length_avg,
        FlowFeatureTag.fw_content_length_std,
        FlowFeatureTag.fw_content_length_max,
        FlowFeatureTag.fw_content_length_min,
        FlowFeatureTag.fw_content_length_total,
        FlowFeatureTag.bw_content_length_avg,
        FlowFeatureTag.bw_content_length_std,
        FlowFeatureTag.bw_content_length_max,
        FlowFeatureTag.bw_content_length_min,
        FlowFeatureTag.bw_content_length_total,
        FlowFeatureTag.keep_alive_packet_ratio,
        FlowFeatureTag.method_get_count,
        FlowFeatureTag.method_post_count,
        FlowFeatureTag.referer_count,
})
public class HttpFeature extends AbstractFlowFeature {

    private final SummaryStatistics content_length = new SummaryStatistics();
    private final SummaryStatistics content_length_req = new SummaryStatistics();
    private final SummaryStatistics content_length_res = new SummaryStatistics();
    private long keepAliveCount = 0L;
    private long getCount = 0;
    private long postCount = 0;
    private long refererCount = 0;

    public HttpFeature(Flow flow) {
        super(flow);
    }

    @Override
    public void addPacket(PacketInfo info, boolean fwd) {

        Boolean request = info.getFeature(HttpPacketDelegate.Feature.REQUEST, Boolean.class);
        if (request == null) return;


        int contentLength = Optional.ofNullable(
                info.getFeature(HttpPacketDelegate.Feature.CONTENT_LEN, Integer.class))
                .orElse(0);
        content_length.addValue(contentLength);

        // we only care about the request
        if (request) {
            content_length_req.addValue(contentLength);

            // TODO: URL query and more
            String url = info.getFeature(HttpPacketDelegate.Feature.URL, String.class);

            String connection = info.getFeature(HttpPacketDelegate.Feature.CONNECTION, String.class);
            if (connection != null) {
                if (connection.equalsIgnoreCase("keep-alive")) keepAliveCount++;
            }

            String method = info.getFeature(HttpPacketDelegate.Feature.METHOD, String.class);
            if (method != null) {
                if (method.equalsIgnoreCase("get")) getCount++;
                else if (method.equalsIgnoreCase("post")) postCount++;
            }

            String referer = info.getFeature(HttpPacketDelegate.Feature.REFERER, String.class);
            if (referer != null) {
                refererCount++;
                // TODO: Need more check such as from a related link/search engine/totally irrelevant
            }

            // TODO check ua
            String ua = info.getFeature(HttpPacketDelegate.Feature.UA, String.class);
            if (ua != null) {

            }

            // TODO: check accept headers
            String accept = info.getFeature(HttpPacketDelegate.Feature.CONTENT_TYPE, String.class);
            String encoding = info.getFeature(HttpPacketDelegate.Feature.ENCODING, String.class);
            String lang = info.getFeature(HttpPacketDelegate.Feature.LANGUAGE, String.class);
        } else {
            content_length_res.addValue(contentLength);
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
        builder.append(refererCount).append(SEPARATOR); // FlowFeatureTag.referer_count,
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

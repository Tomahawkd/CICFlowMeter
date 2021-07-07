package io.tomahawkd.cic.flow.features;

import io.tomahawkd.cic.data.HttpPacketDelegate;
import io.tomahawkd.cic.data.PacketInfo;
import io.tomahawkd.cic.flow.Flow;
import org.apache.commons.math3.stat.descriptive.SummaryStatistics;

@Feature(name = "HttpFeature", tags = {
        FlowFeatureTag.content_length_avg,
        FlowFeatureTag.content_length_std,
        FlowFeatureTag.content_length_max,
        FlowFeatureTag.content_length_min,
        FlowFeatureTag.content_length_total,
        FlowFeatureTag.keep_alive_packet_ratio,
        FlowFeatureTag.method_get_count,
        FlowFeatureTag.method_post_count,
        FlowFeatureTag.referer_count,
})
public class HttpFeature extends AbstractFlowFeature {

    private final SummaryStatistics content_length = new SummaryStatistics();
    private long keepAliveCount = 0L;
    private long getCount = 0;
    private long postCount = 0;
    private long refererCount = 0;

    public HttpFeature(Flow flow) {
        super(flow);
    }

    @Override
    public void addPacket(PacketInfo info, boolean fwd) {
        Integer contentLength = info.getFeature(HttpPacketDelegate.Feature.CONTENT_LEN, Integer.class);
        if (contentLength == null) {
            content_length.addValue(0);
        } else content_length.addValue(contentLength);

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
        if (referer != null) refererCount++;
    }

    @Override
    public String exportData() {
        StringBuilder builder = new StringBuilder();
        if (content_length.getN() > 0) {
            builder.append(content_length.getMean()).append(SEPARATOR); // FlowFeatureTag.content_length_avg,
            builder.append(content_length.getStandardDeviation()).append(SEPARATOR); // FlowFeatureTag.content_length_std,
            builder.append(content_length.getMax()).append(SEPARATOR); // FlowFeatureTag.content_length_max,
            builder.append(content_length.getMin()).append(SEPARATOR); // FlowFeatureTag.content_length_min,
            builder.append(content_length.getSum()).append(SEPARATOR); // FlowFeatureTag.content_length_total,
        } else {
            addZeroesToBuilder(builder, 5);
        }
        builder.append(keepAliveCount).append(SEPARATOR); // FlowFeatureTag.keep_alive_packet_ratio,
        builder.append(getCount).append(SEPARATOR); // FlowFeatureTag.method_get_count,
        builder.append(postCount).append(SEPARATOR); // FlowFeatureTag.method_post_count,
        builder.append(refererCount).append(SEPARATOR); // FlowFeatureTag.referer_count,
        return builder.toString();
    }


}

package io.tomahawkd.cic.flow.features.http;

import io.tomahawkd.cic.flow.features.Feature;
import io.tomahawkd.cic.flow.features.FeatureType;
import io.tomahawkd.cic.flow.features.FlowFeatureTag;
import io.tomahawkd.cic.packet.PacketInfo;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

@Feature(name = "HttpResponseCodeFeature", tags = {
        FlowFeatureTag.ok_count,
        FlowFeatureTag.not_modified_count,
        FlowFeatureTag.not_found_count,
        FlowFeatureTag.info_count,
        FlowFeatureTag.success_count,
        FlowFeatureTag.redirect_count,
        FlowFeatureTag.client_error_count,
        FlowFeatureTag.server_error_count,
        FlowFeatureTag.other_status_count,
}, ordinal = 7, type = FeatureType.HTTP)
public class HttpResponseCodeFeature extends HttpFlowFeature {

    private static final Logger logger = LogManager.getLogger(HttpResponseCodeFeature.class);

    // 200
    private long ok_count = 0;
    // 304
    private long not_modified_count = 0;
    // 404
    private long not_found_count = 0;

    // 1xx
    private long info_count = 0;
    // 2xx
    private long success_count = 0;
    // 3xx
    private long redirect_count = 0;
    // 4xx
    private long client_error_count = 0;
    // 5xx
    private long server_error_count = 0;

    private long other_status_count = 0;

    public HttpResponseCodeFeature(HttpFeatureAdapter httpFeatures) {
        super(httpFeatures);
    }

    @Override
    public void addResponsePacket(PacketInfo info) {
        String code = info.getFeature(HttpPacketFeature.STATUS, String.class);
        if (code == null) {
            logger.warn("Response HTTP with no status code.");
            logger.warn("Packet data: {}", info);
            return;
        }

        if (code.startsWith("1")) info_count++;
        else if (code.startsWith("2")) {
            success_count++;
            if ("200".equals(code)) ok_count++;
        } else if (code.startsWith("3")) {
            redirect_count++;
            if ("304".equals(code)) not_modified_count++;
        } else if (code.startsWith("4")) {
            client_error_count++;
            if ("404".equals(code)) not_found_count++;
        } else if (code.startsWith("5")) server_error_count++;
        else other_status_count++;
    }

    @Override
    public String exportData() {
        StringBuilder builder = new StringBuilder();
        builder.append(ok_count).append(SEPARATOR); // FlowFeatureTag.ok_count,
        builder.append(not_modified_count).append(SEPARATOR); // FlowFeatureTag.not_modified_count,
        builder.append(not_found_count).append(SEPARATOR); // FlowFeatureTag.not_found_count,
        builder.append(info_count).append(SEPARATOR); // FlowFeatureTag.info_count,
        builder.append(success_count).append(SEPARATOR); // FlowFeatureTag.success_count,
        builder.append(redirect_count).append(SEPARATOR); // FlowFeatureTag.redirect_count,
        builder.append(client_error_count).append(SEPARATOR); // FlowFeatureTag.client_error_count,
        builder.append(server_error_count).append(SEPARATOR); // FlowFeatureTag.server_error_count,
        builder.append(other_status_count).append(SEPARATOR); // FlowFeatureTag.other_status_count,
        return builder.toString();
    }
}

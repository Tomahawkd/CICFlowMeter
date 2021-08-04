package io.tomahawkd.cic.flow.features.http;

import io.tomahawkd.cic.flow.features.Feature;
import io.tomahawkd.cic.flow.features.FeatureType;
import io.tomahawkd.cic.flow.features.FlowFeatureTag;
import io.tomahawkd.cic.packet.HttpPacketDelegate;
import io.tomahawkd.cic.packet.PacketInfo;
import org.apache.tika.mime.MediaType;

@Feature(name = "HttpResponseContentFeature", tags = {
        FlowFeatureTag.plain_count,
        FlowFeatureTag.html_count,
        FlowFeatureTag.js_count,
        FlowFeatureTag.css_count,
        FlowFeatureTag.image_count,
        FlowFeatureTag.app_count,
        FlowFeatureTag.other_count,
        FlowFeatureTag.invalid_content_type,
}, ordinal = 6, type = FeatureType.HTTP)
public class HttpResponseContentFeature extends HttpFeature {

    private long plain_count = 0;
    private long html_count = 0;
    private long js_count = 0;
    private long css_count = 0;
    private long image_count = 0;
    private long app_count = 0;
    private long other_count = 0;

    private long invalid_content_type = 0;

    public HttpResponseContentFeature(HttpFeatureAdapter httpFeatures) {
        super(httpFeatures);
    }

    @Override
    public void addResponsePacket(PacketInfo info) {
        String contentType = info.getFeature(HttpPacketDelegate.Feature.CONTENT_TYPE, String.class);
        if (contentType != null) {
            MediaType type = MediaType.parse(contentType);
            if (type == null) {
                invalid_content_type++;
                return;
            }

            if (MediaType.TEXT_HTML.equals(type)) html_count++;
            else if (MediaType.TEXT_PLAIN.equals(type)) plain_count++;
            else if (type.getSubtype().contains("css")) css_count++;
            else if (type.getType().contains("image")) image_count++;
            else if (type.getSubtype().contains("javascript") || type.getSubtype().contains("ecmascript")) js_count++;
            else if (type.getType().contains("application")) app_count++;
            else other_count++;
        }
    }

    @Override
    public String exportData() {
        StringBuilder builder = new StringBuilder();
        builder.append(plain_count).append(SEPARATOR); // FlowFeatureTag.plain_count,
        builder.append(html_count).append(SEPARATOR); // FlowFeatureTag.html_count,
        builder.append(js_count).append(SEPARATOR); // FlowFeatureTag.js_count,
        builder.append(css_count).append(SEPARATOR); // FlowFeatureTag.css_count,
        builder.append(image_count).append(SEPARATOR); // FlowFeatureTag.image_count,
        builder.append(app_count).append(SEPARATOR); // FlowFeatureTag.app_count,
        builder.append(other_count).append(SEPARATOR); // FlowFeatureTag.other_count,
        builder.append(invalid_content_type).append(SEPARATOR); // FlowFeatureTag.invalid_content_type,
        return builder.toString();
    }
}

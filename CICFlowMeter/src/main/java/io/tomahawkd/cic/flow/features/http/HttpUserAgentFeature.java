package io.tomahawkd.cic.flow.features.http;

import io.tomahawkd.cic.flow.features.Feature;
import io.tomahawkd.cic.flow.features.FeatureType;
import io.tomahawkd.cic.flow.features.FlowFeatureTag;
import io.tomahawkd.cic.packet.PacketInfo;
import io.tomahawkd.cic.util.UserAgentAnalyzerHelper;
import nl.basjes.parse.useragent.AgentField;
import nl.basjes.parse.useragent.UserAgent;
import org.apache.commons.lang3.ArrayUtils;

@Feature(name = "HttpUserAgentFeature", tags = {
        FlowFeatureTag.valid_user_agent_count,
        FlowFeatureTag.invalid_user_agent_count,
        FlowFeatureTag.no_user_agent_count
}, ordinal = 4, type = FeatureType.HTTP)
public class HttpUserAgentFeature extends HttpFlowFeature {

    private long validUserAgentCount = 0;
    private long invalidUserAgentCount = 0;
    private long noUserAgentCount = 0;

    public HttpUserAgentFeature(HttpFeatureAdapter httpFeature) {
        super(httpFeature);
    }

    @Override
    public void addRequestPacket(PacketInfo info) {
        UserAgent ua = UserAgentAnalyzerHelper.INSTANCE.parseUserAgent(
                info.getFeature(HttpPacketFeature.UA, String.class));
        if (ua == null) noUserAgentCount++;
        else {
            AgentField device = ua.get(UserAgent.DEVICE_CLASS);
            if (device.isDefaultValue() ||
                    !ArrayUtils.contains(normalType, device.getValue())) invalidUserAgentCount++;
            else validUserAgentCount++;
        }
    }

    @Override
    public String exportData() {
        StringBuilder builder = new StringBuilder();
        builder.append(validUserAgentCount).append(SEPARATOR); // FlowFeatureTag.valid_user_agent_count,
        builder.append(invalidUserAgentCount).append(SEPARATOR); // FlowFeatureTag.invalid_user_agent_count
        builder.append(noUserAgentCount).append(SEPARATOR); // FlowFeatureTag.no_user_agent_count
        return builder.toString();
    }

    private static final String[] normalType = {
        "Phone", "Mobile", "eReader", "Tablet", "Desktop", "Game Console"
    };
}

package io.tomahawkd.cic.flow.features;

import io.tomahawkd.cic.flow.Flow;
import io.tomahawkd.cic.packet.HttpPacketDelegate;
import io.tomahawkd.cic.packet.PacketInfo;
import nl.basjes.parse.useragent.AgentField;
import nl.basjes.parse.useragent.UserAgent;
import org.apache.commons.lang3.ArrayUtils;

@Feature(name = "HttpUserAgentFeature", tags = {
        FlowFeatureTag.user_agent_count,
        FlowFeatureTag.invalid_user_agent_count
}, ordinal = 11)
public class HttpUserAgentFeature extends AbstractHttpFeature {

    private long userAgentCount = 0;
    private long invalidUserAgentCount = 0;

    public HttpUserAgentFeature(Flow flow) {
        super(flow);
    }

    @Override
    public void addRequestPacket(PacketInfo info) {
        UserAgent ua = info.getFeature(HttpPacketDelegate.Feature.UA, UserAgent.class);
        if (ua != null) {
            userAgentCount++;
            AgentField device = ua.get(UserAgent.DEVICE_CLASS);
            if (device.isDefaultValue() ||
                    !ArrayUtils.contains(normalType, device.getValue())) invalidUserAgentCount++;
        }
    }

    @Override
    public String exportData() {
        StringBuilder builder = new StringBuilder();
        builder.append(userAgentCount).append(SEPARATOR); // FlowFeatureTag.user_agent_count,
        builder.append(invalidUserAgentCount).append(SEPARATOR); // FlowFeatureTag.invalid_user_agent_count
        return builder.toString();
    }

    private static final String[] normalType = {
        "Phone", "Mobile", "eReader", "Tablet", "Desktop", "Game Console"
    };
}

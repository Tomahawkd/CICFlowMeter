package io.tomahawkd.cic.flow.features;

import io.tomahawkd.cic.flow.Flow;
import io.tomahawkd.cic.packet.HttpPacketDelegate;
import io.tomahawkd.cic.packet.PacketInfo;
import nl.basjes.parse.useragent.AgentField;
import nl.basjes.parse.useragent.UserAgent;

@Feature(name = "HttpUserAgentFeature", tags = {})
public class HttpUserAgentFeature extends AbstractHttpFeature {

    public HttpUserAgentFeature(Flow flow) {
        super(flow);
    }

    @Override
    public void addRequestPacket(PacketInfo info) {
        // TODO check ua
        UserAgent ua = info.getFeature(HttpPacketDelegate.Feature.UA, UserAgent.class);
        if (ua == null) {

        } else {
            AgentField device = ua.get(UserAgent.DEVICE_CLASS);
        }
    }
}

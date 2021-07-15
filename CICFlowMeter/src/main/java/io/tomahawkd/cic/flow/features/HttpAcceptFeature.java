package io.tomahawkd.cic.flow.features;

import io.tomahawkd.cic.flow.Flow;
import io.tomahawkd.cic.packet.HttpPacketDelegate;
import io.tomahawkd.cic.packet.PacketInfo;

@Feature(name = "HttpAcceptFeature", tags = {})
public class HttpAcceptFeature extends AbstractHttpFeature {


    public HttpAcceptFeature(Flow flow) {
        super(flow);
    }

    @Override
    public void addRequestPacket(PacketInfo info) {
        String accept = info.getFeature(HttpPacketDelegate.Feature.CONTENT_TYPE, String.class);
        String encoding = info.getFeature(HttpPacketDelegate.Feature.ENCODING, String.class);
        String lang = info.getFeature(HttpPacketDelegate.Feature.LANGUAGE, String.class);
    }


}

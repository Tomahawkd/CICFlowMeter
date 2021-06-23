package io.tomahawkd.cic.data;

import org.jnetpcap.packet.PcapPacket;
import org.jnetpcap.protocol.tcpip.Http;

public class HttpPackageDelegate extends AbstractPackageDelegate {

    public HttpPackageDelegate() {
        super(Http.ID);
    }

    @Override
    public void parse(PackageInfo dst, PcapPacket packet) {

        dst.addFeature(MetaFeature.HTTP, true);
    }

    enum Feature implements PackageFeature {

    }
}

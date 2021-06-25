package io.tomahawkd.cic.data;

import org.jnetpcap.packet.PcapPacket;
import org.jnetpcap.protocol.network.Ip6;

public class Ipv6PackageDelegate extends AbstractPackageDelegate {

    public Ipv6PackageDelegate() {
        super(Ip6.ID);
    }

    @Override
    public boolean parse(PackageInfo dst, PcapPacket packet) {
        Ip6 ipv6 = new Ip6();
        if (!packet.hasHeader(ipv6)) {
            return false;
        }

        dst.addFeature(MetaFeature.SRC, ipv6.source());
        dst.addFeature(MetaFeature.DST, ipv6.destination());
        dst.addFeature(MetaFeature.IPV6, true);
        return true;
    }
}
